package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/anomaly"
	"github.com/ObeeJ/corvus-serverside/internal/cve"
	"github.com/ObeeJ/corvus-serverside/internal/fingerprint"
	"github.com/ObeeJ/corvus-serverside/internal/osint"
	"github.com/ObeeJ/corvus-serverside/internal/scanner"
	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/ObeeJ/corvus-serverside/internal/supplychain"
	"github.com/ObeeJ/corvus-serverside/internal/types"
	"github.com/ObeeJ/corvus-serverside/pkg/iprange"
	"github.com/google/uuid"
)

// ScanConfig defines the parameters for a scan job.
type ScanConfig struct {
	UserID      string
	Target      string
	Predict     bool
	Ports       string
	ScanType    string
	Timeout     time.Duration
	Concurrency int
	Rate        int
}

// Job represents a background scan task.
type Job struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Config    ScanConfig `json:"config"`
	StartedAt time.Time  `json:"started_at"`
	Status    string     `json:"status"` // "running", "completed", "failed"
	Error     string     `json:"error,omitempty"`
	Results   int        `json:"results"`
	Hosts     int        `json:"hosts"`
	Ports     int        `json:"ports"`
}

// UsageLogger is implemented by anything that can record a scan event for a user.
// The billing DB satisfies this; a no-op is used for CLI / no-DB mode.
type UsageLogger interface {
	LogScan(userID string)
}

// noopUsageLogger is used when no DB is configured (CLI mode).
type noopUsageLogger struct{}

func (noopUsageLogger) LogScan(_ string) {}

// Engine orchestrates background scans and provides live result streaming.
type Engine struct {
	storeMgr    *store.Manager
	sinks       []anomaly.AlertSink
	fp          *fingerprint.Fingerprinter
	predictor   *osint.Predictor
	correlator  *cve.Correlator
	scChecker   *supplychain.Checker
	log         *slog.Logger
	usageLogger UsageLogger

	mu          sync.RWMutex
	jobs        map[string]*Job
	subscribers map[string][]chan types.EnrichedResult
}

// New creates a new engine instance.
func New(storeMgr *store.Manager, sinks []anomaly.AlertSink, log *slog.Logger) *Engine {
	dbPath := "/var/lib/corvus/corvus.db"
	if home, err := os.UserHomeDir(); err == nil {
		dbPath = filepath.Join(home, ".corvus", "corvus.db")
	}
	cveCachePath := filepath.Join(filepath.Dir(dbPath), "cve_cache.db")
	cveCache, err := cve.NewCache(cveCachePath, 24*time.Hour, log)
	if err != nil {
		log.Warn("CVE cache unavailable", "err", err)
	}

	e := &Engine{
		storeMgr:    storeMgr,
		sinks:       sinks,
		fp:          fingerprint.New(log),
		predictor:   osint.New(log),
		correlator:  cve.NewCorrelator(cveCache, os.Getenv("CORVUS_NVD_API_KEY"), log),
		scChecker:   supplychain.New(),
		log:         log,
		usageLogger: noopUsageLogger{},
		jobs:        make(map[string]*Job),
		subscribers: make(map[string][]chan types.EnrichedResult),
	}

	// Background goroutine: evict completed jobs older than 1 hour to prevent memory leak.
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-1 * time.Hour)
			e.mu.Lock()
			for id, job := range e.jobs {
				if job.Status != "running" && job.StartedAt.Before(cutoff) {
					delete(e.jobs, id)
				}
			}
			e.mu.Unlock()
		}
	}()

	return e
}

// SetUsageLogger wires in a DB-backed usage logger (called by the serve command).
func (e *Engine) SetUsageLogger(l UsageLogger) { e.usageLogger = l }

// StartScan launches a background scan and returns a job ID immediately.
func (e *Engine) StartScan(ctx context.Context, cfg ScanConfig) (*Job, error) {
	ips, err := iprange.Parse(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}
	ports, err := iprange.ParsePorts(cfg.Ports)
	if err != nil {
		return nil, fmt.Errorf("invalid ports: %w", err)
	}

	jobID := uuid.New().String()
	job := &Job{
		ID:        jobID,
		UserID:    cfg.UserID,
		Config:    cfg,
		StartedAt: time.Now(),
		Status:    "running",
		Hosts:     len(ips),
		Ports:     len(ports),
	}

	e.mu.Lock()
	e.jobs[jobID] = job
	e.mu.Unlock()

	// Run scan asynchronously.
	go e.runScan(ctx, jobID, ips, ports)

	return job, nil
}

// GetJob returns the current status of a job.
func (e *Engine) GetJob(id string) (*Job, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	j, ok := e.jobs[id]
	if !ok {
		return nil, false
	}
	// Return a copy.
	copy := *j
	return &copy, true
}

// Subscribe returns a channel that streams live results for a specific job.
func (e *Engine) Subscribe(jobID string) chan types.EnrichedResult {
	e.mu.Lock()
	defer e.mu.Unlock()

	ch := make(chan types.EnrichedResult, 100)
	e.subscribers[jobID] = append(e.subscribers[jobID], ch)
	return ch
}

func (e *Engine) runScan(ctx context.Context, jobID string, ips []net.IP, ports []uint16) {
	job, ok := e.GetJob(jobID)
	if !ok {
		return
	}
	cfg := job.Config

	defer func() {
		e.mu.Lock()
		if e.jobs[jobID].Status == "running" {
			e.jobs[jobID].Status = "completed"
		}
		// Close subscriber channels.
		for _, ch := range e.subscribers[jobID] {
			close(ch)
		}
		delete(e.subscribers, jobID)
		e.mu.Unlock()
	}()

	st, err := e.storeMgr.GetStore(job.UserID)
	if err != nil {
		e.log.Error("Failed to get store for user", "user_id", job.UserID, "err", err)
		return
	}

	anomalyEng := anomaly.New(st, e.sinks, e.log)
	anomalyEng.Reset()

	// 1. OSINT Pre-scan (if enabled)
	var profiles map[string]*types.OSINTProfile
	if cfg.Predict {
		profiles = make(map[string]*types.OSINTProfile)
		for _, ip := range ips {
			if ctx.Err() != nil {
				return
			}
			profiles[ip.String()] = e.predictor.Predict(ctx, ip)
		}
		if len(ips) > 0 {
			if p, ok := profiles[ips[0].String()]; ok {
				ports = osint.PrioritisePorts(ports, p)
			}
		}
	}

	// 2. Setup Scanner
	scCfg := types.ScanConfig{
		Timeout:     cfg.Timeout,
		Concurrency: cfg.Concurrency,
		Rate:        cfg.Rate,
	}
	var sc scanner.Scanner
	switch strings.ToLower(cfg.ScanType) {
	case "syn":
		sc = scanner.NewSYN(scCfg, e.log)
	case "udp":
		sc = scanner.NewUDP(scCfg, e.log)
	default:
		sc = scanner.NewTCP(scCfg, e.log)
	}

	// 3. Execute Scan
	for result := range sc.Scan(ctx, ips, ports) {
		enriched := e.fp.Enrich(ctx, result)

		// CVE Enrichment
		if enriched.ServiceName != "" && enriched.Version != "" {
			cves, err := e.correlator.Lookup(ctx, enriched.ServiceName, enriched.Version)
			if err == nil && len(cves) > 0 {
				for _, cv := range cves {
					enriched.CVEs = append(enriched.CVEs, types.CVERef{
						ID:          cv.ID,
						CVSSv3:      cv.CVSSv3,
						Severity:    cv.Severity,
						Description: cv.Description,
						URL:         cv.URL,
					})
				}
			}
		}

		// Supply Chain
		enriched.SupplyChainFindings = e.scChecker.Check(enriched)

		// OSINT
		if profiles != nil {
			if p, ok := profiles[enriched.IP.String()]; ok {
				enriched.OSINTProfile = p
			}
		}

		// Update Store & Anomalies
		anomalyEng.Process(enriched) //nolint:errcheck

		// Publish to subscribers
		e.mu.RLock()
		e.jobs[jobID].Results++
		subs := e.subscribers[jobID]
		for _, ch := range subs {
			select {
			case ch <- enriched:
			default:
				// Drop if subscriber is too slow.
			}
		}
		e.mu.RUnlock()
	}

	anomalyEng.Flush(ips)
	st.SetMeta("last_scan", time.Now().UTC().Format(time.RFC3339)) //nolint:errcheck
	// Log usage so CLI scans count against quota the same as API scans.
	if job.UserID != "" && job.UserID != "default" {
		e.usageLogger.LogScan(job.UserID)
	}
}
