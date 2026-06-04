package otel

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// Metrics holds atomic counters for Corvus operational metrics.
type Metrics struct {
	ScansStarted   atomic.Int64
	ScansCompleted atomic.Int64
	PortsScanned   atomic.Int64
	PortsOpen      atomic.Int64
	AlertsEmitted  atomic.Int64
	CVEsFound      atomic.Int64
	StoreWrites    atomic.Int64
}

// Provider exposes metrics via a Prometheus-compatible /metrics endpoint.
type Provider struct {
	metrics *Metrics
	port    int
	log     *slog.Logger
}

// New creates a new OpenTelemetry provider.
func New(port int, log *slog.Logger) *Provider {
	return &Provider{
		metrics: &Metrics{},
		port:    port,
		log:     log,
	}
}

// Metrics returns the shared metrics instance for instrumentation.
func (p *Provider) Metrics() *Metrics {
	return p.metrics
}

// Start launches the Prometheus metrics HTTP server.
func (p *Provider) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", p.handleMetrics)

	addr := fmt.Sprintf("0.0.0.0:%d", p.port)
	p.log.Info("OpenTelemetry metrics server starting", "addr", addr)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.log.Error("metrics server error", "err", err)
		}
	}()
	return nil
}

func (p *Provider) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := p.metrics
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP corvus_scans_started_total Total number of scans started\n")
	fmt.Fprintf(w, "# TYPE corvus_scans_started_total counter\n")
	fmt.Fprintf(w, "corvus_scans_started_total %d\n\n", m.ScansStarted.Load())

	fmt.Fprintf(w, "# HELP corvus_scans_completed_total Total number of scans completed\n")
	fmt.Fprintf(w, "# TYPE corvus_scans_completed_total counter\n")
	fmt.Fprintf(w, "corvus_scans_completed_total %d\n\n", m.ScansCompleted.Load())

	fmt.Fprintf(w, "# HELP corvus_ports_scanned_total Total number of port probes sent\n")
	fmt.Fprintf(w, "# TYPE corvus_ports_scanned_total counter\n")
	fmt.Fprintf(w, "corvus_ports_scanned_total %d\n\n", m.PortsScanned.Load())

	fmt.Fprintf(w, "# HELP corvus_ports_open_total Total number of open ports discovered\n")
	fmt.Fprintf(w, "# TYPE corvus_ports_open_total counter\n")
	fmt.Fprintf(w, "corvus_ports_open_total %d\n\n", m.PortsOpen.Load())

	fmt.Fprintf(w, "# HELP corvus_alerts_emitted_total Total number of anomaly alerts emitted\n")
	fmt.Fprintf(w, "# TYPE corvus_alerts_emitted_total counter\n")
	fmt.Fprintf(w, "corvus_alerts_emitted_total %d\n\n", m.AlertsEmitted.Load())

	fmt.Fprintf(w, "# HELP corvus_cves_found_total Total number of CVEs correlated\n")
	fmt.Fprintf(w, "# TYPE corvus_cves_found_total counter\n")
	fmt.Fprintf(w, "corvus_cves_found_total %d\n\n", m.CVEsFound.Load())

	fmt.Fprintf(w, "# HELP corvus_store_writes_total Total number of state records written\n")
	fmt.Fprintf(w, "# TYPE corvus_store_writes_total counter\n")
	fmt.Fprintf(w, "corvus_store_writes_total %d\n\n", m.StoreWrites.Load())
}
