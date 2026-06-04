package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/types"
	"golang.org/x/time/rate"
)

// Scanner is the interface all scan engines implement.
type Scanner interface {
	Scan(ctx context.Context, ips []net.IP, ports []uint16) <-chan types.ScanResult
}

type job struct {
	ip   net.IP
	port uint16
}

// TCPScanner performs TCP connect scans using a bounded goroutine worker pool.
type TCPScanner struct {
	cfg types.ScanConfig
	log *slog.Logger
}

func NewTCP(cfg types.ScanConfig, log *slog.Logger) *TCPScanner {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 2000
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 750 * time.Millisecond
	}
	return &TCPScanner{cfg: cfg, log: log}
}

// Scan starts the worker pool and returns a channel of results.
// Only open ports are sent. The channel is closed when the scan is complete or ctx is cancelled.
func (s *TCPScanner) Scan(ctx context.Context, ips []net.IP, ports []uint16) <-chan types.ScanResult {
	results := make(chan types.ScanResult, s.cfg.Concurrency)

	go func() {
		defer close(results)

		jobs := make(chan job, s.cfg.Concurrency*2)

		var limiter *rate.Limiter
		if s.cfg.Rate > 0 {
			limiter = rate.NewLimiter(rate.Limit(s.cfg.Rate), s.cfg.Rate)
		}

		// Worker pool — each worker dials one port at a time.
		var wg sync.WaitGroup
		for i := 0; i < s.cfg.Concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobs {
					if ctx.Err() != nil {
						return
					}
					if limiter != nil {
						if err := limiter.Wait(ctx); err != nil {
							return
						}
					}
					result := tcpProbe(ctx, j.ip, j.port, s.cfg.Timeout)
					if !result.Open {
						continue
					}
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
				}
			}()
		}

		// Feed jobs: all ports for each IP together so one host is fully
		// saturated before moving to the next — better cache locality and
		// faster per-host completion.
		for _, ip := range ips {
			for _, port := range ports {
				select {
				case jobs <- job{ip: ip, port: port}:
				case <-ctx.Done():
					close(jobs)
					wg.Wait()
					return
				}
			}
		}
		close(jobs)
		wg.Wait()
	}()

	return results
}

func tcpProbe(ctx context.Context, ip net.IP, port uint16, timeout time.Duration) types.ScanResult {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	start := time.Now()

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		return types.ScanResult{
			IP:        ip,
			Port:      port,
			Protocol:  "tcp",
			Open:      false,
			ScannedAt: time.Now(),
		}
	}
	_ = conn.Close()

	return types.ScanResult{
		IP:         ip,
		Port:       port,
		Protocol:   "tcp",
		Open:       true,
		ResponseMs: elapsed,
		ScannedAt:  time.Now(),
	}
}
