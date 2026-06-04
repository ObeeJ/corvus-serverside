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

// UDPScanner sends UDP probes and listens for ICMP port-unreachable responses.
// A port is considered open if no ICMP unreachable is received within the timeout.
// Note: UDP scanning is inherently unreliable — open|filtered is common.
type UDPScanner struct {
	cfg types.ScanConfig
	log *slog.Logger
}

// NewUDP creates a UDP scanner.
func NewUDP(cfg types.ScanConfig, log *slog.Logger) *UDPScanner {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 200 // lower default than TCP: UDP is rate-limited by ICMP backoff
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second // longer timeout: UDP response may be slow
	}
	return &UDPScanner{cfg: cfg, log: log}
}

// Scan implements the Scanner interface for UDP scanning.
func (s *UDPScanner) Scan(ctx context.Context, ips []net.IP, ports []uint16) <-chan types.ScanResult {
	results := make(chan types.ScanResult, s.cfg.Concurrency)

	go func() {
		defer close(results)

		jobs := make(chan job, s.cfg.Concurrency)

		var limiter *rate.Limiter
		if s.cfg.Rate > 0 {
			limiter = rate.NewLimiter(rate.Limit(s.cfg.Rate), s.cfg.Rate)
		} else {
			// Default rate limit for UDP to avoid ICMP rate limiting on the target.
			limiter = rate.NewLimiter(rate.Limit(100), 100)
		}

		var wg sync.WaitGroup
		for i := 0; i < s.cfg.Concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobs {
					if ctx.Err() != nil {
						return
					}
					if err := limiter.Wait(ctx); err != nil {
						return
					}
					result := udpProbe(ctx, j.ip, j.port, s.cfg.Timeout)
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

// udpProbe sends an empty UDP datagram and waits for a response.
// If the port is closed, the target sends ICMP port-unreachable, which Go's
// net.DialContext surfaces as a connection refused error on the next read.
// If no error occurs within the timeout, the port is considered open|filtered.
func udpProbe(ctx context.Context, ip net.IP, port uint16, timeout time.Duration) types.ScanResult {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	start := time.Now()

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return types.ScanResult{
			IP: ip, Port: port, Protocol: "udp", Open: false, ScannedAt: time.Now(),
		}
	}
	defer conn.Close()

	// Send a probe payload. For known services, send a protocol-specific probe.
	payload := udpProbePayload(port)
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck
	if _, err := conn.Write(payload); err != nil {
		return types.ScanResult{
			IP: ip, Port: port, Protocol: "udp", Open: false, ScannedAt: time.Now(),
		}
	}

	// Try to read a response.
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		// Check if it's a "connection refused" (ICMP port unreachable).
		if isConnectionRefused(err) {
			return types.ScanResult{
				IP: ip, Port: port, Protocol: "udp", Open: false, ScannedAt: time.Now(),
			}
		}
		// Timeout or other error: port is open|filtered (we treat as open).
		return types.ScanResult{
			IP:         ip,
			Port:       port,
			Protocol:   "udp",
			Open:       true,
			ResponseMs: elapsed,
			ScannedAt:  time.Now(),
		}
	}

	// Got a response: port is definitely open.
	_ = n // response data is available if needed for fingerprinting
	return types.ScanResult{
		IP:         ip,
		Port:       port,
		Protocol:   "udp",
		Open:       true,
		ResponseMs: elapsed,
		ScannedAt:  time.Now(),
	}
}

// udpProbePayload returns a protocol-appropriate probe for known UDP services.
func udpProbePayload(port uint16) []byte {
	switch port {
	case 53:
		// DNS query for version.bind (minimal valid DNS packet).
		return []byte{
			0x00, 0x01, // Transaction ID
			0x01, 0x00, // Flags: standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answers: 0
			0x00, 0x00, // Authority: 0
			0x00, 0x00, // Additional: 0
			0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
			0x04, 'b', 'i', 'n', 'd', 0x00,
			0x00, 0x10, // Type: TXT
			0x00, 0x03, // Class: CH
		}
	case 123:
		// NTP version request (NTPv3 client mode).
		pkt := make([]byte, 48)
		pkt[0] = 0x1B // LI=0, Version=3, Mode=3 (client)
		return pkt
	case 161:
		// SNMP v1 GetRequest for sysDescr.
		return []byte{
			0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70,
			0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
			0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
			0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06,
			0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
		}
	case 500:
		// IKE (ISAKMP) SA init.
		return []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Initiator SPI
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Responder SPI
			0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // Header
			0x00, 0x00, 0x00, 0x1c,                         // Length
		}
	default:
		// Generic empty probe.
		return []byte{0x00}
	}
}

// isConnectionRefused checks if an error indicates ICMP port-unreachable.
func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return contains(errStr, "connection refused") ||
		contains(errStr, "unreachable")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
