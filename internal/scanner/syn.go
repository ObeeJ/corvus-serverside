package scanner

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/types"
)

// SYNScanner performs half-open TCP SYN scans using raw sockets.
// Requires CAP_NET_RAW capability or root privileges.
// If raw socket creation fails, it falls back to TCP connect scanning.
type SYNScanner struct {
	cfg      types.ScanConfig
	log      *slog.Logger
	fallback bool // true if we fell back to TCP connect
}

// NewSYN creates a SYN scanner. If raw sockets are unavailable, it logs a warning
// and transparently falls back to TCP connect scanning.
func NewSYN(cfg types.ScanConfig, log *slog.Logger) *SYNScanner {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 2000
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 750 * time.Millisecond
	}

	s := &SYNScanner{cfg: cfg, log: log}

	// Test if we can create raw sockets.
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		s.log.Warn("raw sockets unavailable, falling back to TCP connect scan",
			"err", err,
			"hint", "run with CAP_NET_RAW or as root for SYN scanning")
		s.fallback = true
	} else {
		conn.Close()
	}

	return s
}

// Scan implements the Scanner interface. If raw sockets are unavailable,
// delegates to TCP connect scanning.
func (s *SYNScanner) Scan(ctx context.Context, ips []net.IP, ports []uint16) <-chan types.ScanResult {
	if s.fallback {
		// Fall back to TCP connect scan.
		tcp := NewTCP(s.cfg, s.log)
		return tcp.Scan(ctx, ips, ports)
	}

	return s.synScan(ctx, ips, ports)
}

func (s *SYNScanner) synScan(ctx context.Context, ips []net.IP, ports []uint16) <-chan types.ScanResult {
	results := make(chan types.ScanResult, s.cfg.Concurrency)

	go func() {
		defer close(results)

		jobs := make(chan job, s.cfg.Concurrency)

		var wg sync.WaitGroup
		for i := 0; i < s.cfg.Concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobs {
					if ctx.Err() != nil {
						return
					}
					result := s.synProbe(ctx, j.ip, j.port)
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

// synProbe performs a SYN scan of a single port.
// Sends a crafted SYN packet and listens for SYN-ACK.
func (s *SYNScanner) synProbe(ctx context.Context, ip net.IP, port uint16) types.ScanResult {
	start := time.Now()
	target := &net.IPAddr{IP: ip}

	// Open raw socket for sending.
	conn, err := net.DialIP("ip4:tcp", nil, target)
	if err != nil {
		return types.ScanResult{
			IP: ip, Port: port, Protocol: "tcp", Open: false, ScannedAt: time.Now(),
		}
	}
	defer conn.Close()

	// Build a minimal TCP SYN packet.
	srcPort := uint16(40000 + (time.Now().UnixNano() % 20000))
	pkt := buildSYNPacket(srcPort, port, ip)

	conn.SetDeadline(time.Now().Add(s.cfg.Timeout)) //nolint:errcheck
	if _, err := conn.Write(pkt); err != nil {
		return types.ScanResult{
			IP: ip, Port: port, Protocol: "tcp", Open: false, ScannedAt: time.Now(),
		}
	}

	// Read the response.
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	elapsed := time.Since(start).Milliseconds()

	if err != nil || n < 20 {
		return types.ScanResult{
			IP: ip, Port: port, Protocol: "tcp", Open: false, ScannedAt: time.Now(),
		}
	}

	// Parse the TCP flags from the response.
	// TCP header starts after IP header (usually 20 bytes, but check IHL).
	ihl := int(buf[0]&0x0F) * 4
	if n < ihl+14 {
		return types.ScanResult{
			IP: ip, Port: port, Protocol: "tcp", Open: false, ScannedAt: time.Now(),
		}
	}

	flags := buf[ihl+13]
	synAck := flags&0x12 == 0x12 // SYN + ACK

	return types.ScanResult{
		IP:         ip,
		Port:       port,
		Protocol:   "tcp",
		Open:       synAck,
		ResponseMs: elapsed,
		ScannedAt:  time.Now(),
	}
}

// buildSYNPacket constructs a minimal TCP SYN packet.
func buildSYNPacket(srcPort, dstPort uint16, dstIP net.IP) []byte {
	pkt := make([]byte, 20) // minimal TCP header, no options

	binary.BigEndian.PutUint16(pkt[0:2], srcPort)  // source port
	binary.BigEndian.PutUint16(pkt[2:4], dstPort)   // destination port
	binary.BigEndian.PutUint32(pkt[4:8], 0)          // sequence number
	binary.BigEndian.PutUint32(pkt[8:12], 0)         // ack number
	pkt[12] = 5 << 4                                  // data offset (5 * 4 = 20 bytes)
	pkt[13] = 0x02                                    // flags: SYN
	binary.BigEndian.PutUint16(pkt[14:16], 65535)    // window size
	// Checksum and urgent pointer left as 0; kernel fills checksum for raw sockets.

	return pkt
}
