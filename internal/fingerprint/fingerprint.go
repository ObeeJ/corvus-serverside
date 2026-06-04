package fingerprint

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/types"
)

const (
	bannerReadSize = 4096
	bannerTimeout  = 500 * time.Millisecond
)

type Fingerprinter struct {
	log *slog.Logger
}

func New(log *slog.Logger) *Fingerprinter {
	return &Fingerprinter{log: log}
}

// Enrich takes an open ScanResult and returns an EnrichedResult with service details.
// For closed ports it returns the ScanResult unchanged.
func (f *Fingerprinter) Enrich(ctx context.Context, result types.ScanResult) types.EnrichedResult {
	enriched := types.EnrichedResult{ScanResult: result}
	if !result.Open {
		return enriched
	}

	// Attempt TLS handshake first on known TLS ports.
	if tlsPorts[result.Port] {
		if info := f.grabTLS(result.IP, result.Port); info != nil {
			enriched.TLSFingerprint = info.fingerprint
			enriched.TLSSubject = info.subject
			enriched.TLSExpiry = info.expiry
		}
	}

	banner := f.grabBanner(ctx, result.IP, result.Port)
	enriched.Banner = banner

	svc, ver := matchPatterns(banner)
	if svc == "" {
		svc = portHints[result.Port]
	}

	enriched.ServiceName = svc
	enriched.Version = ver

	// Upgrade "http" to "https" when a TLS cert was found.
	if enriched.TLSFingerprint != "" && enriched.ServiceName == "http" {
		enriched.ServiceName = "https"
	}

	f.log.Debug("fingerprinted",
		"host", result.IP,
		"port", result.Port,
		"service", enriched.ServiceName,
		"version", enriched.Version,
	)

	return enriched
}

func (f *Fingerprinter) grabBanner(ctx context.Context, ip net.IP, port uint16) string {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	d := net.Dialer{Timeout: bannerTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close() //nolint:errcheck
	conn.SetDeadline(time.Now().Add(bannerTimeout)) //nolint:errcheck

	// For HTTP ports, send a minimal probe to elicit a response.
	if httpProbePorts[port] {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: corvus/0.1\r\n\r\n", ip.String()) //nolint:errcheck
	}

	buf := make([]byte, bannerReadSize)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	return string(buf[:n])
}

type tlsInfo struct {
	fingerprint string
	subject     string
	expiry      time.Time
}

func (f *Fingerprinter) grabTLS(ip net.IP, port uint16) *tlsInfo {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: bannerTimeout},
		"tcp",
		addr,
		&tls.Config{InsecureSkipVerify: true}, //nolint:gosec — intentional for scanning
	)
	if err != nil {
		return nil
	}
	defer conn.Close() //nolint:errcheck

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	leaf := certs[0]
	fp := sha256.Sum256(leaf.Raw)

	return &tlsInfo{
		fingerprint: fmt.Sprintf("%x", fp),
		subject:     leaf.Subject.CommonName,
		expiry:      leaf.NotAfter,
	}
}

func matchPatterns(banner string) (service, version string) {
	if banner == "" {
		return "", ""
	}
	for _, p := range patterns {
		if p.re.MatchString(banner) {
			service = p.service
			if p.version != nil {
				if m := p.version.FindStringSubmatch(banner); len(m) > 1 {
					version = m[1]
				}
			}
			return service, version
		}
	}
	return "", ""
}
