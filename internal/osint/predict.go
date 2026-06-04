package osint

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"github.com/ObeeJ/corvus-serverside/internal/types"
)

// Predictor gathers passive intelligence about targets before active scanning.
type Predictor struct {
	log *slog.Logger
}

// New creates a new OSINT predictor.
func New(log *slog.Logger) *Predictor {
	return &Predictor{log: log}
}

// Predict gathers all available passive intelligence about an IP and returns a scored profile.
// The profile's PortScores can be used to prioritise which ports to scan first.
func (p *Predictor) Predict(ctx context.Context, ip net.IP) *types.OSINTProfile {
	profile := &types.OSINTProfile{
		IP:         ip,
		PortScores: make(map[uint16]float64),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// Fan out to all OSINT sources concurrently.
	wg.Add(3)

	// 1. Reverse DNS
	go func() {
		defer wg.Done()
		names, err := ReverseLookup(ip)
		if err != nil {
			p.log.Debug("reverse DNS failed", "ip", ip, "err", err)
			return
		}

		mu.Lock()
		profile.Hostnames = append(profile.Hostnames, names...)
		for _, name := range names {
			scoreFromHostname(name, profile.PortScores)
		}
		mu.Unlock()

		p.log.Debug("reverse DNS complete", "ip", ip, "hostnames", names)
	}()

	// 2. BGP/ASN lookup
	go func() {
		defer wg.Done()
		info, err := LookupASN(ctx, ip)
		if err != nil {
			p.log.Debug("ASN lookup failed", "ip", ip, "err", err)
			return
		}

		mu.Lock()
		profile.ASN = info.ASN
		profile.Organization = info.Organization
		profile.CloudProvider = info.CloudProvider
		// Cloud providers have known patterns: boost common cloud ports.
		if info.CloudProvider != "" {
			scoreCloudPorts(info.CloudProvider, profile.PortScores)
		}
		mu.Unlock()

		p.log.Debug("ASN lookup complete", "ip", ip, "asn", info.ASN, "org", info.Organization, "cloud", info.CloudProvider)
	}()

	// 3. Certificate transparency (requires a hostname)
	go func() {
		defer wg.Done()
		// CT logs need a domain, not an IP. We wait for DNS to finish,
		// but since we're running concurrently, we do a quick lookup inline.
		names, _ := ReverseLookup(ip)
		if len(names) == 0 {
			return
		}
		// Use the first hostname's base domain for CT lookup.
		domain := extractBaseDomain(names[0])
		if domain == "" {
			return
		}

		ctNames, err := QueryCTLogs(ctx, domain)
		if err != nil {
			p.log.Debug("CT log query failed", "domain", domain, "err", err)
			return
		}

		mu.Lock()
		for _, name := range ctNames {
			// Avoid duplicates with names we already have.
			found := false
			for _, existing := range profile.Hostnames {
				if existing == name {
					found = true
					break
				}
			}
			if !found {
				profile.Hostnames = append(profile.Hostnames, name)
				scoreFromHostname(name, profile.PortScores)
			}
		}
		mu.Unlock()

		p.log.Debug("CT log query complete", "domain", domain, "names_found", len(ctNames))
	}()

	wg.Wait()

	// Apply default port scores for common ports that no source boosted.
	applyDefaults(profile.PortScores)

	return profile
}

// PrioritisePorts returns ports ordered by descending score from the profile.
// Ports not in the profile get a score of 0 and sort last (original order preserved).
func PrioritisePorts(ports []uint16, profile *types.OSINTProfile) []uint16 {
	if profile == nil || len(profile.PortScores) == 0 {
		return ports
	}

	type scored struct {
		port  uint16
		score float64
		idx   int // original position for stable sort
	}

	items := make([]scored, len(ports))
	for i, p := range ports {
		items[i] = scored{port: p, score: profile.PortScores[p], idx: i}
	}

	// Sort descending by score, stable by original index.
	for i := 1; i < len(items); i++ {
		for j := i; j > 0; j-- {
			if items[j].score > items[j-1].score ||
				(items[j].score == items[j-1].score && items[j].idx < items[j-1].idx) {
				items[j], items[j-1] = items[j-1], items[j]
			} else {
				break
			}
		}
	}

	result := make([]uint16, len(items))
	for i, s := range items {
		result[i] = s.port
	}
	return result
}

// scoreCloudPorts boosts ports commonly found on cloud provider infrastructure.
func scoreCloudPorts(provider string, scores map[uint16]float64) {
	// All cloud providers commonly expose:
	boostIfHigher(scores, 22, 0.70)   // SSH
	boostIfHigher(scores, 443, 0.80)  // HTTPS
	boostIfHigher(scores, 80, 0.75)   // HTTP
	boostIfHigher(scores, 8080, 0.50) // Alt HTTP

	switch provider {
	case "aws":
		boostIfHigher(scores, 5432, 0.40) // RDS Postgres
		boostIfHigher(scores, 3306, 0.40) // RDS MySQL
		boostIfHigher(scores, 6379, 0.35) // ElastiCache Redis
	case "gcp":
		boostIfHigher(scores, 8443, 0.45)
	case "azure":
		boostIfHigher(scores, 3389, 0.50) // RDP common on Azure
		boostIfHigher(scores, 1433, 0.40) // Azure SQL
	}
}

// applyDefaults ensures common ports have at least a baseline score.
func applyDefaults(scores map[uint16]float64) {
	defaults := map[uint16]float64{
		22:  0.30, // SSH
		80:  0.40, // HTTP
		443: 0.40, // HTTPS
		25:  0.15, // SMTP
		53:  0.15, // DNS
	}
	for port, score := range defaults {
		if _, exists := scores[port]; !exists {
			scores[port] = score
		}
	}
}

func boostIfHigher(scores map[uint16]float64, port uint16, score float64) {
	if existing, ok := scores[port]; !ok || score > existing {
		scores[port] = score
	}
}
