package osint

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ASNInfo holds the result of a BGP/ASN lookup.
type ASNInfo struct {
	ASN           uint32
	Organization  string
	Country       string
	CloudProvider string // "aws", "gcp", "azure", or ""
}

// LookupASN queries Team Cymru's DNS-based BGP/ASN service to identify the autonomous system
// that owns an IP address. This reveals the organization, country, and whether the IP belongs
// to a major cloud provider.
func LookupASN(ctx context.Context, ip net.IP) (*ASNInfo, error) {
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("only IPv4 supported for ASN lookup: %s", ip)
	}

	// Reverse the IP octets for the DNS query.
	// e.g., 1.2.3.4 → 4.3.2.1.origin.asn.cymru.com
	reversed := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com",
		v4[3], v4[2], v4[1], v4[0])

	txts, err := net.LookupTXT(reversed)
	if err != nil {
		return nil, fmt.Errorf("ASN DNS lookup for %s: %w", ip, err)
	}

	if len(txts) == 0 {
		return nil, fmt.Errorf("no ASN TXT record for %s", ip)
	}

	// TXT format: "ASN | IP/prefix | CC | RIR | date"
	// e.g., "16509 | 52.0.0.0/11 | US | arin | 2014-11-13"
	info, err := parseASNRecord(txts[0])
	if err != nil {
		return nil, err
	}

	// Enrich with org name from ASN peer lookup (optional, best-effort).
	orgName := lookupASNName(info.ASN)
	if orgName != "" {
		info.Organization = orgName
	}

	// Detect cloud provider from ASN.
	info.CloudProvider = detectCloudProvider(info.ASN, info.Organization)

	return info, nil
}

func parseASNRecord(txt string) (*ASNInfo, error) {
	parts := strings.Split(txt, "|")
	if len(parts) < 3 {
		return nil, fmt.Errorf("unexpected ASN record format: %q", txt)
	}

	asnStr := strings.TrimSpace(parts[0])
	// ASN field may contain multiple ASNs separated by spaces; take the first.
	if fields := strings.Fields(asnStr); len(fields) > 0 {
		asnStr = fields[0]
	}

	asn, err := strconv.ParseUint(asnStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parsing ASN %q: %w", asnStr, err)
	}

	country := ""
	if len(parts) >= 3 {
		country = strings.TrimSpace(parts[2])
	}

	return &ASNInfo{
		ASN:     uint32(asn),
		Country: country,
	}, nil
}

// lookupASNName queries Team Cymru for the AS name.
func lookupASNName(asn uint32) string {
	query := fmt.Sprintf("AS%d.asn.cymru.com", asn)
	txts, err := net.LookupTXT(query)
	if err != nil || len(txts) == 0 {
		return ""
	}

	// Format: "ASN | CC | RIR | date | AS Name"
	parts := strings.Split(txts[0], "|")
	if len(parts) >= 5 {
		return strings.TrimSpace(parts[4])
	}
	return ""
}

// detectCloudProvider maps known ASNs and organization names to cloud providers.
func detectCloudProvider(asn uint32, org string) string {
	// Known cloud provider ASNs.
	awsASNs := map[uint32]bool{
		16509: true, 14618: true, 38895: true,
		8987: true, 10124: true,
	}
	gcpASNs := map[uint32]bool{
		15169: true, 396982: true, 36040: true, 36384: true,
	}
	azureASNs := map[uint32]bool{
		8075: true, 8068: true, 8069: true, 12076: true,
	}

	if awsASNs[asn] {
		return "aws"
	}
	if gcpASNs[asn] {
		return "gcp"
	}
	if azureASNs[asn] {
		return "azure"
	}

	// Fallback: check organization name.
	orgLower := strings.ToLower(org)
	switch {
	case strings.Contains(orgLower, "amazon") || strings.Contains(orgLower, "aws"):
		return "aws"
	case strings.Contains(orgLower, "google") || strings.Contains(orgLower, "gcp"):
		return "gcp"
	case strings.Contains(orgLower, "microsoft") || strings.Contains(orgLower, "azure"):
		return "azure"
	case strings.Contains(orgLower, "digitalocean"):
		return "digitalocean"
	case strings.Contains(orgLower, "linode") || strings.Contains(orgLower, "akamai"):
		return "linode"
	case strings.Contains(orgLower, "cloudflare"):
		return "cloudflare"
	case strings.Contains(orgLower, "hetzner"):
		return "hetzner"
	case strings.Contains(orgLower, "ovh"):
		return "ovh"
	}

	return ""
}
