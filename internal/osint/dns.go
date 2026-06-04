package osint

import (
	"net"
	"strings"
)

// ReverseLookup performs a PTR (reverse DNS) lookup and returns hostnames for the IP.
func ReverseLookup(ip net.IP) ([]string, error) {
	names, err := net.LookupAddr(ip.String())
	if err != nil {
		return nil, err
	}

	// LookupAddr returns names with trailing dots; strip them.
	clean := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if name != "" {
			clean = append(clean, name)
		}
	}
	return clean, nil
}

// scoreFromHostname applies heuristic port probability scores based on hostname keywords.
// If a hostname contains "db", the host is likely a database server, etc.
func scoreFromHostname(hostname string, scores map[uint16]float64) {
	lower := strings.ToLower(hostname)

	rules := map[string]map[uint16]float64{
		"db":            {5432: 0.85, 3306: 0.80, 27017: 0.70, 6379: 0.60},
		"postgres":      {5432: 0.95},
		"mysql":         {3306: 0.95},
		"mongo":         {27017: 0.95},
		"redis":         {6379: 0.95},
		"elastic":       {9200: 0.90, 9300: 0.80},
		"jenkins":       {8080: 0.90, 443: 0.80},
		"web":           {80: 0.90, 443: 0.90, 8080: 0.60},
		"api":           {443: 0.90, 8080: 0.75, 8443: 0.70, 3000: 0.50},
		"ssh":           {22: 0.95},
		"mail":          {25: 0.90, 587: 0.85, 993: 0.80, 143: 0.75, 110: 0.70},
		"smtp":          {25: 0.95, 587: 0.90},
		"imap":          {993: 0.95, 143: 0.90},
		"ldap":          {389: 0.90, 636: 0.85},
		"ftp":           {21: 0.95},
		"proxy":         {3128: 0.85, 8080: 0.75, 8443: 0.70},
		"cache":         {6379: 0.80, 11211: 0.75},
		"queue":         {5672: 0.85, 15672: 0.70},
		"rabbit":        {5672: 0.95, 15672: 0.80},
		"kafka":         {9092: 0.95},
		"zookeeper":     {2181: 0.90},
		"grafana":       {3000: 0.90},
		"prometheus":    {9090: 0.90},
		"kibana":        {5601: 0.90},
		"docker":        {2375: 0.85, 2376: 0.85},
		"kubernetes":    {6443: 0.90, 10250: 0.80},
		"k8s":           {6443: 0.90, 10250: 0.80},
		"etcd":          {2379: 0.90, 2380: 0.80},
		"consul":        {8500: 0.90, 8600: 0.70},
		"vault":         {8200: 0.90},
		"minio":         {9000: 0.90},
		"gitlab":        {80: 0.90, 443: 0.90, 8080: 0.70},
		"ci":            {8080: 0.75, 443: 0.70},
		"build":         {8080: 0.65},
		"vpn":           {1194: 0.85, 443: 0.70},
		"rdp":           {3389: 0.90},
		"windows":       {3389: 0.80, 445: 0.85, 135: 0.70},
		"oracle":        {1521: 0.90},
		"mssql":         {1433: 0.90},
	}

	for keyword, portMap := range rules {
		if strings.Contains(lower, keyword) {
			for port, score := range portMap {
				if existing, ok := scores[port]; !ok || score > existing {
					scores[port] = score
				}
			}
		}
	}
}

// extractBaseDomain returns the base domain from a FQDN.
// e.g., "db-primary.prod.example.com" → "example.com"
func extractBaseDomain(hostname string) string {
	hostname = strings.TrimSuffix(hostname, ".")
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return ""
	}
	// Take the last two components as the base domain.
	return strings.Join(parts[len(parts)-2:], ".")
}
