package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// QueryCTLogs queries crt.sh for certificate transparency log entries matching the domain.
// Returns discovered hostnames (subdomains) that have had TLS certificates issued.
func QueryCTLogs(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating CT log request: %w", err)
	}
	req.Header.Set("User-Agent", "corvus/0.1")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying crt.sh: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decoding crt.sh response: %w", err)
	}

	seen := make(map[string]bool)
	var names []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			if name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}

	return names, nil
}
