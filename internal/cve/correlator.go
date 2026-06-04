package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CVE represents a single vulnerability record.
type CVE struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	CVSSv3      float64 `json:"cvss_v3"`
	Severity    string  `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	URL         string  `json:"url"`
}

// Correlator looks up known vulnerabilities for fingerprinted services.
type Correlator struct {
	cache      *Cache
	apiKey     string // NVD API key (optional, increases rate limit)
	httpClient *http.Client
	log        *slog.Logger
}

// NewCorrelator creates a CVE correlator with a cache and optional NVD API key.
func NewCorrelator(cache *Cache, apiKey string, log *slog.Logger) *Correlator {
	return &Correlator{
		cache:  cache,
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
		},
		log: log,
	}
}

// Lookup returns known CVEs for a service name and version.
// Queries NVD and OSV, deduplicates, and caches the result.
func (c *Correlator) Lookup(ctx context.Context, service, version string) ([]CVE, error) {
	if version == "" {
		return nil, nil
	}

	cpe := buildCPE(service, version)

	// Check cache first.
	if c.cache != nil {
		if cached := c.cache.Get(cpe); cached != nil {
			c.log.Debug("CVE cache hit", "cpe", cpe, "count", len(cached))
			return cached, nil
		}
	}

	var allCVEs []CVE
	seen := make(map[string]bool)

	// Query NVD.
	nvdCVEs, err := c.queryNVD(ctx, cpe)
	if err != nil {
		c.log.Warn("NVD query failed", "cpe", cpe, "err", err)
	}
	for _, cv := range nvdCVEs {
		if !seen[cv.ID] {
			seen[cv.ID] = true
			allCVEs = append(allCVEs, cv)
		}
	}

	// Query OSV for additional coverage.
	osvCVEs, err := c.queryOSV(ctx, service, version)
	if err != nil {
		c.log.Debug("OSV query failed", "service", service, "err", err)
	}
	for _, cv := range osvCVEs {
		if !seen[cv.ID] {
			seen[cv.ID] = true
			allCVEs = append(allCVEs, cv)
		}
	}

	// Cache the combined result.
	if c.cache != nil {
		c.cache.Put(cpe, allCVEs)
	}

	c.log.Debug("CVE lookup complete", "cpe", cpe, "total", len(allCVEs))
	return allCVEs, nil
}

// queryNVD queries the NVD REST API v2.0 for CVEs matching a CPE.
func (c *Correlator) queryNVD(ctx context.Context, cpe string) ([]CVE, error) {
	endpoint := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	params := url.Values{
		"cpeName":        {cpe},
		"resultsPerPage": {"20"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "corvus/0.1")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD returned status %d", resp.StatusCode)
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decoding NVD response: %w", err)
	}

	var cves []CVE
	for _, vuln := range nvdResp.Vulnerabilities {
		cv := vuln.CVE
		cve := CVE{
			ID:  cv.ID,
			URL: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cv.ID),
		}

		// Extract description (prefer English).
		for _, desc := range cv.Descriptions {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}
		if cve.Description == "" && len(cv.Descriptions) > 0 {
			cve.Description = cv.Descriptions[0].Value
		}

		// Extract CVSS v3.1 score.
		if len(cv.Metrics.CVSSv31) > 0 {
			cve.CVSSv3 = cv.Metrics.CVSSv31[0].CVSSData.BaseScore
			cve.Severity = cv.Metrics.CVSSv31[0].CVSSData.BaseSeverity
		} else if len(cv.Metrics.CVSSv30) > 0 {
			cve.CVSSv3 = cv.Metrics.CVSSv30[0].CVSSData.BaseScore
			cve.Severity = cv.Metrics.CVSSv30[0].CVSSData.BaseSeverity
		}

		cves = append(cves, cve)
	}

	return cves, nil
}

// queryOSV queries the OSV.dev API for vulnerabilities.
func (c *Correlator) queryOSV(ctx context.Context, service, version string) ([]CVE, error) {
	ecosystem := mapServiceToEcosystem(service)
	if ecosystem == "" {
		return nil, nil
	}

	payload := fmt.Sprintf(`{"package":{"name":"%s","ecosystem":"%s"},"version":"%s"}`,
		service, ecosystem, version)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.osv.dev/v1/query", strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "corvus/0.1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned status %d", resp.StatusCode)
	}

	var osvResp osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("decoding OSV response: %w", err)
	}

	var cves []CVE
	for _, vuln := range osvResp.Vulns {
		cve := CVE{
			ID:          vuln.ID,
			Description: vuln.Summary,
			URL:         fmt.Sprintf("https://osv.dev/vulnerability/%s", vuln.ID),
		}

		// Extract CVE alias and CVSS if available.
		for _, alias := range vuln.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				cve.ID = alias
				cve.URL = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", alias)
				break
			}
		}

		// Map severity from database_specific or severity array.
		for _, sev := range vuln.Severity {
			if sev.Type == "CVSS_V3" {
				cve.CVSSv3 = parseCVSSScore(sev.Score)
				cve.Severity = cvssToSeverity(cve.CVSSv3)
			}
		}

		cves = append(cves, cve)
	}

	return cves, nil
}

// buildCPE constructs a CPE 2.3 string from a service name and version.
func buildCPE(service, version string) string {
	vendors := map[string]string{
		"nginx":         "f5",
		"apache":        "apache",
		"openssh":       "openbsd",
		"ssh":           "openbsd",
		"postgresql":    "postgresql",
		"redis":         "redis",
		"mysql":         "oracle",
		"elasticsearch": "elastic",
		"memcached":     "memcached",
		"mongodb":       "mongodb",
		"http":          "apache",
	}

	vendor, ok := vendors[strings.ToLower(service)]
	if !ok {
		vendor = strings.ToLower(service)
	}

	product := strings.ToLower(service)
	if product == "ssh" {
		product = "openssh"
	}

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}

func mapServiceToEcosystem(service string) string {
	ecosystems := map[string]string{
		"nginx":         "Debian",
		"apache":        "Debian",
		"openssh":       "Debian",
		"ssh":           "Debian",
		"redis":         "Debian",
		"postgresql":    "Debian",
		"mysql":         "Debian",
		"elasticsearch": "Maven",
		"memcached":     "Debian",
	}
	return ecosystems[strings.ToLower(service)]
}

func parseCVSSScore(vector string) float64 {
	// CVSS vectors end with a numeric score in some formats, but
	// the vector string itself doesn't contain the score. Return 0
	// and let the severity be set from NVD if available.
	return 0
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return ""
	}
}

// ── NVD API response types ───────────────────────────────────────────────────

type nvdResponse struct {
	Vulnerabilities []nvdVuln `json:"vulnerabilities"`
}

type nvdVuln struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSv31 []nvdCVSSEntry `json:"cvssMetricV31"`
	CVSSv30 []nvdCVSSEntry `json:"cvssMetricV30"`
}

type nvdCVSSEntry struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// ── OSV API response types ───────────────────────────────────────────────────

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Aliases  []string      `json:"aliases"`
	Severity []osvSeverity `json:"severity"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}
