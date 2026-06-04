package query

import (
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/ObeeJ/corvus-serverside/internal/types"
	"github.com/ObeeJ/corvus-serverside/pkg/iprange"
)

// QueryPlan is the parsed representation of a user query.
type QueryPlan struct {
	Conditions []Condition
	TargetCIDR string
	Since      time.Time
	Until      time.Time
}

// Condition is a single filter clause in a query.
type Condition struct {
	Type  string // "open-port", "service", "cve-severity", "banner-contains", "new-port"
	Value string
}

// QueryResult is one row in the query output.
type QueryResult struct {
	IP       string             `json:"ip"`
	Port     uint16             `json:"port"`
	Protocol string             `json:"protocol"`
	State    types.StateRecord  `json:"state"`
}

// Engine executes parsed query plans against the temporal store.
type Engine struct {
	store *store.Store
	log   *slog.Logger
}

// NewEngine creates a query engine backed by the given store.
func NewEngine(st *store.Store, log *slog.Logger) *Engine {
	return &Engine{store: st, log: log}
}

// Parse converts a natural-language-like query string into a structured QueryPlan.
// Supported patterns:
//   - "ports opened in last 24h"
//   - "open ports on 10.0.0.0/24"
//   - "hosts running ssh in last 7d"
//   - "services with critical cves"
func Parse(input string) (*QueryPlan, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("empty query")
	}

	lower := strings.ToLower(input)
	plan := &QueryPlan{}

	// Extract time clause: "in last <duration>" or "in the last <duration>"
	lower, plan.Since = extractTimeSince(lower)

	// Extract target CIDR/IP.
	lower, plan.TargetCIDR = extractTarget(lower)

	// Extract conditions from the remaining text.
	plan.Conditions = parseConditions(lower)

	return plan, nil
}

// Execute runs a QueryPlan against the store and returns matching results.
func (e *Engine) Execute(plan *QueryPlan) ([]QueryResult, error) {
	// Determine which hosts to query.
	hosts, err := e.resolveHosts(plan.TargetCIDR)
	if err != nil {
		return nil, fmt.Errorf("resolving hosts: %w", err)
	}

	var results []QueryResult

	for _, hostIP := range hosts {
		ip := net.ParseIP(hostIP)
		if ip == nil {
			continue
		}

		// Get all open ports for this host.
		openPorts, err := e.store.ReadOpenPorts(ip)
		if err != nil {
			e.log.Debug("reading open ports", "host", hostIP, "err", err)
			continue
		}

		for _, portProto := range openPorts {
			var port uint16
			var proto string
			fmt.Sscanf(portProto, "%d/%s", &port, &proto) //nolint:errcheck

			// Read the latest state for filtering.
			latest, err := e.store.ReadLatestState(ip, port, proto)
			if err != nil || latest == nil {
				continue
			}

			// If we have a time range, check the history.
			if !plan.Since.IsZero() {
				history, err := e.store.ReadHistory(ip, port, proto, plan.Since, plan.Until)
				if err != nil || len(history) == 0 {
					continue
				}
				// Use the most recent record from the history window.
				latest = &history[len(history)-1]
			}

			// Apply conditions.
			if !matchesConditions(latest, port, proto, plan.Conditions) {
				continue
			}

			results = append(results, QueryResult{
				IP:       hostIP,
				Port:     port,
				Protocol: proto,
				State:    *latest,
			})
		}
	}

	e.log.Debug("query executed", "results", len(results), "hosts_checked", len(hosts))
	return results, nil
}

// resolveHosts determines which hosts to query.
func (e *Engine) resolveHosts(targetCIDR string) ([]string, error) {
	if targetCIDR == "" {
		// No target specified: query all known hosts.
		return e.store.ListHosts()
	}

	// Parse the target as an IP range and return string IPs.
	ips, err := iprange.Parse(targetCIDR)
	if err != nil {
		return nil, err
	}

	hosts := make([]string, len(ips))
	for i, ip := range ips {
		hosts[i] = ip.String()
	}
	return hosts, nil
}

func matchesConditions(rec *types.StateRecord, port uint16, proto string, conditions []Condition) bool {
	if len(conditions) == 0 {
		return true // no conditions means "show everything"
	}

	for _, cond := range conditions {
		switch cond.Type {
		case "open-port":
			p, err := strconv.ParseUint(cond.Value, 10, 16)
			if err != nil {
				continue
			}
			if port != uint16(p) {
				return false
			}

		case "service":
			if !strings.EqualFold(rec.ServiceName, cond.Value) {
				return false
			}

		case "banner-contains":
			if !strings.Contains(strings.ToLower(rec.Banner), strings.ToLower(cond.Value)) {
				return false
			}

		case "new-port":
			// "new port" queries match any open port (the time filter handles "new").
			if !rec.Open {
				return false
			}

		case "open":
			if !rec.Open {
				return false
			}
		}
	}
	return true
}

// ── Parser helpers ───────────────────────────────────────────────────────────

var reTimeSince = regexp.MustCompile(`(?i)in\s+(?:the\s+)?last\s+(\d+)\s*(s|sec|seconds?|m|min|minutes?|h|hours?|d|days?|w|weeks?)`)
var reTarget = regexp.MustCompile(`(?i)(?:on|in|for)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)`)

func extractTimeSince(input string) (string, time.Time) {
	match := reTimeSince.FindStringSubmatchIndex(input)
	if match == nil {
		return input, time.Time{}
	}

	numStr := input[match[2]:match[3]]
	unitStr := strings.ToLower(input[match[4]:match[5]])

	num, err := strconv.Atoi(numStr)
	if err != nil {
		return input, time.Time{}
	}

	var d time.Duration
	switch {
	case strings.HasPrefix(unitStr, "s"):
		d = time.Duration(num) * time.Second
	case strings.HasPrefix(unitStr, "m"):
		d = time.Duration(num) * time.Minute
	case strings.HasPrefix(unitStr, "h"):
		d = time.Duration(num) * time.Hour
	case strings.HasPrefix(unitStr, "d"):
		d = time.Duration(num) * 24 * time.Hour
	case strings.HasPrefix(unitStr, "w"):
		d = time.Duration(num) * 7 * 24 * time.Hour
	default:
		return input, time.Time{}
	}

	cleaned := input[:match[0]] + input[match[1]:]
	return strings.TrimSpace(cleaned), time.Now().Add(-d)
}

func extractTarget(input string) (string, string) {
	match := reTarget.FindStringSubmatch(input)
	if match == nil {
		return input, ""
	}

	target := match[1]
	cleaned := strings.Replace(input, match[0], "", 1)
	return strings.TrimSpace(cleaned), target
}

func parseConditions(input string) []Condition {
	var conditions []Condition
	lower := strings.ToLower(input)

	// "ports opened" or "new ports" or "open ports"
	if strings.Contains(lower, "port") && (strings.Contains(lower, "open") || strings.Contains(lower, "new")) {
		conditions = append(conditions, Condition{Type: "open", Value: ""})
	}

	// "running <service>" or "with <service>"
	reService := regexp.MustCompile(`(?i)(?:running|with)\s+(\w+)`)
	if m := reService.FindStringSubmatch(lower); m != nil {
		svc := m[1]
		// Filter out common non-service words.
		nonServices := map[string]bool{"critical": true, "high": true, "any": true, "all": true, "the": true}
		if !nonServices[svc] {
			conditions = append(conditions, Condition{Type: "service", Value: svc})
		}
	}

	// "port <number>"
	rePort := regexp.MustCompile(`(?i)port\s+(\d+)`)
	if m := rePort.FindStringSubmatch(lower); m != nil {
		conditions = append(conditions, Condition{Type: "open-port", Value: m[1]})
	}

	// If no conditions were parsed, treat as "show all open".
	if len(conditions) == 0 {
		conditions = append(conditions, Condition{Type: "open", Value: ""})
	}

	return conditions
}
