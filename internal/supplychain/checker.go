package supplychain

import (
	"fmt"
	"strings"

	"github.com/ObeeJ/corvus-serverside/internal/types"
)

// Checker evaluates scan results against security hygiene rules.
// It detects debug ports, dev tools, reverse shell indicators, and exposed package managers
// that should never appear on production hosts.
type Checker struct{}

// New creates a new supply chain checker.
func New() *Checker {
	return &Checker{}
}

// Check evaluates a single enriched result and returns any supply chain findings.
func (c *Checker) Check(result types.EnrichedResult) []types.SupplyChainFinding {
	var findings []types.SupplyChainFinding

	// Check debug ports.
	if f := checkDebugPorts(result); f != nil {
		findings = append(findings, *f)
	}

	// Check dev tools.
	if f := checkDevTools(result); f != nil {
		findings = append(findings, *f)
	}

	// Check reverse shell ports.
	if f := checkReverseShellPorts(result); f != nil {
		findings = append(findings, *f)
	}

	// Check exposed package managers.
	if f := checkPackageManagers(result); f != nil {
		findings = append(findings, *f)
	}

	// Check dangerous exposed services.
	if f := checkDangerousServices(result); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

// ── Debug port detection ─────────────────────────────────────────────────────

var debugPorts = map[uint16]string{
	5005:  "Java Debug Wire Protocol (JDWP)",
	5858:  "Node.js legacy debugger",
	9229:  "Node.js inspector",
	9222:  "Chrome DevTools Protocol",
	4200:  "Angular dev server",
	3000:  "Development server (Vite/Next.js/Grafana)",
	5000:  "Flask/development server",
	8000:  "Django development server",
	35729: "LiveReload",
	6006:  "TensorBoard",
	8888:  "Jupyter Notebook",
	4040:  "Spark UI",
	2345:  "Go Delve debugger",
	1234:  "PHP Xdebug",
}

func checkDebugPorts(r types.EnrichedResult) *types.SupplyChainFinding {
	desc, found := debugPorts[r.Port]
	if !found {
		return nil
	}

	return &types.SupplyChainFinding{
		Type:        "debug-port",
		Severity:    "HIGH",
		Port:        r.Port,
		Service:     r.ServiceName,
		Description: fmt.Sprintf("debug port %d open: %s — should not be exposed in production", r.Port, desc),
	}
}

// ── Dev tool detection ───────────────────────────────────────────────────────

type devToolRule struct {
	bannerContains string
	service        string
	description    string
	severity       string
}

var devToolRules = []devToolRule{
	{"webpack-dev-server", "webpack", "Webpack dev server exposed — development build artifact", "HIGH"},
	{"Vite", "vite", "Vite dev server exposed — development build artifact", "HIGH"},
	{"WEBrick", "webrick", "Ruby WEBrick dev server — not for production use", "MEDIUM"},
	{"Werkzeug", "werkzeug", "Python Werkzeug debugger — may allow remote code execution", "CRITICAL"},
	{"phpMyAdmin", "phpmyadmin", "phpMyAdmin exposed — database admin panel accessible", "CRITICAL"},
	{"Adminer", "adminer", "Adminer database tool exposed", "CRITICAL"},
	{"phpinfo", "phpinfo", "PHP info page exposed — leaks server configuration", "HIGH"},
	{"Jupyter", "jupyter", "Jupyter Notebook exposed — may allow arbitrary code execution", "CRITICAL"},
	{"Swagger", "swagger", "Swagger API docs exposed — reveals API surface", "MEDIUM"},
	{"GraphQL Playground", "graphql", "GraphQL Playground exposed — interactive query interface", "MEDIUM"},
	{"X-Powered-By: Express", "express-debug", "Express.js debug headers enabled", "LOW"},
	{"Server: development", "dev-server", "Server running in development mode", "MEDIUM"},
	{"debug", "debug-mode", "Debug mode indicator in banner", "MEDIUM"},
}

func checkDevTools(r types.EnrichedResult) *types.SupplyChainFinding {
	if r.Banner == "" {
		return nil
	}
	bannerLower := strings.ToLower(r.Banner)

	for _, rule := range devToolRules {
		if strings.Contains(bannerLower, strings.ToLower(rule.bannerContains)) {
			return &types.SupplyChainFinding{
				Type:        "dev-tool",
				Severity:    rule.severity,
				Port:        r.Port,
				Service:     rule.service,
				Description: rule.description,
			}
		}
	}
	return nil
}

// ── Reverse shell port detection ─────────────────────────────────────────────

var reverseShellPorts = map[uint16]string{
	4444: "Metasploit default handler",
	4445: "Metasploit alternate handler",
	5555: "Common reverse shell / Android Debug Bridge",
	1337: "Common backdoor port (leet)",
	31337: "Back Orifice / classic backdoor",
	6666: "Common backdoor port",
	6667: "IRC (often used for C2)",
	6697: "IRC over TLS (often used for C2)",
}

func checkReverseShellPorts(r types.EnrichedResult) *types.SupplyChainFinding {
	desc, found := reverseShellPorts[r.Port]
	if !found {
		return nil
	}

	return &types.SupplyChainFinding{
		Type:        "reverse-shell",
		Severity:    "CRITICAL",
		Port:        r.Port,
		Service:     r.ServiceName,
		Description: fmt.Sprintf("suspicious port %d open: %s — commonly used for reverse shells or C2", r.Port, desc),
	}
}

// ── Exposed package manager detection ────────────────────────────────────────

var packageManagerPorts = map[uint16]string{
	4873:  "Verdaccio/Sinopia (npm registry)",
	8036:  "PyPI server",
	5000:  "Docker Registry (when banner matches)",
	8081:  "Nexus Repository Manager",
	8082:  "Artifactory",
	9090:  "Sonatype Nexus (when banner matches)",
}

func checkPackageManagers(r types.EnrichedResult) *types.SupplyChainFinding {
	desc, found := packageManagerPorts[r.Port]
	if !found {
		return nil
	}

	bannerLower := strings.ToLower(r.Banner)
	// Only flag if the banner confirms it's actually a package manager,
	// since some of these ports are used by other services too.
	pkgKeywords := []string{"registry", "nexus", "artifactory", "verdaccio", "pypi", "sinopia"}
	confirmed := false
	for _, kw := range pkgKeywords {
		if strings.Contains(bannerLower, kw) {
			confirmed = true
			break
		}
	}

	// Port 4873 is almost always Verdaccio — flag even without banner confirmation.
	if r.Port == 4873 {
		confirmed = true
	}

	if !confirmed {
		return nil
	}

	return &types.SupplyChainFinding{
		Type:        "exposed-pkg-mgr",
		Severity:    "HIGH",
		Port:        r.Port,
		Service:     r.ServiceName,
		Description: fmt.Sprintf("package manager exposed on port %d: %s — may allow dependency poisoning", r.Port, desc),
	}
}

// ── Dangerous exposed services ───────────────────────────────────────────────

func checkDangerousServices(r types.EnrichedResult) *types.SupplyChainFinding {
	svc := strings.ToLower(r.ServiceName)
	bannerLower := strings.ToLower(r.Banner)

	// Docker API without TLS.
	if r.Port == 2375 && (svc == "docker" || strings.Contains(bannerLower, "docker")) {
		return &types.SupplyChainFinding{
			Type:        "dangerous-service",
			Severity:    "CRITICAL",
			Port:        r.Port,
			Service:     "docker",
			Description: "Docker API exposed on port 2375 without TLS — allows unauthenticated container control",
		}
	}

	// Kubernetes API.
	if r.Port == 10250 && (svc == "kubelet" || strings.Contains(bannerLower, "kubelet")) {
		return &types.SupplyChainFinding{
			Type:        "dangerous-service",
			Severity:    "CRITICAL",
			Port:        r.Port,
			Service:     "kubelet",
			Description: "Kubelet API exposed on port 10250 — may allow pod execution",
		}
	}

	// etcd without auth.
	if r.Port == 2379 && (svc == "etcd" || strings.Contains(bannerLower, "etcd")) {
		return &types.SupplyChainFinding{
			Type:        "dangerous-service",
			Severity:    "CRITICAL",
			Port:        r.Port,
			Service:     "etcd",
			Description: "etcd API exposed on port 2379 — may contain Kubernetes secrets",
		}
	}

	// Redis without auth.
	if svc == "redis" && !strings.Contains(bannerLower, "noauth") {
		if strings.Contains(bannerLower, "redis_version") {
			return &types.SupplyChainFinding{
				Type:        "dangerous-service",
				Severity:    "HIGH",
				Port:        r.Port,
				Service:     "redis",
				Description: "Redis exposed without apparent authentication — may allow data exfiltration or RCE",
			}
		}
	}

	return nil
}
