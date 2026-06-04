package supplychain

import (
	"testing"

	"github.com/ObeeJ/corvus-serverside/internal/types"
)

func enriched(port uint16, service, banner string) types.EnrichedResult {
	r := types.EnrichedResult{ServiceName: service, Banner: banner}
	r.Port = port
	return r
}

func findingOfType(fs []types.SupplyChainFinding, typ string) *types.SupplyChainFinding {
	for i := range fs {
		if fs[i].Type == typ {
			return &fs[i]
		}
	}
	return nil
}

func TestCheckDebugPort(t *testing.T) {
	c := New()
	fs := c.Check(enriched(9229, "", ""))
	f := findingOfType(fs, "debug-port")
	if f == nil {
		t.Fatal("expected debug-port finding for port 9229")
	}
	if f.Severity != "HIGH" {
		t.Errorf("want HIGH severity, got %s", f.Severity)
	}
}

func TestCheckReverseShellPort(t *testing.T) {
	c := New()
	fs := c.Check(enriched(4444, "", ""))
	f := findingOfType(fs, "reverse-shell")
	if f == nil {
		t.Fatal("expected reverse-shell finding for port 4444")
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("want CRITICAL severity, got %s", f.Severity)
	}
}

func TestCheckDevToolFromBanner(t *testing.T) {
	c := New()
	fs := c.Check(enriched(8080, "http", "Server: Werkzeug/2.0 Python/3.9"))
	f := findingOfType(fs, "dev-tool")
	if f == nil {
		t.Fatal("expected dev-tool finding for Werkzeug banner")
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("Werkzeug should be CRITICAL, got %s", f.Severity)
	}
}

func TestCheckPackageManagerRequiresConfirmation(t *testing.T) {
	c := New()
	// Port 8081 (Nexus) without a confirming banner should NOT flag.
	if f := findingOfType(c.Check(enriched(8081, "http", "Server: nginx")), "exposed-pkg-mgr"); f != nil {
		t.Error("port 8081 without registry banner should not flag")
	}
	// With a confirming banner it should flag.
	if f := findingOfType(c.Check(enriched(8081, "http", "X-Nexus-Registry: true")), "exposed-pkg-mgr"); f == nil {
		t.Error("port 8081 with nexus banner should flag")
	}
	// Port 4873 (Verdaccio) flags even without a banner.
	if f := findingOfType(c.Check(enriched(4873, "", "")), "exposed-pkg-mgr"); f == nil {
		t.Error("port 4873 should always flag")
	}
}

func TestCheckDangerousDockerAPI(t *testing.T) {
	c := New()
	f := findingOfType(c.Check(enriched(2375, "docker", "")), "dangerous-service")
	if f == nil {
		t.Fatal("expected dangerous-service finding for Docker API on 2375")
	}
	if f.Severity != "CRITICAL" {
		t.Errorf("want CRITICAL, got %s", f.Severity)
	}
}

func TestCheckClean(t *testing.T) {
	c := New()
	if fs := c.Check(enriched(443, "https", "Server: nginx")); len(fs) != 0 {
		t.Errorf("expected no findings for benign https, got %v", fs)
	}
}
