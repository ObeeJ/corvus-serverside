package query

import (
	"testing"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/types"
)

func TestParseExtractsTarget(t *testing.T) {
	plan, err := Parse("open ports on 10.0.0.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.TargetCIDR != "10.0.0.0/24" {
		t.Errorf("want target 10.0.0.0/24, got %q", plan.TargetCIDR)
	}
}

func TestParseExtractsTimeWindow(t *testing.T) {
	plan, err := Parse("ports opened in the last 24h")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Since.IsZero() {
		t.Fatal("expected a non-zero Since time")
	}
	elapsed := time.Since(plan.Since)
	if elapsed < 23*time.Hour || elapsed > 25*time.Hour {
		t.Errorf("Since should be ~24h ago, got %v ago", elapsed)
	}
}

func TestParseExtractsService(t *testing.T) {
	plan, err := Parse("hosts running ssh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var found bool
	for _, c := range plan.Conditions {
		if c.Type == "service" && c.Value == "ssh" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected service=ssh condition, got %+v", plan.Conditions)
	}
}

func TestParseEmptyErrors(t *testing.T) {
	if _, err := Parse("   "); err == nil {
		t.Error("expected error for empty query")
	}
}

func TestMatchesConditions(t *testing.T) {
	rec := &types.StateRecord{Open: true, ServiceName: "ssh", Banner: "SSH-2.0-OpenSSH_8.9"}

	tests := []struct {
		name string
		port uint16
		cond []Condition
		want bool
	}{
		{"no conditions matches all", 22, nil, true},
		{"service match", 22, []Condition{{Type: "service", Value: "ssh"}}, true},
		{"service mismatch", 22, []Condition{{Type: "service", Value: "http"}}, false},
		{"port match", 22, []Condition{{Type: "open-port", Value: "22"}}, true},
		{"port mismatch", 22, []Condition{{Type: "open-port", Value: "80"}}, false},
		{"banner contains", 22, []Condition{{Type: "banner-contains", Value: "openssh"}}, true},
		{"banner missing", 22, []Condition{{Type: "banner-contains", Value: "nginx"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesConditions(rec, tt.port, "tcp", tt.cond); got != tt.want {
				t.Errorf("matchesConditions = %v, want %v", got, tt.want)
			}
		})
	}
}
