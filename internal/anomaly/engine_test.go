package anomaly

import (
	"net"
	"testing"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/types"
)

func hasType(events []types.AnomalyEvent, typ types.AnomalyType) bool {
	for _, e := range events {
		if e.Type == typ {
			return true
		}
	}
	return false
}

func TestDiffNewPort(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	curr := &types.StateRecord{Timestamp: time.Now(), Open: true, ServiceName: "ssh"}
	events := diff(ip, 22, "tcp", nil, curr)
	if !hasType(events, types.AnomalyNewPort) {
		t.Errorf("expected new-port anomaly, got %+v", events)
	}
}

func TestDiffNoChange(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	prev := &types.StateRecord{Open: true, Banner: "same", Version: "1.0", ResponseMs: 10}
	curr := &types.StateRecord{Open: true, Banner: "same", Version: "1.0", ResponseMs: 10}
	if events := diff(ip, 80, "tcp", prev, curr); len(events) != 0 {
		t.Errorf("expected no anomalies for identical state, got %+v", events)
	}
}

func TestDiffBannerDrift(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	prev := &types.StateRecord{Open: true, Banner: "nginx/1.24"}
	curr := &types.StateRecord{Open: true, Banner: "nginx/1.25"}
	if !hasType(diff(ip, 80, "tcp", prev, curr), types.AnomalyBannerDrift) {
		t.Error("expected banner-drift anomaly")
	}
}

func TestDiffCertRotation(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	prev := &types.StateRecord{Open: true, TLSFingerprint: "aa:bb"}
	curr := &types.StateRecord{Open: true, TLSFingerprint: "cc:dd"}
	if !hasType(diff(ip, 443, "tcp", prev, curr), types.AnomalyCertRotation) {
		t.Error("expected cert-rotation anomaly")
	}
}

func TestDiffLatencySpike(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	prev := &types.StateRecord{Open: true, ResponseMs: 10}
	curr := &types.StateRecord{Open: true, ResponseMs: 100} // >3x
	if !hasType(diff(ip, 80, "tcp", prev, curr), types.AnomalyLatencySpike) {
		t.Error("expected latency-spike anomaly")
	}
}
