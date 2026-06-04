package store

import (
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/types"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestWriteAndReadLatestState(t *testing.T) {
	s := testStore(t)
	ip := net.ParseIP("192.168.1.10")
	rec := types.StateRecord{Timestamp: time.Now(), Open: true, ServiceName: "ssh", Version: "8.9"}

	if err := s.WriteState(ip, 22, "tcp", rec); err != nil {
		t.Fatalf("WriteState: %v", err)
	}

	got, err := s.ReadLatestState(ip, 22, "tcp")
	if err != nil {
		t.Fatalf("ReadLatestState: %v", err)
	}
	if got == nil {
		t.Fatal("expected a record, got nil")
	}
	if got.ServiceName != "ssh" || got.Version != "8.9" || !got.Open {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestReadOpenPortsAndListHosts(t *testing.T) {
	s := testStore(t)
	ip := net.ParseIP("192.168.1.10")
	_ = s.WriteState(ip, 22, "tcp", types.StateRecord{Timestamp: time.Now(), Open: true})
	_ = s.WriteState(ip, 443, "tcp", types.StateRecord{Timestamp: time.Now(), Open: true})
	_ = s.WriteState(ip, 23, "tcp", types.StateRecord{Timestamp: time.Now(), Open: false})

	ports, err := s.ReadOpenPorts(ip)
	if err != nil {
		t.Fatalf("ReadOpenPorts: %v", err)
	}
	if len(ports) != 2 {
		t.Errorf("expected 2 open ports, got %d (%v)", len(ports), ports)
	}

	hosts, err := s.ListHosts()
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != ip.String() {
		t.Errorf("expected [%s], got %v", ip, hosts)
	}
}

func TestMetaRoundTrip(t *testing.T) {
	s := testStore(t)
	if err := s.SetMeta("last_scan", "2026-06-04"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	v, err := s.GetMeta("last_scan")
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if v != "2026-06-04" {
		t.Errorf("want 2026-06-04, got %q", v)
	}
}

func TestHistoryWindow(t *testing.T) {
	s := testStore(t)
	ip := net.ParseIP("192.168.1.10")
	base := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 3; i++ {
		rec := types.StateRecord{Timestamp: base.Add(time.Duration(i) * time.Hour), Open: true}
		if err := s.WriteState(ip, 80, "tcp", rec); err != nil {
			t.Fatalf("WriteState: %v", err)
		}
	}
	hist, err := s.ReadHistory(ip, 80, "tcp", base.Add(-time.Minute), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("ReadHistory: %v", err)
	}
	if len(hist) != 3 {
		t.Errorf("expected 3 history records, got %d", len(hist))
	}
}
