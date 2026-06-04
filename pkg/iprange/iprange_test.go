package iprange

import "testing"

func TestParseSingleIP(t *testing.T) {
	ips, err := Parse("192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("want 1 IP, got %d", len(ips))
	}
	if ips[0].String() != "192.168.1.1" {
		t.Errorf("want 192.168.1.1, got %s", ips[0])
	}
}

func TestParseCIDR(t *testing.T) {
	ips, err := Parse("10.0.0.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /30 yields 2 usable hosts (network and broadcast excluded).
	if len(ips) != 2 {
		t.Fatalf("want 2 usable hosts for /30, got %d", len(ips))
	}
}

func TestParseRange(t *testing.T) {
	ips, err := Parse("192.168.1.1-192.168.1.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 5 {
		t.Fatalf("want 5 IPs, got %d", len(ips))
	}
	if ips[0].String() != "192.168.1.1" || ips[4].String() != "192.168.1.5" {
		t.Errorf("range bounds wrong: %s..%s", ips[0], ips[4])
	}
}

func TestParseInvalid(t *testing.T) {
	for _, in := range []string{"", "not-an-ip", "999.999.999.999"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) expected error, got nil", in)
		}
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		spec string
		want []uint16
	}{
		{"80", []uint16{80}},
		{"80,443", []uint16{80, 443}},
		{"1-3", []uint16{1, 2, 3}},
		{"80,80,443", []uint16{80, 443}}, // dedup
		{"443, 80 ,22", []uint16{443, 80, 22}},
	}
	for _, tt := range tests {
		got, err := ParsePorts(tt.spec)
		if err != nil {
			t.Errorf("ParsePorts(%q) error: %v", tt.spec, err)
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("ParsePorts(%q) = %v, want %v", tt.spec, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("ParsePorts(%q) = %v, want %v", tt.spec, got, tt.want)
				break
			}
		}
	}
}

func TestParsePortsInvalid(t *testing.T) {
	for _, in := range []string{"", "abc", "5-1", "70000"} {
		if _, err := ParsePorts(in); err == nil {
			t.Errorf("ParsePorts(%q) expected error, got nil", in)
		}
	}
}
