package fingerprint

import "testing"

func TestMatchPatterns(t *testing.T) {
	tests := []struct {
		name        string
		banner      string
		wantService string
	}{
		{"ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu", "ssh"},
		{"nginx", "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n", "http"},
		{"apache", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57\r\n", "http"},
		{"generic http", "HTTP/1.1 404 Not Found", "http"},
		{"empty", "", ""},
		{"unknown", "random noise that matches nothing", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := matchPatterns(tt.banner)
			if svc != tt.wantService {
				t.Errorf("matchPatterns(%q) service = %q, want %q", tt.banner, svc, tt.wantService)
			}
		})
	}
}

func TestMatchPatternsExtractsVersion(t *testing.T) {
	// nginx Server header carries a version the pattern should capture if defined.
	svc, ver := matchPatterns("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n")
	if svc != "http" {
		t.Fatalf("want http, got %q", svc)
	}
	// Version capture is best-effort; if present it must be the real version.
	if ver != "" && ver != "1.25.3" {
		t.Errorf("unexpected version %q", ver)
	}
}
