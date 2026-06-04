package osint

import "testing"

func TestDetectCloudProviderByASN(t *testing.T) {
	tests := []struct {
		asn  uint32
		want string
	}{
		{16509, "aws"},   // Amazon
		{15169, "gcp"},   // Google
		{8075, "azure"},  // Microsoft
		{999999, ""},     // unknown
	}
	for _, tt := range tests {
		if got := detectCloudProvider(tt.asn, ""); got != tt.want {
			t.Errorf("detectCloudProvider(%d) = %q, want %q", tt.asn, got, tt.want)
		}
	}
}

func TestDetectCloudProviderByOrg(t *testing.T) {
	tests := []struct {
		org  string
		want string
	}{
		{"Amazon.com, Inc.", "aws"},
		{"Google LLC", "gcp"},
		{"Microsoft Azure", "azure"},
		{"DigitalOcean, LLC", "digitalocean"},
		{"Cloudflare, Inc.", "cloudflare"},
		{"Some Random ISP", ""},
	}
	for _, tt := range tests {
		if got := detectCloudProvider(0, tt.org); got != tt.want {
			t.Errorf("detectCloudProvider(org=%q) = %q, want %q", tt.org, got, tt.want)
		}
	}
}

func TestParseASNRecord(t *testing.T) {
	// Team Cymru origin format: "ASN | BGP Prefix | CC | RIR | date"
	info, err := parseASNRecord("15169 | 8.8.8.0/24 | US | arin | 2000-03-30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ASN != 15169 {
		t.Errorf("want ASN 15169, got %d", info.ASN)
	}
	if info.Country != "US" {
		t.Errorf("want country US, got %q", info.Country)
	}
}

func TestParseASNRecordInvalid(t *testing.T) {
	if _, err := parseASNRecord("garbage"); err == nil {
		t.Error("expected error for malformed ASN record")
	}
}
