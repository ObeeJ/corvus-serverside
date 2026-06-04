package apikey

import (
	"strings"
	"testing"
)

func TestHashIsDeterministicAndHex(t *testing.T) {
	h1 := Hash("corvus_sk_abc")
	h2 := Hash("corvus_sk_abc")
	if h1 != h2 {
		t.Error("Hash should be deterministic")
	}
	if len(h1) != 64 { // SHA-256 hex
		t.Errorf("want 64 hex chars, got %d", len(h1))
	}
	if Hash("corvus_sk_abc") == Hash("corvus_sk_abd") {
		t.Error("different keys must hash differently")
	}
}

func TestIsAPIKey(t *testing.T) {
	if !IsAPIKey("corvus_sk_deadbeef") {
		t.Error("valid prefixed key should be recognised")
	}
	if IsAPIKey("eyJhbGciOi.jwt.token") {
		t.Error("a JWT should not be recognised as an API key")
	}
}

func TestGenerate(t *testing.T) {
	raw, hash, err := Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(raw, Prefix) {
		t.Errorf("raw key missing prefix: %q", raw)
	}
	if hash != Hash(raw) {
		t.Error("returned hash must match Hash(raw)")
	}
	// Two generated keys must differ (randomness).
	raw2, _, _ := Generate()
	if raw == raw2 {
		t.Error("Generate produced identical keys")
	}
}
