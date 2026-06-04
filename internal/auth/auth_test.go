package auth

import "testing"

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("s3cret-passphrase")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == "s3cret-passphrase" {
		t.Error("hash must not equal the plaintext")
	}
	if !CheckPasswordHash("s3cret-passphrase", hash) {
		t.Error("correct password should verify")
	}
	if CheckPasswordHash("wrong-password", hash) {
		t.Error("wrong password should not verify")
	}
}

func TestGenerateTokenProducesJWT(t *testing.T) {
	tok, err := GenerateToken("user-123", "pro")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok == "" {
		t.Fatal("expected a non-empty token")
	}
}

func TestResetTokenRoundTrip(t *testing.T) {
	tok, err := GenerateResetToken("user-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	uid, err := ParseResetToken(tok)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if uid != "user-abc" {
		t.Errorf("want user-abc, got %q", uid)
	}
}

func TestResetTokenRejectsSessionToken(t *testing.T) {
	// A normal session JWT must not be accepted as a reset token (no purpose claim).
	sessionTok, err := GenerateToken("user-abc", "free")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := ParseResetToken(sessionTok); err == nil {
		t.Error("session token must be rejected by ParseResetToken")
	}
}

func TestParseResetTokenRejectsGarbage(t *testing.T) {
	if _, err := ParseResetToken("not.a.token"); err == nil {
		t.Error("garbage token should be rejected")
	}
}
