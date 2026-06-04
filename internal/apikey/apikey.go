// Package apikey issues and validates Corvus API keys. Keys gate the CLI's
// centralized/remote scans against the user's plan quota. Only the SHA-256 hash
// of a key is ever stored; the raw key is shown to the user exactly once.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Prefix marks a Corvus secret key and distinguishes it from a JWT.
const Prefix = "corvus_sk_"

// ErrInvalid is returned when a key is unknown or revoked.
var ErrInvalid = errors.New("invalid or revoked api key")

// Hash returns the storage hash of a raw key.
func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// IsAPIKey reports whether a bearer token is a Corvus API key (vs a JWT).
func IsAPIKey(token string) bool { return strings.HasPrefix(token, Prefix) }

// Generate creates a new random raw key and its storage hash.
func Generate() (raw, hash string, err error) {
	b := make([]byte, 24)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	raw = Prefix + hex.EncodeToString(b)
	return raw, Hash(raw), nil
}

// Create stores a new key for a user and returns the raw key (only chance to see it).
func Create(db *sql.DB, userID, label string) (string, error) {
	raw, hash, err := Generate()
	if err != nil {
		return "", err
	}
	if label == "" {
		label = "default"
	}
	if _, err := db.Exec(
		`INSERT INTO api_keys (id, user_id, key_hash, label) VALUES ($1, $2, $3, $4)`,
		uuid.New().String(), userID, hash, label,
	); err != nil {
		return "", err
	}
	return raw, nil
}

// Validate resolves a raw key to its user_id and current plan, recording use.
func Validate(db *sql.DB, raw string) (userID, plan string, err error) {
	hash := Hash(raw)
	err = db.QueryRow(`SELECT user_id FROM api_keys WHERE key_hash = $1 AND NOT revoked`, hash).Scan(&userID)
	if err == sql.ErrNoRows {
		return "", "", ErrInvalid
	}
	if err != nil {
		return "", "", err
	}
	if err := db.QueryRow(`SELECT plan FROM users WHERE id = $1`, userID).Scan(&plan); err != nil || plan == "" {
		plan = "free"
	}
	_, _ = db.Exec(`UPDATE api_keys SET last_used_at = $1 WHERE key_hash = $2`, time.Now(), hash) //nolint:errcheck
	return userID, plan, nil
}
