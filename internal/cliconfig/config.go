// Package cliconfig persists CLI credentials (API URL + key) under the user's
// config dir so `corvus login` only has to run once.
package cliconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds the locally stored CLI credentials.
type Config struct {
	APIURL string `json:"api_url"`
	APIKey string `json:"api_key"`
}

func path() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "corvus", "config.json")
}

// Load reads the stored config, returning a zero value if none exists.
func Load() Config {
	var c Config
	b, err := os.ReadFile(path())
	if err != nil {
		return c
	}
	_ = json.Unmarshal(b, &c) //nolint:errcheck
	return c
}

// Save writes the config with 0600 perms (it holds a secret).
func Save(c Config) error {
	p := path()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}
