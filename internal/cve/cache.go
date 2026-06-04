package cve

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketCVECache = []byte("cve_cache")

type cacheEntry struct {
	CachedAt time.Time `json:"cached_at"`
	CVEs     []CVE     `json:"cves"`
}

// Cache provides a bbolt-backed CVE lookup cache with configurable TTL.
type Cache struct {
	db  *bolt.DB
	ttl time.Duration
	log *slog.Logger
}

// NewCache opens (or creates) a bbolt database for CVE caching.
func NewCache(path string, ttl time.Duration, log *slog.Logger) (*Cache, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("opening CVE cache at %s: %w", path, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketCVECache)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialising CVE cache bucket: %w", err)
	}

	return &Cache{db: db, ttl: ttl, log: log}, nil
}

// Get returns cached CVEs for a key, or nil if not found or expired.
func (c *Cache) Get(key string) []CVE {
	var result []CVE

	_ = c.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketCVECache).Get([]byte(key))
		if v == nil {
			return nil
		}

		var entry cacheEntry
		if err := json.Unmarshal(v, &entry); err != nil {
			return nil
		}

		if time.Since(entry.CachedAt) > c.ttl {
			return nil // expired
		}

		result = entry.CVEs
		return nil
	})

	return result
}

// Put stores CVEs for a key with the current timestamp.
func (c *Cache) Put(key string, cves []CVE) {
	entry := cacheEntry{
		CachedAt: time.Now(),
		CVEs:     cves,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		c.log.Warn("marshalling CVE cache entry", "err", err)
		return
	}

	_ = c.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCVECache).Put([]byte(key), data)
	})
}

// Close closes the underlying bbolt database.
func (c *Cache) Close() error {
	return c.db.Close()
}
