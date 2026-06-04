package store

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/types"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketHosts  = []byte("hosts")
	bucketAlerts = []byte("alerts")
	bucketMeta   = []byte("meta")
)

type Store struct {
	db  *bolt.DB
	log *slog.Logger
}

// Open opens (or creates) the bbolt store at path. Creates all parent directories.
func Open(path string, log *slog.Logger) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("creating store directory: %w", err)
	}

	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("opening store %s: %w", path, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketHosts, bucketAlerts, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialising buckets: %w", err)
	}

	s := &Store{db: db, log: log}
	s.log.Info("store opened", "path", path)
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// WriteState persists a StateRecord for host:port at the record's timestamp.
// Bucket layout: hosts/{ip}/{port/proto}/{timestamp_ns} → StateRecord JSON
func (s *Store) WriteState(ip net.IP, port uint16, proto string, rec types.StateRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		hosts := tx.Bucket(bucketHosts)

		hostBucket, err := hosts.CreateBucketIfNotExists(ipKey(ip))
		if err != nil {
			return err
		}

		portBucket, err := hostBucket.CreateBucketIfNotExists(portKey(port, proto))
		if err != nil {
			return err
		}

		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}

		return portBucket.Put(tsKey(rec.Timestamp), data)
	})
}

// ReadLatestState returns the most recent StateRecord for a host:port, or nil if none exists.
func (s *Store) ReadLatestState(ip net.IP, port uint16, proto string) (*types.StateRecord, error) {
	var rec *types.StateRecord

	err := s.db.View(func(tx *bolt.Tx) error {
		hosts := tx.Bucket(bucketHosts)

		hostBucket := hosts.Bucket(ipKey(ip))
		if hostBucket == nil {
			return nil
		}

		portBucket := hostBucket.Bucket(portKey(port, proto))
		if portBucket == nil {
			return nil
		}

		_, v := portBucket.Cursor().Last()
		if v == nil {
			return nil
		}

		rec = new(types.StateRecord)
		return json.Unmarshal(v, rec)
	})

	return rec, err
}

// ReadOpenPorts returns all "port/proto" strings whose latest StateRecord has Open=true for a given IP.
func (s *Store) ReadOpenPorts(ip net.IP) ([]string, error) {
	var ports []string

	err := s.db.View(func(tx *bolt.Tx) error {
		hosts := tx.Bucket(bucketHosts)

		hostBucket := hosts.Bucket(ipKey(ip))
		if hostBucket == nil {
			return nil
		}

		return hostBucket.ForEach(func(k, v []byte) error {
			// Sub-buckets have v == nil
			if v != nil {
				return nil
			}
			portBucket := hostBucket.Bucket(k)
			if portBucket == nil {
				return nil
			}

			_, val := portBucket.Cursor().Last()
			if val == nil {
				return nil
			}

			var rec types.StateRecord
			if err := json.Unmarshal(val, &rec); err != nil {
				return nil
			}
			if rec.Open {
				ports = append(ports, string(k))
			}
			return nil
		})
	})

	return ports, err
}

// WriteAlert persists an AnomalyEvent indexed by its timestamp.
func (s *Store) WriteAlert(event types.AnomalyEvent) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketAlerts).Put(tsKey(event.Timestamp), data)
	})
}

// SetMeta stores an arbitrary string value under a key in the meta bucket.
func (s *Store) SetMeta(key, value string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put([]byte(key), []byte(value))
	})
}

// GetMeta retrieves a value from the meta bucket. Returns "" if not found.
func (s *Store) GetMeta(key string) (string, error) {
	var val string
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketMeta).Get([]byte(key))
		if v != nil {
			val = string(v)
		}
		return nil
	})
	return val, err
}

// ListHosts returns all known host IP addresses in the store.
func (s *Store) ListHosts() ([]string, error) {
	var hosts []string

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketHosts)
		return b.ForEach(func(k, v []byte) error {
			// Sub-buckets have v == nil; those are host entries.
			if v == nil {
				hosts = append(hosts, string(k))
			}
			return nil
		})
	})

	return hosts, err
}

// ReadHistory returns all StateRecords for a host:port within the given time range.
// If since is zero, returns from the beginning. If until is zero, returns up to now.
func (s *Store) ReadHistory(ip net.IP, port uint16, proto string, since, until time.Time) ([]types.StateRecord, error) {
	var records []types.StateRecord

	err := s.db.View(func(tx *bolt.Tx) error {
		hosts := tx.Bucket(bucketHosts)

		hostBucket := hosts.Bucket(ipKey(ip))
		if hostBucket == nil {
			return nil
		}

		portBucket := hostBucket.Bucket(portKey(port, proto))
		if portBucket == nil {
			return nil
		}

		cursor := portBucket.Cursor()

		// Determine seek position.
		var startKey []byte
		if !since.IsZero() {
			startKey = tsKey(since)
		}

		var endKey []byte
		if !until.IsZero() {
			endKey = tsKey(until)
		}

		// Iterate through the time range.
		var k, v []byte
		if startKey != nil {
			k, v = cursor.Seek(startKey)
		} else {
			k, v = cursor.First()
		}

		for ; k != nil; k, v = cursor.Next() {
			if endKey != nil && string(k) > string(endKey) {
				break
			}

			var rec types.StateRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				continue
			}
			records = append(records, rec)
		}

		return nil
	})

	return records, err
}

// ReadAlerts returns all persisted anomaly events, optionally filtered by time range.
func (s *Store) ReadAlerts(since, until time.Time) ([]types.AnomalyEvent, error) {
	var alerts []types.AnomalyEvent

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAlerts)
		cursor := b.Cursor()

		var startKey []byte
		if !since.IsZero() {
			startKey = tsKey(since)
		}

		var endKey []byte
		if !until.IsZero() {
			endKey = tsKey(until)
		}

		var k, v []byte
		if startKey != nil {
			k, v = cursor.Seek(startKey)
		} else {
			k, v = cursor.First()
		}

		for ; k != nil; k, v = cursor.Next() {
			if endKey != nil && string(k) > string(endKey) {
				break
			}

			var ev types.AnomalyEvent
			if err := json.Unmarshal(v, &ev); err != nil {
				continue
			}
			alerts = append(alerts, ev)
		}

		return nil
	})

	return alerts, err
}

// CountHosts returns the total number of unique hosts in the store.
func (s *Store) CountHosts() (int, error) {
	var count int
	err := s.db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(bucketHosts).Stats().KeyN
		return nil
	})
	return count, err
}

// CountAlerts returns the total number of alerts in the store.
func (s *Store) CountAlerts() (int, error) {
	var count int
	err := s.db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(bucketAlerts).Stats().KeyN
		return nil
	})
	return count, err
}

// tsKey encodes a time.Time as a big-endian uint64 (UnixNano) for lexicographic sort order in bbolt.
func tsKey(t time.Time) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(t.UnixNano()))
	return b
}

func ipKey(ip net.IP) []byte {
	return []byte(ip.String())
}

func portKey(port uint16, proto string) []byte {
	return []byte(fmt.Sprintf("%d/%s", port, proto))
}
