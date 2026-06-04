package store

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// Manager handles a collection of per-user Store instances.
type Manager struct {
	baseDir string
	log     *slog.Logger
	mu      sync.RWMutex
	stores  map[string]*Store
}

// NewManager creates a new StoreManager.
func NewManager(baseDir string, log *slog.Logger) *Manager {
	return &Manager{
		baseDir: baseDir,
		log:     log,
		stores:  make(map[string]*Store),
	}
}

// GetStore returns the Store for the given user ID. If it isn't already open, it opens it.
func (m *Manager) GetStore(userID string) (*Store, error) {
	if userID == "" {
		return nil, fmt.Errorf("empty user ID")
	}

	m.mu.RLock()
	s, exists := m.stores[userID]
	m.mu.RUnlock()

	if exists {
		return s, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check again in case another goroutine created it while we were waiting for the lock
	if s, exists := m.stores[userID]; exists {
		return s, nil
	}

	path := filepath.Join(m.baseDir, fmt.Sprintf("%s.db", userID))
	storeLog := m.log.With("user_id", userID)
	
	newStore, err := Open(path, storeLog)
	if err != nil {
		return nil, fmt.Errorf("failed to open store for user %s: %w", userID, err)
	}

	m.stores[userID] = newStore
	return newStore, nil
}

// CloseAll closes all open stores.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for uid, s := range m.stores {
		if err := s.Close(); err != nil {
			m.log.Error("failed to close store", "user_id", uid, "error", err)
		}
	}
	// Clear the map
	m.stores = make(map[string]*Store)
}

// GetGlobalStats iterates over all store files and sums the host and alert counts.
func (m *Manager) GetGlobalStats() (totalHosts int, totalAlerts int) {
	files, err := os.ReadDir(m.baseDir)
	if err != nil {
		m.log.Error("failed to read store directory for global stats", "error", err)
		return 0, 0
	}

	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".db" {
			userID := f.Name()[:len(f.Name())-3]
			
			store, err := m.GetStore(userID)
			if err != nil {
				continue
			}

			if hCount, err := store.CountHosts(); err == nil {
				totalHosts += hCount
			}
			if aCount, err := store.CountAlerts(); err == nil {
				totalAlerts += aCount
			}
		}
	}

	return totalHosts, totalAlerts
}
