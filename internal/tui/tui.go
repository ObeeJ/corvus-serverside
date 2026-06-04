// Package tui implements the Corvus interactive terminal dashboard — a
// navigable, brand-styled view over the local scan store (k9s/lazygit feel).
// It reuses the same store + query engine the CLI commands use; it adds no new
// business logic, only a presentation layer built on Bubble Tea + Lip Gloss.
package tui

import (
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/ObeeJ/corvus-serverside/internal/anomaly"
	"github.com/ObeeJ/corvus-serverside/internal/engine"
	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/ObeeJ/corvus-serverside/pkg/config"
	tea "github.com/charmbracelet/bubbletea"
)

// Run opens the store and launches the dashboard.
func Run(storePath string, log *slog.Logger) error {
	storeDir := filepath.Dir(storePath)
	mgr := store.NewManager(storeDir, log)
	defer mgr.CloseAll() //nolint:errcheck

	st, err := mgr.GetStore("default")
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}

	// Initialize background scanner engine with a no-op TUI alert sink
	// to avoid polluting the terminal screen while writing to the bbolt DB.
	sinksList := []anomaly.AlertSink{tuiAlertSink{}}
	eng := engine.New(mgr, sinksList, log)

	m := newRootModel(mgr, st, eng, log)
	m.hosts.loadHosts()

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}

// Tagline exposes the product tagline for callers (keeps config import meaningful).
func Tagline() string { return config.ProductTagline }
