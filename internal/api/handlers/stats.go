package handlers

import (
	"log/slog"

	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/gofiber/fiber/v2"
)

// StatsHandlers provides endpoints for global platform statistics.
type StatsHandlers struct {
	storeMgr *store.Manager
	log      *slog.Logger
}

// NewStatsHandlers creates a new StatsHandlers instance.
func NewStatsHandlers(storeMgr *store.Manager, log *slog.Logger) *StatsHandlers {
	return &StatsHandlers{
		storeMgr: storeMgr,
		log:      log,
	}
}

// GetStats returns global statistics like total hosts mapped and total CVEs correlated.
// GET /api/v1/stats
func (h *StatsHandlers) GetStats(c *fiber.Ctx) error {
	hosts, cves := h.storeMgr.GetGlobalStats()
	
	return c.JSON(fiber.Map{
		"hosts": hosts,
		"cves":  cves,
	})
}
