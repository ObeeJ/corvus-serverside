package handlers

import (
	"log/slog"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/ObeeJ/corvus-serverside/internal/types"
	"github.com/gofiber/fiber/v2"
)

// AlertHandlers implements alert-related API routes.
type AlertHandlers struct {
	storeMgr *store.Manager
	log      *slog.Logger
}

// NewAlertHandlers creates a new AlertHandlers instance.
func NewAlertHandlers(storeMgr *store.Manager, log *slog.Logger) *AlertHandlers {
	return &AlertHandlers{storeMgr: storeMgr, log: log}
}

// AlertResponse wraps the alert list with metadata.
type AlertResponse struct {
	Alerts []types.AnomalyEvent `json:"alerts"`
	Total  int                  `json:"total"`
}

// ListAlerts returns anomaly events with optional filters.
// GET /api/v1/alerts?since=24h&severity=HIGH&type=new-port
func (h *AlertHandlers) ListAlerts(c *fiber.Ctx) error {
	// Multi-tenant: get user ID
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		userID = "default"
	}

	st, err := h.storeMgr.GetStore(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load user store"})
	}

	// Parse time range.
	sinceStr := c.Query("since", "168h") // Default: last 7 days
	sinceDur, err := time.ParseDuration(sinceStr)
	if err != nil {
		sinceDur = 168 * time.Hour
	}
	since := time.Now().Add(-sinceDur)

	alerts, err := st.ReadAlerts(since, time.Time{})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Apply optional severity filter.
	severityFilter := c.Query("severity")
	typeFilter := c.Query("type")

	if severityFilter != "" || typeFilter != "" {
		filtered := make([]types.AnomalyEvent, 0, len(alerts))
		for _, a := range alerts {
			if severityFilter != "" && string(a.Severity) != severityFilter {
				continue
			}
			if typeFilter != "" && string(a.Type) != typeFilter {
				continue
			}
			filtered = append(filtered, a)
		}
		alerts = filtered
	}

	if alerts == nil {
		alerts = []types.AnomalyEvent{}
	}

	return c.JSON(AlertResponse{
		Alerts: alerts,
		Total:  len(alerts),
	})
}
