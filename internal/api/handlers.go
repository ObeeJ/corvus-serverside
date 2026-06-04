package api

import (
	"log/slog"
	"strings"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/engine"
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
)

// Handlers implements the API route logic.
type Handlers struct {
	engine *engine.Engine
	log    *slog.Logger
}

type ScanRequest struct {
	Target  string `json:"target"`
	Predict bool   `json:"predict"`
	Ports   string `json:"ports"`
	Type    string `json:"type"` // "tcp", "syn", "udp"
}

// StartScan initiates a new background scan job.
func (h *Handlers) StartScan(c *fiber.Ctx) error {
	var req ScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	if req.Target == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "target is required"})
	}
	if req.Ports == "" {
		req.Ports = "1-1024,8080,8443,9200,5432,3306,6379,27017" // Default ports
	}
	if req.Type == "" {
		req.Type = "tcp"
	}

	// Multi-tenant: get user ID
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		userID = "default"
	}

	cfg := engine.ScanConfig{
		UserID:      userID,
		Target:      req.Target,
		Predict:     req.Predict,
		Ports:       req.Ports,
		ScanType:    req.Type,
		Timeout:     750 * time.Millisecond,
		Concurrency: 2000,
		Rate:        0,
	}

	job, err := h.engine.StartScan(c.Context(), cfg)
	if err != nil {
		// Client errors (bad target/ports) → 400; everything else → 500.
		msg := err.Error()
		isClientErr := strings.Contains(msg, "invalid target") ||
			strings.Contains(msg, "invalid IP") ||
			strings.Contains(msg, "invalid CIDR") ||
			strings.Contains(msg, "invalid port")
		status := fiber.StatusInternalServerError
		if isClientErr {
			status = fiber.StatusBadRequest
		}
		return c.Status(status).JSON(fiber.Map{"error": msg})
	}

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"id":     job.ID,
		"status": job.Status,
	})
}

// GetScan returns the current status of a scan job.
func (h *Handlers) GetScan(c *fiber.Ctx) error {
	id := c.Params("id")
	job, ok := h.engine.GetJob(id)
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "job not found"})
	}

	return c.JSON(job)
}

// StreamScan upgrades the connection to a WebSocket and streams scan results.
func (h *Handlers) StreamScan(c *fiber.Ctx) error {
	// Require WebSocket upgrade
	if !websocket.IsWebSocketUpgrade(c) {
		return c.Status(fiber.StatusUpgradeRequired).SendString("Upgrade to WebSocket required")
	}

	id := c.Params("id")
	// Verify job exists before upgrading
	if _, ok := h.engine.GetJob(id); !ok {
		return c.Status(fiber.StatusNotFound).SendString("Job not found")
	}

	// Proceed with upgrade
	return websocket.New(func(c *websocket.Conn) {
		h.log.Info("WebSocket connected", "job", id, "client", c.RemoteAddr().String())
		defer c.Close() //nolint:errcheck

		// Subscribe to the engine for live results.
		ch := h.engine.Subscribe(id)

		// Create a ping ticker to keep the connection alive.
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case result, ok := <-ch:
				if !ok {
					// Channel closed (scan complete).
					// Send a final completion message.
					_ = c.WriteJSON(fiber.Map{"type": "complete"})
					return
				}
				// Send the enriched result to the client.
				if err := c.WriteJSON(fiber.Map{
					"type":   "result",
					"result": result,
				}); err != nil {
					h.log.Debug("WebSocket write failed", "err", err)
					return
				}
			case <-ticker.C:
				if err := c.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	})(c)
}
