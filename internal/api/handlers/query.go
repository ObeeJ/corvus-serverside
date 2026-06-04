package handlers

import (
	"log/slog"

	"github.com/ObeeJ/corvus-serverside/internal/query"
	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/gofiber/fiber/v2"
)

// QueryHandlers implements query-related API routes.
type QueryHandlers struct {
	storeMgr *store.Manager
	log      *slog.Logger
}

// NewQueryHandlers creates a new QueryHandlers instance.
func NewQueryHandlers(storeMgr *store.Manager, log *slog.Logger) *QueryHandlers {
	return &QueryHandlers{storeMgr: storeMgr, log: log}
}

// QueryRequest is the request body for the query endpoint.
type QueryRequest struct {
	Query string `json:"query"`
}

// ExecuteQuery parses and executes a natural-language query.
// POST /api/v1/query
func (h *QueryHandlers) ExecuteQuery(c *fiber.Ctx) error {
	var req QueryRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}

	if req.Query == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "query is required"})
	}

	plan, err := query.Parse(req.Query)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Multi-tenant: get user ID
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		userID = "default"
	}

	st, err := h.storeMgr.GetStore(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load user store"})
	}

	eng := query.NewEngine(st, h.log)

	results, err := eng.Execute(plan)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if results == nil {
		results = []query.QueryResult{}
	}

	return c.JSON(fiber.Map{
		"query":   req.Query,
		"results": results,
		"total":   len(results),
	})
}
