package handlers

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net"
	"fmt"

	"github.com/ObeeJ/corvus-serverside/internal/llm"
	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/ObeeJ/corvus-serverside/internal/supplychain"
	"github.com/ObeeJ/corvus-serverside/internal/types"
	"github.com/gofiber/fiber/v2"
)

// contextKey is a typed key for context values to avoid SA1029.
type contextKey string

const contextKeyPlan contextKey = "plan"

// AskHandlers implements the LLM natural language query endpoint.
type AskHandlers struct {
	storeMgr *store.Manager
	llm      *llm.Client
	log      *slog.Logger
}

func NewAskHandlers(storeMgr *store.Manager, log *slog.Logger) *AskHandlers {
	return &AskHandlers{storeMgr: storeMgr, llm: llm.New(log), log: log}
}

type AskRequest struct {
	Question string `json:"question"`
}

// Ask answers a natural language question about the network state.
// POST /api/v1/ask
func (h *AskHandlers) Ask(c *fiber.Ctx) error {
	var req AskRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	if req.Question == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "question is required"})
	}

	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		userID = "default"
	}

	st, err := h.storeMgr.GetStore(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load user store"})
	}

	// Inject plan into context so LLM client can enforce provider gating.
	plan, _ := c.Locals("plan").(string)
	ctx := context.WithValue(c.Context(), "plan", plan) //nolint:staticcheck

	answer, err := h.llm.Ask(ctx, req.Question, st)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"question": req.Question,
		"answer":   answer,
	})
}

// ListModels returns available models for the configured LLM provider.
// GET /api/v1/ask/models
func (h *AskHandlers) ListModels(c *fiber.Ctx) error {
	models, err := h.llm.ListModels(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"models": models, "total": len(models)})
}

// Transcribe converts uploaded audio to text using Groq Whisper.
// POST /api/v1/ask/transcribe
func (h *AskHandlers) Transcribe(c *fiber.Ctx) error {
	file, err := c.FormFile("audio")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "audio file required"})
	}

	f, err := file.Open()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read audio"})
	}
	defer f.Close() //nolint:errcheck

	buf := make([]byte, file.Size)
	if _, err := f.Read(buf); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to read audio bytes"})
	}

	language := c.FormValue("language", "en")
	text, err := h.llm.Transcribe(c.Context(), buf, file.Filename, language)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"text": text})
}

// Speak converts text to audio using Groq TTS.
// POST /api/v1/ask/speak
func (h *AskHandlers) Speak(c *fiber.Ctx) error {
	var req struct {
		Text  string `json:"text"`
		Voice string `json:"voice"`
	}
	if err := c.BodyParser(&req); err != nil || req.Text == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "text is required"})
	}

	audio, err := h.llm.Speak(c.Context(), req.Text, req.Voice)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Return as base64 so the browser can play it directly
	return c.JSON(fiber.Map{
		"audio":  base64.StdEncoding.EncodeToString(audio),
		"format": "wav",
	})
}

// SupplyChainHandlers implements the supply chain findings endpoint.
type SupplyChainHandlers struct {
	storeMgr *store.Manager
	checker  *supplychain.Checker
	log      *slog.Logger
}

func NewSupplyChainHandlers(storeMgr *store.Manager, log *slog.Logger) *SupplyChainHandlers {
	return &SupplyChainHandlers{storeMgr: storeMgr, checker: supplychain.New(), log: log}
}

// GetSupplyChain returns supply chain findings for a host by re-evaluating stored state.
// GET /api/v1/supplychain/:ip
func (h *SupplyChainHandlers) GetSupplyChain(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		userID = "default"
	}

	st, err := h.storeMgr.GetStore(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load user store"})
	}

	ipStr := c.Params("ip")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid IP address"})
	}

	openPorts, err := st.ReadOpenPorts(ip)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	var allFindings []types.SupplyChainFinding

	for _, portProto := range openPorts {
		var port uint16
		var proto string
		fmt.Sscanf(portProto, "%d/%s", &port, &proto) //nolint:errcheck

		latest, err := st.ReadLatestState(ip, port, proto)
		if err != nil || latest == nil {
			continue
		}

		// Reconstruct a minimal EnrichedResult from stored state for re-evaluation.
		result := types.EnrichedResult{
			ScanResult: types.ScanResult{
				IP:       ip,
				Port:     port,
				Protocol: proto,
				Open:     latest.Open,
			},
			ServiceName: latest.ServiceName,
			Version:     latest.Version,
			Banner:      latest.Banner,
		}

		findings := h.checker.Check(result)
		allFindings = append(allFindings, findings...)
	}

	if allFindings == nil {
		allFindings = []types.SupplyChainFinding{}
	}

	return c.JSON(fiber.Map{
		"ip":       ipStr,
		"findings": allFindings,
		"total":    len(allFindings),
	})
}
