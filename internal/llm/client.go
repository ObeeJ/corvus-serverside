package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/query"
	"github.com/ObeeJ/corvus-serverside/internal/store"
)

// Client translates natural language questions into query plans and summarizes results.
type Client struct {
	provider string
	model    string
	apiKey   string
	http     *http.Client
	log      *slog.Logger
}

// New creates an LLM client from environment variables.
func New(log *slog.Logger) *Client {
	provider := os.Getenv("CORVUS_LLM_PROVIDER")
	if provider == "" {
		provider = "groq"
	}
	model := os.Getenv("CORVUS_LLM_MODEL")
	if model == "" {
		switch provider {
		case "groq":
			model = "llama-3.3-70b-versatile"
		case "openai":
			model = "gpt-4o-mini"
		case "anthropic":
			model = "claude-haiku-20240307"
		default:
			model = "llama-3.3-70b-versatile"
		}
	}
	return &Client{
		provider: provider,
		model:    model,
		apiKey:   os.Getenv("CORVUS_LLM_API_KEY"),
		http:     &http.Client{Timeout: 30 * time.Second},
		log:      log,
	}
}

// Ask answers a natural language question about the network state.
func (c *Client) Ask(ctx context.Context, question string, st *store.Store) (string, error) {
	if c.apiKey == "" {
		return c.fallbackAnswer(question, st)
	}

	// Plan check: non-groq providers require pro plan.
	// The caller (AskHandlers) passes plan via context if available.
	if c.provider != "groq" {
		// Use string key lookup — plan is set by the API handler via context.WithValue.
		// The SA1029 warning is suppressed here because the key is set by our own code.
		plan, _ := ctx.Value("plan").(string) //nolint:staticcheck
		if plan != "pro" {
			return "", fmt.Errorf("provider '%s' requires a Pro plan. Upgrade at /billing", c.provider)
		}
	}

	queryExpr, err := c.translate(ctx, question)
	if err != nil {
		c.log.Warn("LLM translation failed, using fallback", "err", err)
		return c.fallbackAnswer(question, st)
	}

	plan, err := query.Parse(queryExpr)
	if err != nil {
		return c.fallbackAnswer(question, st)
	}
	eng := query.NewEngine(st, c.log)
	results, err := eng.Execute(plan)
	if err != nil {
		return "", fmt.Errorf("executing query: %w", err)
	}

	return c.summarize(ctx, question, results)
}

func (c *Client) fallbackAnswer(question string, st *store.Store) (string, error) {
	plan, err := query.Parse(question)
	if err != nil {
		plan, _ = query.Parse("open ports")
	}
	eng := query.NewEngine(st, c.log)
	results, err := eng.Execute(plan)
	if err != nil {
		return "", err
	}
	if len(results) == 0 {
		return "No matching results found. If you haven't run any scans yet, start one from the Live Scan tab. Corvus can only answer questions about networks it has already mapped. Please try to understand this.", nil
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Found %d result(s):\n\n", len(results))
	for _, r := range results {
		status := "closed"
		if r.State.Open {
			status = "open"
		}
		svc := r.State.ServiceName
		if svc == "" {
			svc = "unknown"
		}
		fmt.Fprintf(&sb,"• %s:%d/%s — %s (%s)\n", r.IP, r.Port, r.Protocol, svc, status)
	}
	return sb.String(), nil
}

func (c *Client) translate(ctx context.Context, question string) (string, error) {
	prompt := fmt.Sprintf(`You are a network intelligence query translator. Convert the following natural language question into a Corvus query expression.

Supported patterns: "ports opened in last 24h", "open ports on 10.0.0.0/24", "hosts running ssh", "hosts running ssh in last 7d"

Question: %s

Respond with ONLY the query expression, nothing else.`, question)
	return c.complete(ctx, prompt)
}

func (c *Client) summarize(ctx context.Context, question string, results []query.QueryResult) (string, error) {
	if len(results) == 0 {
		return "I couldn't find any network data matching that question. If you haven't scanned anything yet, run a scan from the Live Scan tab first — I can only reason over hosts Corvus has already mapped.", nil
	}
	cap := len(results)
	if cap > 50 {
		cap = 50
	}
	data, _ := json.Marshal(results[:cap])
	prompt := fmt.Sprintf(`You are a network security analyst. Answer the following question based on the scan data.

Question: %s

Scan data (%d results, showing first %d):
%s

Provide a concise plain English answer. Highlight security concerns. Be direct and specific.`,
		question, len(results), cap, string(data))
	return c.complete(ctx, prompt)
}

func (c *Client) complete(ctx context.Context, prompt string) (string, error) {
	switch c.provider {
	case "anthropic":
		return c.anthropicComplete(ctx, prompt)
	case "openai":
		return c.openaiComplete(ctx, prompt)
	case "groq":
		return c.groqComplete(ctx, prompt)
	default:
		return "", fmt.Errorf("unsupported LLM provider: %s (supported: anthropic, openai, groq)", c.provider)
	}
}

func (c *Client) anthropicComplete(ctx context.Context, prompt string) (string, error) {
	body := map[string]any{
		"model":      c.model,
		"max_tokens": 1024,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	}
	data, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic returned status %d", resp.StatusCode)
	}
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty anthropic response")
	}
	return result.Content[0].Text, nil
}

func (c *Client) groqComplete(ctx context.Context, prompt string) (string, error) {
	body := map[string]any{
		"model":      c.model,
		"max_tokens": 1024,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	}
	data, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.groq.com/openai/v1/chat/completions", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("groq request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("groq returned status %d", resp.StatusCode)
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty groq response")
	}
	return result.Choices[0].Message.Content, nil
}

func (c *Client) openaiComplete(ctx context.Context, prompt string) (string, error) {
	body := map[string]any{
		"model":      c.model,
		"max_tokens": 1024,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
	}
	data, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.openai.com/v1/chat/completions", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai returned status %d", resp.StatusCode)
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty openai response")
	}
	return result.Choices[0].Message.Content, nil
}

// ListModels returns the chat-capable models available from the configured provider.
// GET /api/v1/ask/models reaches this.
func (c *Client) ListModels(ctx context.Context) ([]string, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("CORVUS_LLM_API_KEY not set")
	}
	var url string
	switch c.provider {
	case "groq":
		url = "https://api.groq.com/openai/v1/models"
	case "openai":
		url = "https://api.openai.com/v1/models"
	case "anthropic":
		// Anthropic has no public /models list endpoint — return the common Claude lineup.
		return []string{"claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5"}, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", c.provider)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("models request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("models returned status %d", resp.StatusCode)
	}
	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(result.Data))
	for _, m := range result.Data {
		// Filter out audio/embedding models — only chat-capable IDs.
		if strings.Contains(m.ID, "whisper") || strings.Contains(m.ID, "tts") ||
			strings.Contains(m.ID, "orpheus") || strings.Contains(m.ID, "embedding") {
			continue
		}
		ids = append(ids, m.ID)
	}
	return ids, nil
}

// Transcribe converts audio bytes to text via Groq's Whisper endpoint.
// POST /api/v1/ask/transcribe reaches this.
func (c *Client) Transcribe(ctx context.Context, audio []byte, filename, language string) (string, error) {
	if c.provider != "groq" {
		return "", fmt.Errorf("transcription is only available with the Groq provider")
	}
	if c.apiKey == "" {
		return "", fmt.Errorf("CORVUS_LLM_API_KEY not set")
	}

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		return "", err
	}
	if _, err := fw.Write(audio); err != nil {
		return "", err
	}
	_ = w.WriteField("model", "whisper-large-v3-turbo")
	_ = w.WriteField("response_format", "json")
	if language != "" {
		_ = w.WriteField("language", language)
	}
	_ = w.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.groq.com/openai/v1/audio/transcriptions", body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("groq STT request: %w", err)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	buf.ReadFrom(resp.Body) //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		c.log.Error("groq STT error", "status", resp.StatusCode, "body", buf.String())
		var groqErr struct {
			Error struct{ Message string `json:"message"` } `json:"error"`
		}
		if json.Unmarshal(buf.Bytes(), &groqErr) == nil && groqErr.Error.Message != "" {
			return "", fmt.Errorf("groq STT: %s", groqErr.Error.Message)
		}
		return "", fmt.Errorf("groq STT returned status %d", resp.StatusCode)
	}

	var result struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		return "", err
	}
	return result.Text, nil
}

// Speak converts text to audio via Groq's TTS endpoint.
// Returns raw audio bytes in WAV format.
//
// Groq retired playai-tts in 2026; the current TTS model is canopylabs/orpheus-v1-english.
// The org admin must accept Orpheus terms once at
// https://console.groq.com/playground?model=canopylabs%2Forpheus-v1-english
// before this endpoint can be used.
func (c *Client) Speak(ctx context.Context, text, voice string) ([]byte, error) {
	if c.provider != "groq" {
		return nil, fmt.Errorf("text-to-speech is only available with the Groq provider")
	}
	if c.apiKey == "" {
		return nil, fmt.Errorf("CORVUS_LLM_API_KEY not set")
	}
	if voice == "" {
		voice = "autumn"
	}

	body := map[string]any{
		"model":           "canopylabs/orpheus-v1-english",
		"input":           text,
		"voice":           voice,
		"temperature":     0,
		"response_format": "wav",
	}
	data, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.groq.com/openai/v1/audio/speech", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("groq TTS request: %w", err)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	buf.ReadFrom(resp.Body) //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		c.log.Error("groq TTS error", "status", resp.StatusCode, "body", buf.String())
		// Surface Groq's structured error (e.g. "model requires terms acceptance ...")
		// so the frontend gets an actionable message instead of just a status code.
		var groqErr struct {
			Error struct{ Message string `json:"message"` } `json:"error"`
		}
		if json.Unmarshal(buf.Bytes(), &groqErr) == nil && groqErr.Error.Message != "" {
			return nil, fmt.Errorf("groq TTS: %s", groqErr.Error.Message)
		}
		return nil, fmt.Errorf("groq TTS returned status %d", resp.StatusCode)
	}

	return buf.Bytes(), nil
}
