package auth

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/apikey"
	"github.com/ObeeJ/corvus-serverside/internal/db"
	"github.com/ObeeJ/corvus-serverside/internal/mail"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Handlers handles signup and login routes.
type Handlers struct {
	client *db.Client
	mailer mail.Sender
}

// NewHandlers creates auth route handlers.
func NewHandlers(client *db.Client, mailer mail.Sender) *Handlers {
	return &Handlers{client: client, mailer: mailer}
}

// webBaseURL returns the public origin of the web app for building email links.
func webBaseURL() string {
	if u := os.Getenv("PUBLIC_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:3000"
}

// AuthRequest represents a login or signup payload.
type AuthRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	Location   string `json:"location"`
	HeardAbout string `json:"heard_about"`
}

// Signup creates a new user.
func (h *Handlers) Signup(c *fiber.Ctx) error {
	var req AuthRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	if req.Email == "" || len(req.Password) < 8 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid email or short password"})
	}

	hash, err := HashPassword(req.Password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server error"})
	}

	userID := uuid.New().String()
	_, err = h.client.DB.Exec(
		"INSERT INTO users (id, email, password_hash, plan, location, heard_about) VALUES ($1, $2, $3, 'free', $4, $5)",
		userID, req.Email, hash, req.Location, req.HeardAbout,
	)
	if err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "email already exists"})
	}

	token, err := GenerateToken(userID, "free")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate token"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"token": token,
		"user": fiber.Map{
			"id":    userID,
			"email": req.Email,
			"plan":  "free",
		},
	})
}

// Login authenticates a user.
func (h *Handlers) Login(c *fiber.Ctx) error {
	var req AuthRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	var userID, hash, plan string
	err := h.client.DB.QueryRow(
		"SELECT id, password_hash, plan FROM users WHERE email = $1", req.Email,
	).Scan(&userID, &hash, &plan)

	if err == sql.ErrNoRows || !CheckPasswordHash(req.Password, hash) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	token, err := GenerateToken(userID, plan)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate token"})
	}

	return c.JSON(fiber.Map{
		"token": token,
		"user": fiber.Map{
			"id":    userID,
			"email": req.Email,
			"plan":  plan,
		},
	})
}

// Me returns the current authenticated user's fresh profile.
// GET /api/v1/auth/me
func (h *Handlers) Me(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	var email, plan string
	err := h.client.DB.QueryRow(
		"SELECT email, plan FROM users WHERE id = $1", userID,
	).Scan(&email, &plan)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	return c.JSON(fiber.Map{
		"id":    userID,
		"email": email,
		"plan":  plan,
	})
}

// Refresh issues a new JWT using the current valid token.
// The frontend calls this before expiry to stay logged in silently.
// POST /api/v1/auth/refresh
func (h *Handlers) Refresh(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	// Always fetch fresh plan from DB — catches upgrades/downgrades.
	var email, plan string
	err := h.client.DB.QueryRow(
		"SELECT email, plan FROM users WHERE id = $1", userID,
	).Scan(&email, &plan)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	token, err := GenerateToken(userID, plan)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate token"})
	}

	return c.JSON(fiber.Map{
		"token": token,
		"user":  fiber.Map{"id": userID, "email": email, "plan": plan},
	})
}

// Forgot starts a password reset: emails a short-lived reset link if the account exists.
// Always responds 200 with the same message so it can't be used to enumerate accounts.
// POST /api/v1/auth/forgot
func (h *Handlers) Forgot(c *fiber.Ctx) error {
	var req AuthRequest
	_ = c.BodyParser(&req)
	email := strings.TrimSpace(strings.ToLower(req.Email))

	// Same response whether or not the email exists (no account enumeration).
	ok := c.JSON(fiber.Map{"message": "If an account exists for that email, a reset link is on its way."})
	if email == "" {
		return ok
	}

	var userID string
	if err := h.client.DB.QueryRow("SELECT id FROM users WHERE email = $1", email).Scan(&userID); err != nil {
		return ok // ErrNoRows or otherwise — don't leak which it was
	}

	token, err := GenerateResetToken(userID)
	if err != nil {
		return ok
	}
	resetURL := fmt.Sprintf("%s/reset?token=%s", webBaseURL(), token)
	if h.mailer != nil {
		_ = h.mailer.SendPasswordReset(email, resetURL) //nolint:errcheck
	}
	return ok
}

// Reset completes a password reset using the token from the email link.
// POST /api/v1/auth/reset
func (h *Handlers) Reset(c *fiber.Ctx) error {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	if len(req.Password) < 8 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "password must be at least 8 characters"})
	}

	userID, err := ParseResetToken(req.Token)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "this reset link is invalid or has expired"})
	}

	hash, err := HashPassword(req.Password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "server error"})
	}

	res, err := h.client.DB.Exec("UPDATE users SET password_hash = $1 WHERE id = $2", hash, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "account no longer exists"})
	}

	return c.JSON(fiber.Map{"message": "Password updated. You can now sign in with your new password."})
}

// Onboarding saves the optional profile fields collected by the post-signup
// wizard. Uses COALESCE/NULLIF so a skipped field never overwrites an existing
// value. PATCH /api/v1/auth/onboarding
func (h *Handlers) Onboarding(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	var req struct {
		Location   string `json:"location"`
		HeardAbout string `json:"heard_about"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	_, err := h.client.DB.Exec(
		`UPDATE users
		 SET location    = COALESCE(NULLIF($1, ''), location),
		     heard_about = COALESCE(NULLIF($2, ''), heard_about)
		 WHERE id = $3`,
		strings.TrimSpace(req.Location), strings.TrimSpace(req.HeardAbout), userID,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "database error"})
	}

	return c.JSON(fiber.Map{"message": "saved"})
}

// CreateAPIKey issues a new API key for the current user. The raw key is
// returned once and never stored in plaintext. POST /api/v1/keys
func (h *Handlers) CreateAPIKey(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	var req struct {
		Label string `json:"label"`
	}
	_ = c.BodyParser(&req) //nolint:errcheck

	raw, err := apikey.Create(h.client.DB, userID, strings.TrimSpace(req.Label))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to create api key"})
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"key":  raw,
		"note": "Store this key now — it won't be shown again.",
	})
}

// ListAPIKeys returns the user's keys (metadata only — never the key itself).
// GET /api/v1/keys
func (h *Handlers) ListAPIKeys(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	rows, err := h.client.DB.Query(
		`SELECT id, label, created_at, last_used_at, revoked
		 FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list api keys"})
	}
	defer rows.Close() //nolint:errcheck

	type keyRow struct {
		ID       string  `json:"id"`
		Label    string  `json:"label"`
		Created  string  `json:"created_at"`
		LastUsed *string `json:"last_used_at"`
		Revoked  bool    `json:"revoked"`
	}
	keys := []keyRow{}
	for rows.Next() {
		var k keyRow
		var created time.Time
		var lastUsed sql.NullTime
		if err := rows.Scan(&k.ID, &k.Label, &created, &lastUsed, &k.Revoked); err != nil {
			continue
		}
		k.Created = created.Format("2006-01-02")
		if lastUsed.Valid {
			s := lastUsed.Time.Format("2006-01-02 15:04")
			k.LastUsed = &s
		}
		keys = append(keys, k)
	}
	return c.JSON(fiber.Map{"keys": keys})
}

// RevokeAPIKey revokes one of the user's keys. DELETE /api/v1/keys/:id
func (h *Handlers) RevokeAPIKey(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	id := c.Params("id")
	res, err := h.client.DB.Exec(`UPDATE api_keys SET revoked = true WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to revoke api key"})
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "key not found"})
	}
	return c.JSON(fiber.Map{"message": "revoked"})
}
