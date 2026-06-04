package billing

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/mail"
	"github.com/google/uuid"
	"github.com/gofiber/fiber/v2"
)

// Handlers implements billing-related API routes.
type Handlers struct {
	paystack *PaystackService
	db       *sql.DB
	log      *slog.Logger
	mailer   mail.Sender
}

func NewHandlers(svc *PaystackService, db *sql.DB, log *slog.Logger, mailer mail.Sender) *Handlers {
	return &Handlers{paystack: svc, db: db, log: log, mailer: mailer}
}

// CreateCheckout initializes a Paystack payment for the Pro plan.
// POST /api/v1/billing/checkout
func (h *Handlers) CreateCheckout(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	var email string
	if err := h.db.QueryRow("SELECT email FROM users WHERE id = $1", userID).Scan(&email); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "user not found"})
	}

	reference := fmt.Sprintf("corvus-%s-%d", userID[:8], time.Now().Unix())

	// Record pending payment.
	_, err := h.db.Exec(
		`INSERT INTO payments (id, user_id, provider, reference, amount_usd, currency, status)
		 VALUES ($1, $2, 'paystack', $3, 10.00, 'NGN', 'pending')
		 ON CONFLICT (reference) DO NOTHING`,
		uuid.New().String(), userID, reference,
	)
	if err != nil {
		h.log.Warn("failed to record pending payment", "err", err)
	}

	url, err := h.paystack.InitializeTransaction(c.Context(), userID, email, reference)
	if err != nil {
		h.log.Error("paystack init failed", "err", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"url": url, "reference": reference})
}

// CryptoCheckout returns payment details for a stablecoin payment.
// POST /api/v1/billing/crypto
func (h *Handlers) CryptoCheckout(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	var req struct {
		Token   string `json:"token"`   // BTC | ETH | USDT | USDC
		Network string `json:"network"` // bitcoin | ethereum | base | arbitrum | tron | solana
	}
	if err := c.BodyParser(&req); err != nil || req.Token == "" || req.Network == "" {
		req.Token = "USDT"
		req.Network = "base"
	}

	reference := fmt.Sprintf("crypto-%s-%d", userID[:8], time.Now().Unix())

	info, err := GetCryptoPaymentInfo(userID, reference, req.Token, req.Network)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Record pending crypto payment — store token/network in currency for later verification.
	_, err = h.db.Exec(
		`INSERT INTO payments (id, user_id, provider, reference, amount_usd, currency, status)
		 VALUES ($1, $2, 'crypto', $3, 10.00, $4, 'pending')
		 ON CONFLICT (reference) DO NOTHING`,
		uuid.New().String(), userID, reference, fmt.Sprintf("%s/%s", req.Token, req.Network),
	)
	if err != nil {
		h.log.Warn("failed to record pending crypto payment", "err", err)
	}

	return c.JSON(fiber.Map{
		"payment": info,
		"instructions": fmt.Sprintf(
			"Send exactly %s %s on %s to the address below. Include reference '%s' in memo if supported.",
			info.Amount, info.Token, info.Network, reference,
		),
	})
}

// VerifyCrypto verifies a crypto payment on-chain and upgrades the user if confirmed.
// POST /api/v1/billing/crypto/verify
func (h *Handlers) VerifyCrypto(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	var req struct {
		Reference string `json:"reference"`
		TxHash    string `json:"tx_hash"`
	}
	if err := c.BodyParser(&req); err != nil || req.Reference == "" || req.TxHash == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "reference and tx_hash required"})
	}

	// Look up the payment to get token and network.
	var currency string
	if err := h.db.QueryRow(
		`SELECT currency FROM payments WHERE user_id = $1 AND reference = $2`,
		userID, req.Reference,
	).Scan(&currency); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "payment record not found — generate a payment address first"})
	}

	// currency is stored as "TOKEN/NETWORK" e.g. "USDC/base"
	parts := strings.SplitN(currency, "/", 2)
	storedToken := parts[0]
	network := "ethereum"
	if len(parts) == 2 {
		network = parts[1]
	}

	verifier := NewChainVerifier()
	result, err := verifier.Verify(c.Context(), req.TxHash, network, storedToken)
	if err != nil {
		h.log.Warn("on-chain verification error", "err", err, "tx", req.TxHash)
		_, _ = h.db.Exec(
			`UPDATE payments SET reference = $1, status = 'pending_review' WHERE user_id = $2 AND reference = $3`,
			req.TxHash, userID, req.Reference,
		) //nolint:errcheck
		return c.JSON(fiber.Map{
			"status":  "pending_review",
			"message": "Could not verify automatically. Your transaction has been submitted for manual review within 1 hour.",
		})
	}

	if !result.Confirmed {
		_, _ = h.db.Exec(
			`UPDATE payments SET reference = $1, status = 'pending_review' WHERE user_id = $2 AND reference = $3`,
			req.TxHash, userID, req.Reference,
		) //nolint:errcheck
		return c.JSON(fiber.Map{
			"status":  "pending",
			"message": fmt.Sprintf("Transaction found but not yet confirmed: %s", result.Error),
		})
	}

	_, _ = h.db.Exec(`UPDATE payments SET reference = $1, status = 'success' WHERE user_id = $2 AND reference = $3`,
		req.TxHash, userID, req.Reference) //nolint:errcheck
	_, _ = h.db.Exec(`UPDATE users SET plan = 'pro' WHERE id = $1`, userID) //nolint:errcheck
	_, _ = h.db.Exec(`
		INSERT INTO subscriptions (user_id, provider, provider_subscription_id, status, current_period_end)
		VALUES ($1, 'crypto', $2, 'active', $3)
		ON CONFLICT (user_id) DO UPDATE SET
			status = 'active',
			provider_subscription_id = EXCLUDED.provider_subscription_id,
			current_period_end = EXCLUDED.current_period_end
	`, userID, req.TxHash, time.Now().AddDate(0, 1, 0)) //nolint:errcheck

	h.log.Info("crypto payment confirmed on-chain, user upgraded",
		"user_id", userID, "tx", req.TxHash, "network", network, "token", storedToken)

	var email string
	_ = h.db.QueryRow("SELECT email FROM users WHERE id = $1", userID).Scan(&email)
	if email != "" && h.mailer != nil {
		_ = h.mailer.SendReceipt(email, "$10", "Pro (Crypto)", req.TxHash)
		_ = h.mailer.SendUpgradeWelcome(email)
	}

	return c.JSON(fiber.Map{
		"status":  "confirmed",
		"message": fmt.Sprintf("Payment confirmed on %s. Your plan has been upgraded to Pro.", network),
	})
}

// applyProUpgrade marks a payment successful, flips the user to pro, and upserts
// the subscription. Idempotent — safe to call from both the webhook and the
// synchronous verify path.
func (h *Handlers) applyProUpgrade(userID, reference, provider, subID string) {
	_, _ = h.db.Exec(`UPDATE payments SET status = 'success' WHERE reference = $1`, reference)                 //nolint:errcheck
	_, _ = h.db.Exec(`UPDATE users SET plan = 'pro' WHERE id = $1`, userID)                                    //nolint:errcheck
	_, _ = h.db.Exec(`
		INSERT INTO subscriptions (user_id, provider, provider_subscription_id, status, current_period_end)
		VALUES ($1, $2, $3, 'active', $4)
		ON CONFLICT (user_id) DO UPDATE SET
			status = 'active',
			provider_subscription_id = EXCLUDED.provider_subscription_id,
			current_period_end = EXCLUDED.current_period_end
	`, userID, provider, subID, time.Now().AddDate(0, 1, 0)) //nolint:errcheck
}

// VerifyPaystack confirms a Paystack payment by reference. This is the synchronous
// fallback for environments where the asynchronous webhook can't reach the server
// (local dev, no public URL, signature mismatch). Idempotent — safe to retry.
// POST /api/v1/billing/verify  { "reference": "..." }
func (h *Handlers) VerifyPaystack(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	var req struct {
		Reference string `json:"reference"`
	}
	_ = c.BodyParser(&req) //nolint:errcheck
	reference := strings.TrimSpace(req.Reference)
	if reference == "" {
		// Fall back to the user's most recent pending Paystack payment.
		_ = h.db.QueryRow(
			`SELECT reference FROM payments WHERE user_id = $1 AND provider = 'paystack' ORDER BY created_at DESC LIMIT 1`,
			userID,
		).Scan(&reference) //nolint:errcheck
	}
	if reference == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "no payment reference to verify"})
	}

	// Already processed? Return success without hitting Paystack again.
	var status string
	_ = h.db.QueryRow(`SELECT status FROM payments WHERE reference = $1 AND user_id = $2`, reference, userID).Scan(&status) //nolint:errcheck
	if status == "success" {
		return c.JSON(fiber.Map{"status": "confirmed", "plan": "pro"})
	}

	confirmed, err := h.paystack.VerifyTransaction(c.Context(), reference)
	if err != nil {
		h.log.Warn("paystack verify failed", "err", err, "reference", reference)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"status": "error", "error": "could not reach Paystack to verify payment"})
	}
	if !confirmed {
		return c.JSON(fiber.Map{"status": "pending", "message": "Payment not confirmed yet — try again in a moment."})
	}

	h.applyProUpgrade(userID, reference, "paystack", reference)
	h.log.Info("paystack payment verified synchronously, user upgraded", "user_id", userID, "reference", reference)

	var email string
	_ = h.db.QueryRow("SELECT email FROM users WHERE id = $1", userID).Scan(&email) //nolint:errcheck
	if email != "" && h.mailer != nil {
		_ = h.mailer.SendReceipt(email, "₦16,500", "Pro", reference) //nolint:errcheck
		_ = h.mailer.SendUpgradeWelcome(email)                       //nolint:errcheck
	}

	return c.JSON(fiber.Map{"status": "confirmed", "plan": "pro"})
}

// ListInvoices returns payment history for the authenticated user.
// GET /api/v1/billing/invoices
func (h *Handlers) ListInvoices(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	rows, err := h.db.QueryContext(c.Context(),
		`SELECT id, provider, reference, amount_usd, currency, status, created_at
		 FROM payments WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
		userID,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch invoices"})
	}
	defer rows.Close() //nolint:errcheck

	type Invoice struct {
		ID        string  `json:"id"`
		Provider  string  `json:"method"`
		Reference string  `json:"reference"`
		Amount    float64 `json:"amount_usd"`
		Currency  string  `json:"currency"`
		Status    string  `json:"status"`
		Date      string  `json:"date"`
	}

	var invoices []Invoice
	for rows.Next() {
		var inv Invoice
		var createdAt time.Time
		if err := rows.Scan(&inv.ID, &inv.Provider, &inv.Reference, &inv.Amount, &inv.Currency, &inv.Status, &createdAt); err != nil {
			continue
		}
		inv.Date = createdAt.Format("2006-01-02")
		invoices = append(invoices, inv)
	}

	if invoices == nil {
		invoices = []Invoice{}
	}

	return c.JSON(fiber.Map{"invoices": invoices})
}

// GetUsage returns the current usage stats for the authenticated user.
// GET /api/v1/billing/usage
func (h *Handlers) GetUsage(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	plan, _ := c.Locals("plan").(string)
	if plan == "" {
		plan = "free"
	}

	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	var scanCount int
	h.db.QueryRow(
		`SELECT COUNT(*) FROM usage_logs WHERE user_id = $1 AND feature = 'scan' AND created_at >= $2`,
		userID, thirtyDaysAgo,
	).Scan(&scanCount) //nolint:errcheck

	scanLimit := 5
	if plan == "pro" {
		scanLimit = -1 // unlimited
	}

	return c.JSON(fiber.Map{
		"plan":        plan,
		"scans_used":  scanCount,
		"scans_limit": scanLimit,
		"period_days": 30,
	})
}

// CancelSubscription marks a subscription for cancellation at period end.
// POST /api/v1/billing/cancel
func (h *Handlers) CancelSubscription(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}

	_, err := h.db.Exec(
		`UPDATE subscriptions SET status = 'cancel_at_period_end' WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to cancel subscription"})
	}

	return c.JSON(fiber.Map{"status": "cancel_at_period_end", "message": "Subscription will cancel at end of billing period."})
}

// Webhook handles Paystack webhook events.
// POST /api/v1/billing/webhook
func (h *Handlers) Webhook(c *fiber.Ctx) error {
	payload := c.Body()
	signature := c.Get("x-paystack-signature")

	if !VerifyWebhookSignature(payload, signature, h.paystack.secretKey) {
		h.log.Warn("invalid paystack webhook signature")
		return c.Status(fiber.StatusBadRequest).SendString("invalid signature")
	}

	var event struct {
		Event string `json:"event"`
		Data  struct {
			Reference string            `json:"reference"`
			Status    string            `json:"status"`
			Metadata  map[string]string `json:"metadata"`
		} `json:"data"`
	}
	if err := c.BodyParser(&event); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("invalid payload")
	}

	if event.Event != "charge.success" {
		return c.SendStatus(fiber.StatusOK)
	}

	// Idempotency check — don't process the same reference twice.
	var existingStatus string
	h.db.QueryRow(`SELECT status FROM payments WHERE reference = $1`, event.Data.Reference).Scan(&existingStatus) //nolint:errcheck
	if existingStatus == "success" {
		h.log.Info("paystack webhook: already processed", "reference", event.Data.Reference)
		return c.SendStatus(fiber.StatusOK)
	}

	userID := event.Data.Metadata["user_id"]
	if userID == "" {
		// Try to look up by reference.
		h.db.QueryRow("SELECT user_id FROM payments WHERE reference = $1", event.Data.Reference).Scan(&userID) //nolint:errcheck
	}
	if userID == "" {
		h.log.Warn("paystack webhook: no user_id found", "reference", event.Data.Reference)
		return c.SendStatus(fiber.StatusOK)
	}

	// Mark payment success.
	_, _ = h.db.Exec(`UPDATE payments SET status = 'success' WHERE reference = $1`, event.Data.Reference) //nolint:errcheck

	// Upgrade user to pro.
	_, _ = h.db.Exec(`UPDATE users SET plan = 'pro' WHERE id = $1`, userID) //nolint:errcheck

	// Upsert subscription record.
	_, _ = h.db.Exec(`
		INSERT INTO subscriptions (user_id, provider, provider_subscription_id, status, current_period_end)
		VALUES ($1, 'paystack', $2, 'active', $3)
		ON CONFLICT (user_id) DO UPDATE SET
			status = 'active',
			provider_subscription_id = EXCLUDED.provider_subscription_id,
			current_period_end = EXCLUDED.current_period_end
	`, userID, event.Data.Reference, time.Now().AddDate(0, 1, 0)) //nolint:errcheck

	h.log.Info("payment confirmed, user upgraded to pro", "user_id", userID)

	var email string
	_ = h.db.QueryRow("SELECT email FROM users WHERE id = $1", userID).Scan(&email)
	if email != "" && h.mailer != nil {
		_ = h.mailer.SendReceipt(email, "₦16,500", "Pro", event.Data.Reference)
		_ = h.mailer.SendUpgradeWelcome(email)
	}

	return c.SendStatus(fiber.StatusOK)
}
