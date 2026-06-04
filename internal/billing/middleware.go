package billing

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// QuotaMiddleware enforces billing limits based on the user's plan.
// For pro users it also checks subscription expiry — if current_period_end has
// passed, the user is treated as free until they pay again.
func QuotaMiddleware(db *sql.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if db == nil {
			return c.Next()
		}

		// Only starting a scan (POST) is gated/logged — status polls (GET) must not
		// consume quota or they'd exhaust the free limit on a single scan.
		if c.Method() != fiber.MethodPost {
			return c.Next()
		}

		userID, ok := c.Locals("user_id").(string)
		if !ok || userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}

		plan, ok := c.Locals("plan").(string)
		if !ok || plan == "" {
			plan = "free"
		}

		// Pro plan: verify subscription hasn't expired.
		if plan == "pro" {
			var periodEnd time.Time
			err := db.QueryRow(
				`SELECT current_period_end FROM subscriptions WHERE user_id = $1 AND status = 'active'`,
				userID,
			).Scan(&periodEnd)
			if err != nil || time.Now().After(periodEnd) {
				// Subscription expired or not found — downgrade in DB and treat as free.
				_, _ = db.Exec(`UPDATE users SET plan = 'free' WHERE id = $1`, userID)
				_, _ = db.Exec(`UPDATE subscriptions SET status = 'expired' WHERE user_id = $1`, userID)
				return c.Status(fiber.StatusPaymentRequired).JSON(fiber.Map{
					"error":   "Your Pro subscription has expired. Renew to continue scanning.",
					"upgrade": "/billing",
				})
			}
			return proceedAndLog(c, db, userID, "scan")
		}

		// Free plan: rolling 30-day quota.
		thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
		var count int
		err := db.QueryRow(
			`SELECT COUNT(*) FROM usage_logs WHERE user_id = $1 AND feature = $2 AND created_at >= $3`,
			userID, "scan", thirtyDaysAgo,
		).Scan(&count)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to check quota"})
		}
		if count >= 5 {
			return c.Status(fiber.StatusPaymentRequired).JSON(fiber.Map{
				"error":   "Free plan limit reached (5 scans). Upgrade to Pro for unlimited scans.",
				"upgrade": "/billing",
			})
		}
		return proceedAndLog(c, db, userID, "scan")
	}
}

// proceedAndLog calls the next handler and if successful, logs the usage.
func proceedAndLog(c *fiber.Ctx, db *sql.DB, userID string, feature string) error {
	// Let the request proceed
	err := c.Next()

	// Only log usage if the request was successful
	if err == nil && c.Response().StatusCode() < http.StatusBadRequest {
		id := uuid.New().String()
		_, _ = db.Exec(
			`INSERT INTO usage_logs (id, user_id, feature, created_at) VALUES ($1, $2, $3, $4)`,
			id, userID, feature, time.Now(),
		)
	}

	return err
}
