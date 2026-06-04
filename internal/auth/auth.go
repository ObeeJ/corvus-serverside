package auth

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/apikey"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// secretKey returns the JWT signing key from env or falls back to dev default.
func secretKey() []byte {
	if k := os.Getenv("JWT_SECRET"); k != "" {
		return []byte(k)
	}
	return []byte("corvus_super_secret_dev_key")
}

// Claims represents the JWT payload.
type Claims struct {
	UserID string `json:"uid"`
	Plan   string `json:"plan"`
	jwt.RegisteredClaims
}

// HashPassword creates a bcrypt hash.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

// CheckPasswordHash compares a plaintext password with a bcrypt hash.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateToken creates a JWT for a user.
func GenerateToken(userID string, plan string) (string, error) {
	claims := Claims{
		UserID: userID,
		Plan:   plan,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey())
}

// ResetClaims is a purpose-scoped JWT used only for password resets. Keeping a
// distinct purpose means a normal session token can't be replayed as a reset
// token (and vice-versa) — ParseResetToken rejects anything without purpose:"reset".
type ResetClaims struct {
	UserID  string `json:"uid"`
	Purpose string `json:"purpose"`
	jwt.RegisteredClaims
}

// GenerateResetToken issues a short-lived (30 min) password-reset token.
func GenerateResetToken(userID string) (string, error) {
	claims := ResetClaims{
		UserID:  userID,
		Purpose: "reset",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey())
}

// ParseResetToken validates a reset token and returns the user ID it was issued for.
func ParseResetToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &ResetClaims{}, func(t *jwt.Token) (interface{}, error) {
		return secretKey(), nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid or expired reset token")
	}
	claims, ok := token.Claims.(*ResetClaims)
	if !ok || claims.Purpose != "reset" || claims.UserID == "" {
		return "", fmt.Errorf("invalid reset token")
	}
	return claims.UserID, nil
}

// headerBearer extracts a bearer token from the Authorization header ONLY.
// API keys must use this path so a long-lived secret never lands in a URL/log.
func headerBearer(c *fiber.Ctx) string {
	t := c.Get("Authorization")
	if len(t) > 7 && strings.EqualFold(t[:7], "Bearer ") {
		return t[7:]
	}
	return ""
}

// FlexibleMiddleware authenticates a request using EITHER a Corvus API key
// (CLI remote scans) OR a JWT (dashboard). Whichever succeeds populates the same
// user_id/plan locals, so downstream quota middleware works unchanged.
//
// Security: API keys are accepted from the Authorization header only. The
// ?token= query fallback exists solely for the WebSocket stream transport
// (browsers can't set headers on a WS handshake) and is restricted to JWTs —
// an API key arriving via the query string is rejected outright, so a
// long-lived secret never ends up in server logs or browser history.
func FlexibleMiddleware(db *sql.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// API key — header only.
		if h := headerBearer(c); db != nil && apikey.IsAPIKey(h) {
			uid, plan, err := apikey.Validate(db, h)
			if err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid api key"})
			}
			c.Locals("user_id", uid)
			c.Locals("plan", plan)
			return c.Next()
		}

		// JWT — header, or ?token= for the WebSocket transport.
		tok := headerBearer(c)
		if tok == "" {
			tok = c.Query("token")
		}
		if tok == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		// An API key must never arrive via the query string.
		if apikey.IsAPIKey(tok) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "api keys must use the Authorization header"})
		}

		token, err := jwt.ParseWithClaims(tok, &Claims{}, func(t *jwt.Token) (interface{}, error) {
			return secretKey(), nil
		})
		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		if claims, ok := token.Claims.(*Claims); ok {
			c.Locals("user_id", claims.UserID)
			c.Locals("plan", claims.Plan)
			return c.Next()
		}
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token claims"})
	}
}

// Middleware verifies the JWT and injects user_id into the Fiber context.
func Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString := c.Get("Authorization")
		if tokenString == "" {
			tokenString = c.Query("token")
		}
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}
		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		}
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return secretKey(), nil
		})
		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		if claims, ok := token.Claims.(*Claims); ok {
			c.Locals("user_id", claims.UserID)
			c.Locals("plan", claims.Plan)
			return c.Next()
		}
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token claims"})
	}
}
