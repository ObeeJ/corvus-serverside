package api

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
	sentryfiber "github.com/getsentry/sentry-go/fiber"
	"github.com/ObeeJ/corvus-serverside/internal/api/handlers"
	"github.com/ObeeJ/corvus-serverside/internal/auth"
	"github.com/ObeeJ/corvus-serverside/internal/billing"
	"github.com/ObeeJ/corvus-serverside/internal/db"
	"github.com/ObeeJ/corvus-serverside/internal/engine"
	"github.com/ObeeJ/corvus-serverside/internal/mail"
	"github.com/ObeeJ/corvus-serverside/internal/mesh"
	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

// Config holds API server configuration.
type Config struct {
	Port      int
	AuthToken string
}

// Server provides the REST and WebSocket API.
type Server struct {
	app                *fiber.App
	engine             *engine.Engine
	db                 *db.Client
	cfg                Config
	log                *slog.Logger
	scanHandlers       *Handlers
	hostHandlers       *handlers.HostHandlers
	alertHandlers      *handlers.AlertHandlers
	queryHandlers      *handlers.QueryHandlers
	askHandlers        *handlers.AskHandlers
	supplyChainHandlers *handlers.SupplyChainHandlers
	statsHandlers      *handlers.StatsHandlers
	auth               *auth.Handlers
	billing            *billing.Handlers
	mesh               *mesh.Mesh
}

// New creates a new API Server instance.
func New(eng *engine.Engine, storeMgr *store.Manager, dbClient *db.Client, meshNode *mesh.Mesh, cfg Config, log *slog.Logger) *Server {
	// Init Sentry if DSN is configured.
	if dsn := os.Getenv("SENTRY_DSN"); dsn != "" {
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:              dsn,
			TracesSampleRate: getSampleRate(),
			EnableLogs:       true,
			Environment:      os.Getenv("APP_ENV"),
			BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
				// Strip sensitive headers before sending to Sentry.
				if event.Request != nil {
					delete(event.Request.Headers, "Authorization")
					delete(event.Request.Headers, "Cookie")
				}
				return event
			},
		}); err != nil {
			log.Warn("Sentry init failed", "err", err)
		} else {
			log.Info("Sentry error tracking enabled")
		}
	}

	app := fiber.New(fiber.Config{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	})

	s := &Server{
		app:                 app,
		engine:              eng,
		db:                  dbClient,
		cfg:                 cfg,
		log:                 log,
		scanHandlers:        &Handlers{engine: eng, log: log},
		hostHandlers:        handlers.NewHostHandlers(storeMgr, log),
		alertHandlers:       handlers.NewAlertHandlers(storeMgr, log),
		queryHandlers:       handlers.NewQueryHandlers(storeMgr, log),
		askHandlers:         handlers.NewAskHandlers(storeMgr, log),
		supplyChainHandlers: handlers.NewSupplyChainHandlers(storeMgr, log),
		statsHandlers:       handlers.NewStatsHandlers(storeMgr, log),
		mesh:                meshNode,
	}

	if dbClient != nil {
		mailer := mail.New(log)
		s.auth = auth.NewHandlers(dbClient, mailer)
		svc := billing.NewPaystackService(log)
		s.billing = billing.NewHandlers(svc, dbClient.DB, log, mailer)
	}

	s.registerMiddleware()
	s.registerRoutes()

	return s
}

// Start begins listening on the configured port.
func (s *Server) Start() error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Port)
	s.log.Info("Starting API server", "addr", addr)
	return s.app.Listen(addr)
}

func (s *Server) registerMiddleware() {
	// Sentry must be first to catch all panics and errors.
	if os.Getenv("SENTRY_DSN") != "" {
		s.app.Use(sentryfiber.New(sentryfiber.Options{
			Repanic:         true,
			WaitForDelivery: false,
		}))
		// Capture every request as a Sentry transaction + tag user + report 5xx.
		s.app.Use(func(c *fiber.Ctx) error {
			hub := sentryfiber.GetHubFromContext(c)
			if hub == nil {
				return c.Next()
			}

			// Start a transaction for every request.
			txName := c.Method() + " " + c.Path()
			span := sentry.StartTransaction(c.Context(), txName,
				sentry.WithTransactionSource(sentry.SourceURL),
			)
			span.SetTag("http.method", c.Method())
			span.SetTag("http.url", c.Path())
			defer span.Finish()

			err := c.Next()

			// Tag user after auth middleware has run.
			if uid, ok := c.Locals("user_id").(string); ok && uid != "" {
				hub.Scope().SetUser(sentry.User{ID: uid})
				span.SetTag("user.id", uid)
			}

			status := c.Response().StatusCode()
			span.SetTag("http.status_code", fmt.Sprintf("%d", status))

			// Capture 4xx client errors and all 5xx as Sentry events.
			if status >= 400 {
				hub.WithScope(func(scope *sentry.Scope) {
					scope.SetTag("http.method", c.Method())
					scope.SetTag("http.path", c.Path())
					scope.SetTag("http.status", fmt.Sprintf("%d", status))
					if status >= 500 {
						hub.CaptureMessage(fmt.Sprintf("%s %s → %d", c.Method(), c.Path(), status))
					}
				})
			}

			return err
		})
	}
	// CORS for development — allows the Next.js dev server to call the API.
	s.app.Use(cors.New(cors.Config{
		AllowOrigins: getAllowedOrigins(),
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
	}))

	s.app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${latency} ${method} ${path}\n",
	}))

	// Basic rate limiter: 100 requests per minute per IP.
	s.app.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: time.Minute,
	}))

	// Per-user rate limiter on authenticated routes: 200 req/min per user.
	// Applied after JWT middleware so user_id is available.
	userRateLimiter := limiter.New(limiter.Config{
		Max:        200,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			if uid, ok := c.Locals("user_id").(string); ok && uid != "" {
				return "user:" + uid
			}
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Rate limit exceeded. Max 200 requests per minute per user.",
			})
		},
	})
	s.app.Use("/api/v1/scan", userRateLimiter)
	s.app.Use("/api/v1/ask", userRateLimiter)

	// Use JWT middleware for authenticated routes if DB is configured.
	// /scan accepts either a JWT (dashboard) or an API key (CLI remote scans).
	if s.db != nil {
		s.app.Use("/api/v1/scan", auth.FlexibleMiddleware(s.db.DB))
		s.app.Use("/api/v1/hosts", auth.Middleware())
		s.app.Use("/api/v1/alerts", auth.Middleware())
		s.app.Use("/api/v1/query", auth.Middleware())
		
		// Apply quota middleware to scan endpoint
		s.app.Use("/api/v1/scan", billing.QuotaMiddleware(s.db.DB))
	}
}

func (s *Server) registerRoutes() {
	s.app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
	s.app.Get("/readyz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	v1 := s.app.Group("/api/v1")

	// Auth routes (always registered; return 503 if DB not configured)
	v1.Post("/auth/signup", func(c *fiber.Ctx) error {
		if s.auth == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "authentication not configured (DATABASE_URL not set)"})
		}
		return s.auth.Signup(c)
	})
	v1.Post("/auth/login", func(c *fiber.Ctx) error {
		if s.auth == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "authentication not configured (DATABASE_URL not set)"})
		}
		return s.auth.Login(c)
	})
	v1.Post("/auth/forgot", func(c *fiber.Ctx) error {
		if s.auth == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "authentication not configured (DATABASE_URL not set)"})
		}
		return s.auth.Forgot(c)
	})
	v1.Post("/auth/reset", func(c *fiber.Ctx) error {
		if s.auth == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "authentication not configured (DATABASE_URL not set)"})
		}
		return s.auth.Reset(c)
	})
	v1.Get("/auth/me", auth.Middleware(), func(c *fiber.Ctx) error {
		if s.auth == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "authentication not configured"})
		}
		return s.auth.Me(c)
	})
	v1.Post("/auth/refresh", auth.Middleware(), func(c *fiber.Ctx) error {
		if s.auth == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "authentication not configured"})
		}
		return s.auth.Refresh(c)
	})
	v1.Patch("/auth/onboarding", auth.Middleware(), func(c *fiber.Ctx) error {
		if s.auth == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "authentication not configured"})
		}
		return s.auth.Onboarding(c)
	})

	// API key management (manage from the dashboard with a JWT).
	if s.auth != nil {
		v1.Post("/keys", auth.Middleware(), s.auth.CreateAPIKey)
		v1.Get("/keys", auth.Middleware(), s.auth.ListAPIKeys)
		v1.Delete("/keys/:id", auth.Middleware(), s.auth.RevokeAPIKey)
	}

	// Billing routes
	if s.billing != nil {
		v1.Post("/billing/checkout", auth.Middleware(), s.billing.CreateCheckout)
		v1.Post("/billing/crypto", auth.Middleware(), s.billing.CryptoCheckout)
		v1.Post("/billing/crypto/verify", auth.Middleware(), s.billing.VerifyCrypto)
		v1.Post("/billing/verify", auth.Middleware(), s.billing.VerifyPaystack)
		v1.Get("/billing/invoices", auth.Middleware(), s.billing.ListInvoices)
		v1.Get("/billing/usage", auth.Middleware(), s.billing.GetUsage)
		v1.Post("/billing/cancel", auth.Middleware(), s.billing.CancelSubscription)
		v1.Post("/billing/webhook", s.billing.Webhook)
	}

	// Scan routes
	v1.Post("/scan", s.scanHandlers.StartScan)
	v1.Get("/scan/:id", s.scanHandlers.GetScan)
	v1.Get("/scan/:id/stream", s.scanHandlers.StreamScan)

	// Host routes
	v1.Get("/hosts", s.hostHandlers.ListHosts)
	v1.Get("/hosts/:ip", s.hostHandlers.GetHost)

	// Alert routes
	v1.Get("/alerts", s.alertHandlers.ListAlerts)

	// Query routes
	v1.Post("/query", s.queryHandlers.ExecuteQuery)

	// Stats route
	v1.Get("/stats", s.statsHandlers.GetStats)

	// LLM ask route
	v1.Post("/ask", auth.Middleware(), s.askHandlers.Ask)
	v1.Post("/ask/transcribe", auth.Middleware(), s.askHandlers.Transcribe)
	v1.Post("/ask/speak", auth.Middleware(), s.askHandlers.Speak)
	v1.Get("/ask/models", auth.Middleware(), s.askHandlers.ListModels)

	// Supply chain route
	v1.Get("/supplychain/:ip", auth.Middleware(), s.supplyChainHandlers.GetSupplyChain)

	// Mesh routes
	v1.Get("/mesh/nodes", auth.Middleware(), s.handleMeshNodes)

	// Static fallback for the Next.js frontend build.
	s.app.Static("/", "./web/out")
}

func (s *Server) handleMeshNodes(c *fiber.Ctx) error {
	if s.mesh == nil {
		return c.JSON(fiber.Map{"nodes": []struct{}{}, "total": 0})
	}
	nodes := s.mesh.Nodes()
	return c.JSON(fiber.Map{"nodes": nodes, "total": len(nodes)})
}

// getAllowedOrigins returns CORS origins from env or defaults to localhost for dev.
func getAllowedOrigins() string {
	if origins := os.Getenv("ALLOWED_ORIGINS"); origins != "" {
		return origins
	}
	// Dev default: allow Next.js dev server and production URL
	publicURL := os.Getenv("PUBLIC_URL")
	if publicURL == "" {
		publicURL = "http://localhost:3000"
	}
	return "http://localhost:3000,http://localhost:3001," + publicURL
}

// getSampleRate returns 1.0 in dev, 0.1 in production to stay within Sentry free tier.
func getSampleRate() float64 {
	if os.Getenv("APP_ENV") == "production" {
		return 0.1
	}
	return 1.0
}
