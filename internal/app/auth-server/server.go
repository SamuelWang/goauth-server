package authserver

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/repository"
	auditservice "github.com/SamuelWang/goauth-server/internal/service/audit"
	authservice "github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/service/client"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/SamuelWang/goauth-server/internal/service/session"
	"github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/SamuelWang/goauth-server/internal/transport/http/api"
	"github.com/SamuelWang/goauth-server/internal/transport/http/ops"
	"github.com/SamuelWang/goauth-server/internal/transport/http/web"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Server struct {
	router *gin.Engine
	srv    *http.Server
}

func NewServer(cfg *config.Config, dbPool *pgxpool.Pool) (*Server, error) {
	// Initialize repository
	repo := repository.New(dbPool)

	// Initialize provider service (requires a 32-byte AES-256 key, hex-encoded in config).
	encKeyBytes, err := hex.DecodeString(cfg.Security.ProviderEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("decoding provider encryption key: %w", err)
	}
	providerSvc, err := provider.New(repo, encKeyBytes, cfg.Server.Env)
	if err != nil {
		return nil, fmt.Errorf("initializing provider service: %w", err)
	}

	// Initialize services
	auditService := auditservice.New(repo)
	authService, err := authservice.New(repo, cfg, providerSvc)
	if err != nil {
		return nil, fmt.Errorf("initializing auth service: %w", err)
	}
	userService := user.New(repo)
	clientService := client.New(repo, cfg.Server.Env, auditService)
	sessionService := session.New(repo)

	// Set Gin mode
	if cfg.Server.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create Gin router
	r := gin.New()

	// Record latency and status of every request (must come before route
	// groups so all paths are covered, including /ops/health and /metrics).
	r.Use(middleware.MetricsMiddleware())

	// Apply CORS globally so preflight OPTIONS requests are handled before any
	// route-group middleware (auth, rate limiting, etc.) intercepts them.
	r.Use(middleware.CORSMiddleware(cfg.Security.CORSAllowedOrigins, cfg.Server.Env))

	// Limit request body size to 1 MiB to prevent memory-exhaustion DoS before
	// any JSON binding occurs.
	r.Use(middleware.MaxBodySizeMiddleware())

	// Apply defensive HTTP security headers globally (X-Content-Type-Options,
	// X-Frame-Options, X-XSS-Protection, Content-Security-Policy, and HSTS in
	// production).
	r.Use(middleware.SecurityHeadersMiddleware(cfg.Server.Env))

	// Register routes
	api.RegisterRoutes(r, cfg, authService, userService, providerSvc, clientService, sessionService)
	web.RegisterRoutes(r, cfg, authService)
	ops.RegisterRoutes(r)

	s := &Server{
		router: r,
		srv: &http.Server{
			Addr:              ":" + cfg.Server.Port,
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second, // mitigate Slowloris (G112)
		},
	}

	return s, nil
}

func (s *Server) Run() error {
	return s.srv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
