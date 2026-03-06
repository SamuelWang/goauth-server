package authserver

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/repository"
	authservice "github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
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
	providerSvc, err := provider.New(repo, encKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("initializing provider service: %w", err)
	}

	// Initialize services
	authService, err := authservice.New(repo, cfg, providerSvc)
	if err != nil {
		return nil, fmt.Errorf("initializing auth service: %w", err)
	}
	userService := user.New(repo)

	// Set Gin mode
	if cfg.Server.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create Gin router
	r := gin.New()

	// Register routes
	api.RegisterRoutes(r, cfg, authService, userService)
	web.RegisterRoutes(r, cfg, authService)
	ops.RegisterRoutes(r)

	s := &Server{
		router: r,
		srv: &http.Server{
			Addr:    ":" + cfg.Server.Port,
			Handler: r,
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
