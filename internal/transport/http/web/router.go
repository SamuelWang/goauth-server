package web

import (
	"encoding/hex"
	"log"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/transport/http/web/handler"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, cfg *config.Config, authService *auth.Service) {
	signingKey, err := hex.DecodeString(cfg.Security.SessionSigningKey)
	if err != nil {
		// config.Load validates the key, so this should never happen at runtime.
		log.Printf("web: WARNING: could not decode SESSION_SIGNING_KEY: %v", err)
		signingKey = []byte{}
	}

	webHandler := handler.New(authService, cfg, signingKey)

	webGroup := r.Group("/web")
	webGroup.Use(gin.Recovery(), gin.Logger(), middleware.ContextMiddleware(cfg))

	// Client-scoped OAuth web flow (public).
	authGroup := webGroup.Group("/auth/:client_id/:provider")
	{
		authGroup.GET("/login", webHandler.Login)
		authGroup.GET("/callback", webHandler.Callback)
	}
}
