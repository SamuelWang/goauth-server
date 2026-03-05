package web

import (
	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/transport/http/web/handler"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, cfg *config.Config, authService *auth.Service) {
	webHandler := handler.New(authService)

	r.Use(gin.Recovery(), gin.Logger(), middleware.ContextMiddleware(cfg))

	// Auth routes
	authGroup := r.Group("/auth")

	if cfg.OAuth.Google.Enabled {
		authGroup.GET("/google/login", webHandler.GoogleLogin)
		authGroup.GET("/google/callback", webHandler.GoogleCallback)
	}
}
