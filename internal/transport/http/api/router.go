package api

import (
	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/SamuelWang/goauth-server/internal/service/user"
	v1 "github.com/SamuelWang/goauth-server/internal/transport/http/api/v1"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, cfg *config.Config, authService *auth.Service, userService *user.Service, providerService *provider.Service) {
	apiGroup := r.Group("/api")
	apiGroup.Use(gin.Recovery(), gin.Logger(), middleware.ContextMiddleware(cfg))

	apiV1Group := apiGroup.Group("/v1")
	v1.RegisterRoutes(apiV1Group, authService, userService, providerService)
}
