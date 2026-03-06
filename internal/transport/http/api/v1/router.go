package v1

import (
	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/SamuelWang/goauth-server/internal/transport/http/api/v1/handler"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, authService *auth.Service, userService *user.Service, providerService *provider.Service) {
	h := handler.New(userService, providerService)

	// Auth routes
	authGroup := r.Group("/auth")
	{
		// Public routes
		authGroup.POST("/logout", h.Logout)

		// Protected routes
		authGroup.Use(middleware.AuthMiddleware(authService))
		authGroup.GET("/me", h.GetCurrentUser)
	}

	// Client-scoped provider routes (admin only)
	clientProviderGroup := r.Group("/clients/:client_id/providers")
	clientProviderGroup.Use(middleware.AuthMiddleware(authService), middleware.AdminMiddleware(userService))
	{
		clientProviderGroup.GET("", h.ListProviders)
		clientProviderGroup.GET("/:id", h.GetProvider)
		clientProviderGroup.POST("", h.CreateProvider)
		clientProviderGroup.PATCH("/:id", h.UpdateProvider)
		clientProviderGroup.DELETE("/:id", h.DeleteProvider)
	}
}
