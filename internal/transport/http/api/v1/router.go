package v1

import (
	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/service/client"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/SamuelWang/goauth-server/internal/transport/http/api/v1/handler"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, authService *auth.Service, userService *user.Service, providerService *provider.Service, clientService *client.Service) {
	h := handler.New(authService, userService, providerService, clientService)

	// Public auth routes
	publicAuth := r.Group("/auth")
	{
		publicAuth.POST("/token", h.TokenExchange)
	}

	// Public client-scoped routes
	r.GET("/clients/:client_id/auth/providers", h.ListEnabledProviders)

	// Protected auth routes (require a valid bearer token)
	protectedAuth := r.Group("/auth")
	protectedAuth.Use(middleware.AuthMiddleware(authService))
	{
		protectedAuth.POST("/logout", h.Logout)
		protectedAuth.GET("/me", h.GetCurrentUser)
	}

	// Client management routes (admin only)
	clientsGroup := r.Group("/clients")
	clientsGroup.Use(middleware.AuthMiddleware(authService), middleware.AdminMiddleware(userService))
	{
		clientsGroup.GET("", h.ListClients)
		clientsGroup.GET("/:id", h.GetClient)
		clientsGroup.POST("", h.CreateClient)
		clientsGroup.PATCH("/:id", h.UpdateClient)
		clientsGroup.POST("/:id/regenerate-secret", h.RegenerateClientSecret)
		clientsGroup.DELETE("/:id", h.DeleteClient)
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
