package v1

import (
	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/service/audit"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/service/client"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/SamuelWang/goauth-server/internal/service/session"
	"github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/SamuelWang/goauth-server/internal/transport/http/api/v1/handler"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, authService *auth.Service, userService *user.Service, providerService *provider.Service, clientService *client.Service, sessionService *session.Service, auditSvc *audit.Service) {
	h := handler.New(authService, userService, providerService, clientService, sessionService, auditSvc)

	// Public auth routes
	publicAuth := r.Group("/auth")
	{
		// Token exchange: 10 requests per minute per IP.
		publicAuth.POST("/token", middleware.RateLimitByIP(middleware.TokenRatePerMin, middleware.TokenRatePerMin), h.TokenExchange)
		// Direct login: 10 requests per minute per IP.
		publicAuth.POST("/login", middleware.RateLimitByIP(middleware.LoginRatePerMin, middleware.LoginRatePerMin), h.Login)
		// Force-password-change exchange: 10 requests per minute per IP.
		// The challenge token is the credential; no Authorization header needed.
		publicAuth.POST("/change-password", middleware.RateLimitByIP(middleware.LoginRatePerMin, middleware.LoginRatePerMin), h.ChangePassword)
		// RFC 7009 token revocation: caller authenticates via HTTP Basic or Bearer.
		publicAuth.POST("/revoke", middleware.RateLimitByIP(middleware.TokenRatePerMin, middleware.TokenRatePerMin), h.Revoke)
	}

	// Public client-scoped routes
	r.GET("/clients/:client_id/auth/providers", h.ListEnabledProviders)

	// Protected auth routes (require a valid bearer token)
	protectedAuth := r.Group("/auth")
	protectedAuth.Use(middleware.AuthMiddleware(authService), middleware.CSRFMiddleware())
	{
		protectedAuth.POST("/logout", h.Logout)
		protectedAuth.GET("/me", h.GetCurrentUser)
	}

	// Client management routes (admin only)
	// Admin endpoints: 30 requests per minute per authenticated user.
	clientsGroup := r.Group("/clients")
	clientsGroup.Use(middleware.AuthMiddleware(authService), middleware.AdminMiddleware(userService), middleware.RateLimitByUser(middleware.AdminRatePerMin, middleware.AdminRatePerMin), middleware.CSRFMiddleware())
	{
		clientsGroup.GET("", h.ListClients)
		clientsGroup.GET("/:client_id", h.GetClient)
		clientsGroup.POST("", h.CreateClient)
		clientsGroup.PATCH("/:client_id", h.UpdateClient)
		clientsGroup.POST("/:client_id/regenerate-secret", h.RegenerateClientSecret)
		clientsGroup.DELETE("/:client_id", h.DeleteClient)
	}

	// Client-scoped provider routes (admin only)
	clientProviderGroup := r.Group("/clients/:client_id/providers")
	clientProviderGroup.Use(middleware.AuthMiddleware(authService), middleware.AdminMiddleware(userService), middleware.RateLimitByUser(middleware.AdminRatePerMin, middleware.AdminRatePerMin), middleware.CSRFMiddleware())
	{
		clientProviderGroup.GET("", h.ListProviders)
		clientProviderGroup.GET("/:id", h.GetProvider)
		clientProviderGroup.POST("", h.CreateProvider)
		clientProviderGroup.PATCH("/:id", h.UpdateProvider)
		clientProviderGroup.DELETE("/:id", h.DeleteProvider)
	}

	// User management routes (admin only)
	usersGroup := r.Group("/users")
	usersGroup.Use(middleware.AuthMiddleware(authService), middleware.AdminMiddleware(userService), middleware.RateLimitByUser(middleware.AdminRatePerMin, middleware.AdminRatePerMin), middleware.CSRFMiddleware())
	{
		usersGroup.GET("", h.ListUsers)
		usersGroup.PATCH("/:id", h.UpdateUserStatus)
		usersGroup.DELETE("/:id/lockout", h.UnlockUser)
	}

	// Session management routes (admin only)
	sessionsGroup := r.Group("/sessions")
	sessionsGroup.Use(middleware.AuthMiddleware(authService), middleware.AdminMiddleware(userService), middleware.RateLimitByUser(middleware.AdminRatePerMin, middleware.AdminRatePerMin), middleware.CSRFMiddleware())
	{
		sessionsGroup.GET("/codes", h.ListAuthorizationCodes)
		sessionsGroup.DELETE("/codes/:id", h.RevokeAuthorizationCode)
		sessionsGroup.GET("/tokens", h.ListAccessTokens)
		sessionsGroup.DELETE("/tokens/:id", h.RevokeAccessToken)
	}
}
