package v1

import (
	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/SamuelWang/goauth-server/internal/transport/http/api/v1/handler"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, authService *auth.Service, userService *user.Service) {
	authHandler := handler.New(userService)

	// Auth routes
	authGroup := r.Group("/auth")
	{
		// Public routes
		authGroup.POST("/logout", authHandler.Logout)

		// Protected routes
		authGroup.Use(middleware.AuthMiddleware(authService))
		authGroup.GET("/me", authHandler.GetCurrentUser)
	}
}
