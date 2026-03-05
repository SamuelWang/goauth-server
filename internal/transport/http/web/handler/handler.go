package handler

import (
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/gin-gonic/gin"
)

type WebHandler struct {
	authService *auth.Service
}

func New(authService *auth.Service) *WebHandler {
	return &WebHandler{
		authService: authService,
	}
}

// getCookieSecure retrieves the cookie_secure value from the Gin context
func getCookieSecure(c *gin.Context) bool {
	if val, exists := c.Get("cookie_secure"); exists {
		if secure, ok := val.(bool); ok {
			return secure
		}
	}
	return false
}
