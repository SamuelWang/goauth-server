package handler

import (
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/gin-gonic/gin"
)

type ApiV1Handler struct {
	authService *auth.AuthService
}

func New(authService *auth.AuthService) *ApiV1Handler {
	return &ApiV1Handler{
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

// getUserID retrieves the user_id value from the Gin context
// Returns the user ID and a boolean indicating whether it was found
func getUserID(c *gin.Context) (string, bool) {
	if val, exists := c.Get("user_id"); exists {
		if userID, ok := val.(string); ok {
			return userID, true
		}
	}
	return "", false
}
