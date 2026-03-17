package handler

import (
	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/gin-gonic/gin"
)

type WebHandler struct {
	authService *auth.Service
	cfg         *config.Config
	signingKey  []byte
}

func New(authService *auth.Service, cfg *config.Config, signingKey []byte) *WebHandler {
	return &WebHandler{
		authService: authService,
		cfg:         cfg,
		signingKey:  signingKey,
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
