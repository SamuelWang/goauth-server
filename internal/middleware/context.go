package middleware

import (
	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/gin-gonic/gin"
)

func ContextMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("env", cfg.Server.Env)
		c.Set("cookie_secure", cfg.Server.Env == "production" || cfg.Server.Scheme == "https")
		c.Next()
	}
}
