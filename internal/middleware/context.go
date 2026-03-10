package middleware

import (
	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func ContextMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Assign a unique request ID for log correlation.  Accept a
		// forwarded ID from a trusted upstream proxy when present so that
		// the identifier is consistent across the entire request chain;
		// otherwise generate a fresh UUID.
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Set("env", cfg.Server.Env)
		c.Set("cookie_secure", cfg.Server.Env == "production" || cfg.Server.Scheme == "https")
		c.Next()
	}
}
