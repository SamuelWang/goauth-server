package middleware

import (
	"regexp"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// validRequestIDPattern matches safe request ID values: alphanumeric characters,
// hyphens, and underscores, with a maximum length of 64 characters.
// This prevents log-injection attacks via the X-Request-ID header.
var validRequestIDPattern = regexp.MustCompile(`^[a-zA-Z0-9\-_]{1,64}$`)

func ContextMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Assign a unique request ID for log correlation.  Accept a
		// forwarded ID from a trusted upstream proxy when present, but only
		// if it contains safe characters to prevent log-injection attacks.
		// Otherwise generate a fresh UUID.
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" || !validRequestIDPattern.MatchString(requestID) {
			requestID = uuid.New().String()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Set("env", cfg.Server.Env)
		c.Set("cookie_secure", cfg.Server.Env == "production" || cfg.Server.Scheme == "https")
		c.Next()
	}
}
