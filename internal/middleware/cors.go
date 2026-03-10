package middleware

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORSMiddleware configures Cross-Origin Resource Sharing using gin-contrib/cors.
//
// Behaviour by environment:
//   - production: Only origins listed in allowedOrigins are permitted.
//     Credentials (cookies, Authorization headers) are supported.
//     Wildcard (*) is never used.
//   - development/other: If allowedOrigins is empty, all origins are permitted
//     via the wildcard (*) without credentials (W3C spec forbids combining both).
//     When origins are explicitly listed they are enforced by exact match, same
//     as in production.
func CORSMiddleware(allowedOrigins []string, env string) gin.HandlerFunc {
	cfg := cors.Config{
		AllowMethods:  []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:  []string{"Authorization", "Content-Type", "X-CSRF-Token"},
		ExposeHeaders: []string{"Content-Length"},
		MaxAge:        24 * time.Hour,
	}

	if len(allowedOrigins) > 0 {
		// Explicit allowlist — credentials are safe to enable.
		cfg.AllowOrigins = allowedOrigins
		cfg.AllowCredentials = true
	} else if env != "production" {
		// Development fallback: permit all origins via wildcard.
		// Credentials must not be set when using AllowAllOrigins (W3C spec).
		cfg.AllowAllOrigins = true
	} else {
		// Production with no allowedOrigins: block all cross-origin requests.
		// Use AllowOriginFunc returning false; gin-contrib/cors requires at least
		// one of AllowAllOrigins / AllowOrigins / AllowOriginFunc to be set.
		cfg.AllowOriginFunc = func(_ string) bool { return false }
	}

	return cors.New(cfg)
}
