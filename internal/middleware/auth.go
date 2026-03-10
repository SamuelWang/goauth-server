package middleware

import (
	"log"
	"net/http"
	"strings"

	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/gin-gonic/gin"
)

// AuthMiddleware validates an access token and populates user context.
// It accepts the token from either an "Authorization: Bearer <token>" header
// or an "access_token" cookie. The raw token string is stored under the
// "raw_token" context key so that handlers (e.g. logout) can revoke it.
func AuthMiddleware(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var token string

		// Prefer the Authorization header; fall back to the cookie.
		if authHeader := c.GetHeader("Authorization"); authHeader != "" {
			if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "bearer ") {
				token = authHeader[7:]
			} else {
				util.LogAuthFailure(c.ClientIP(), c.GetString("request_id"), "", "malformed authorization header")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - malformed authorization header"})
				c.Abort()
				return
			}
		} else {
			var err error
			token, err = c.Cookie("access_token")
			if err != nil {
				util.LogAuthFailure(c.ClientIP(), c.GetString("request_id"), "", "missing token")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - no token"})
				c.Abort()
				return
			}
		}

		// Validate the token signature and expiry.
		claims, err := authService.ValidateAccessToken(token)
		if err != nil {
			log.Printf("Invalid token: %v", err)
			util.LogAuthFailure(c.ClientIP(), c.GetString("request_id"), "", "invalid token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - invalid token"})
			c.Abort()
			return
		}

		// Check whether the token has been revoked in the database.
		isRevoked, err := authService.IsTokenRevoked(c.Request.Context(), token)
		if err != nil {
			log.Printf("AuthMiddleware: revocation check failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			c.Abort()
			return
		}
		if isRevoked {
			util.LogAuthFailure(c.ClientIP(), c.GetString("request_id"), claims.UserID, "token revoked")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized - token has been revoked"})
			c.Abort()
			return
		}

		// Store the raw token so handlers can revoke it (e.g. logout).
		c.Set("raw_token", token)
		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)

		c.Next()
	}
}
