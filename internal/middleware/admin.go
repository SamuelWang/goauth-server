package middleware

import (
	"log"
	"net/http"

	"github.com/SamuelWang/goauth-server/internal/metrics"
	"github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AdminMiddleware verifies that the authenticated user has admin privileges.
// It must be used after AuthMiddleware, which populates "user_id" in the context.
func AdminMiddleware(userService *user.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		rawID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		userID, err := uuid.Parse(rawID.(string))
		if err != nil {
			log.Printf("AdminMiddleware: invalid user_id format: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		isAdmin, err := userService.IsAdmin(c.Request.Context(), userID)
		if err != nil {
			log.Printf("AdminMiddleware: error checking admin status: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			c.Abort()
			return
		}

		if !isAdmin {
			util.LogAdminAccessDenied(c.ClientIP(), c.GetString("request_id"), rawID.(string), c.Request.URL.Path)
			metrics.AdminAccessDeniedTotal.Inc()
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			c.Abort()
			return
		}

		c.Next()
	}
}
