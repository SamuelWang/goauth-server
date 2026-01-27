package ops

import (
	"net/http"

	"github.com/SamuelWang/goauth-server/internal/transport/http/ops/handler"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine) {
	opsGroup := r.Group("/ops")

	// Health routes
	{
		opsGroup.GET("/health", handler.HealthCheck)
	}

	r.NoRoute(func(c *gin.Context) {
		// Check if the request path starts with /api
		if len(c.Request.URL.Path) >= 4 && c.Request.URL.Path[0:4] == "/api" {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		} else {
			c.Next()
		}
	})
}
