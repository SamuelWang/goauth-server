package ops

import (
	"net/http"

	"github.com/SamuelWang/goauth-server/internal/metrics"
	"github.com/SamuelWang/goauth-server/internal/transport/http/ops/handler"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func RegisterRoutes(r *gin.Engine) {
	opsGroup := r.Group("/ops")

	// Health routes
	{
		opsGroup.GET("/health", handler.HealthCheck)
	}

	// Prometheus metrics endpoint — served directly from the app-level registry
	// so it is scoped only to this service's metrics (not the default global
	// registry used by third-party libraries).
	r.GET("/metrics", gin.WrapH(promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{})))
	r.NoRoute(func(c *gin.Context) {
		// Check if the request path starts with /api
		if len(c.Request.URL.Path) >= 4 && c.Request.URL.Path[0:4] == "/api" {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		} else {
			c.Next()
		}
	})
}
