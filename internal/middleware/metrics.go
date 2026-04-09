package middleware

import (
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/SamuelWang/goauth-server/internal/metrics"
	"github.com/gin-gonic/gin"
)

// MetricsMiddleware records HTTP request count and duration for every request
// using the application-level Prometheus metrics.  It must be registered after
// gin.Recovery() so panics are caught and counted with a 500 status rather than
// causing the process to exit before the metric is recorded.
//
// The "path" label uses Gin's matched route template (e.g.
// "/api/v1/clients/:client_id") rather than the raw URL to avoid high
// cardinality from path parameters containing user-supplied values such as UUIDs.
func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		// Use the matched route template to keep cardinality bounded.
		route := c.FullPath()
		if route == "" {
			// Unmatched routes (404s) are grouped to avoid cardinality explosion
			// from arbitrary URL paths sent by scanners or mis-configured clients.
			route = "unmatched"
		}

		method := c.Request.Method
		status := strconv.Itoa(c.Writer.Status())
		elapsed := time.Since(start).Seconds()

		metrics.HTTPRequestsTotal.WithLabelValues(method, route, status).Inc()
		metrics.HTTPRequestDuration.WithLabelValues(method, route).Observe(elapsed)
	}
}

// MetricsIPAllowlistMiddleware restricts access to the /metrics endpoint to
// the given CIDRs.  CIDRs are parsed once at registration time; any invalid
// entry causes a panic so misconfiguration is caught at startup.
// When allowedCIDRs is empty all callers are permitted (open/default behaviour).
func MetricsIPAllowlistMiddleware(allowedCIDRs []string) gin.HandlerFunc {
	nets := make([]*net.IPNet, 0, len(allowedCIDRs))
	for _, cidr := range allowedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("MetricsIPAllowlistMiddleware: invalid CIDR " + cidr + ": " + err.Error())
		}
		nets = append(nets, network)
	}

	return func(c *gin.Context) {
		if len(nets) == 0 {
			c.Next()
			return
		}

		ip := net.ParseIP(c.ClientIP())
		if ip != nil {
			for _, network := range nets {
				if network.Contains(ip) {
					c.Next()
					return
				}
			}
		}

		c.AbortWithStatus(http.StatusForbidden)
	}
}
