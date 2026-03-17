package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HealthCheck is the liveness probe endpoint.
//
// @Summary     Health check
// @Description Returns 200 OK when the server is running.
// @Tags        Ops
// @Success     200
// @Router      /ops/health [get]
func HealthCheck(c *gin.Context) {
	// Simple 200 OK for liveness probes
	c.Status(http.StatusOK)
}
