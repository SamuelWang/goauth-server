package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func HealthCheck(c *gin.Context) {
	// Simple 200 OK for liveness probes
	c.Status(http.StatusOK)
}
