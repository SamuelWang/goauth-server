package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMetricsRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(MetricsMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.GET("/test/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"id": c.Param("id")})
	})
	return r
}

// TestMetricsMiddleware_RecordsMatchedRoute verifies that a request to a
// registered route is processed without errors and returns the expected status.
func TestMetricsMiddleware_RecordsMatchedRoute(t *testing.T) {
	r := setupMetricsRouter()

	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestMetricsMiddleware_RecordsUnmatchedRoute verifies that requests to
// unregistered paths (404) are handled gracefully by the metrics middleware.
func TestMetricsMiddleware_RecordsUnmatchedRoute(t *testing.T) {
	r := setupMetricsRouter()

	req, err := http.NewRequest(http.MethodGet, "/does-not-exist", nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Even though the route is unmatched the middleware should not panic.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestMetricsMiddleware_RecordsParameterisedRoute verifies that a route with
// path parameters is processed correctly.
func TestMetricsMiddleware_RecordsParameterisedRoute(t *testing.T) {
	r := setupMetricsRouter()

	req, err := http.NewRequest(http.MethodGet, "/test/abc-123", nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
