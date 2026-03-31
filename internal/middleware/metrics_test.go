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

// ---------------------------------------------------------------------------
// MetricsIPAllowlistMiddleware tests
// ---------------------------------------------------------------------------

func setupAllowlistRouter(cidrs []string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/metrics", MetricsIPAllowlistMiddleware(cidrs), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return r
}

// TestMetricsIPAllowlistMiddleware_NoCIDRsAllowsAll verifies that when no CIDRs
// are configured the endpoint is accessible from any IP.
func TestMetricsIPAllowlistMiddleware_NoCIDRsAllowsAll(t *testing.T) {
	r := setupAllowlistRouter(nil)

	req, err := http.NewRequest(http.MethodGet, "/metrics", nil)
	require.NoError(t, err)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestMetricsIPAllowlistMiddleware_AllowedIP verifies that a request from an
// IP within the configured CIDR is permitted.
func TestMetricsIPAllowlistMiddleware_AllowedIP(t *testing.T) {
	r := setupAllowlistRouter([]string{"10.0.0.0/8"})

	req, err := http.NewRequest(http.MethodGet, "/metrics", nil)
	require.NoError(t, err)
	req.RemoteAddr = "10.1.2.3:12345"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestMetricsIPAllowlistMiddleware_DeniedIP verifies that a request from an IP
// outside all configured CIDRs receives 403 Forbidden.
func TestMetricsIPAllowlistMiddleware_DeniedIP(t *testing.T) {
	r := setupAllowlistRouter([]string{"10.0.0.0/8"})

	req, err := http.NewRequest(http.MethodGet, "/metrics", nil)
	require.NoError(t, err)
	req.RemoteAddr = "203.0.113.1:12345"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestMetricsIPAllowlistMiddleware_MultipleCIDRs verifies that any IP matching
// one of several configured CIDRs is permitted.
func TestMetricsIPAllowlistMiddleware_MultipleCIDRs(t *testing.T) {
	r := setupAllowlistRouter([]string{"10.0.0.0/8", "172.16.0.0/12"})

	for _, ip := range []string{"10.0.0.1", "172.20.0.5"} {
		req, err := http.NewRequest(http.MethodGet, "/metrics", nil)
		require.NoError(t, err)
		req.RemoteAddr = ip + ":12345"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "expected 200 for IP %s", ip)
	}

	// IP outside both ranges.
	req, err := http.NewRequest(http.MethodGet, "/metrics", nil)
	require.NoError(t, err)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestMetricsIPAllowlistMiddleware_InvalidCIDRPanics verifies that registering
// the middleware with a malformed CIDR panics at startup.
func TestMetricsIPAllowlistMiddleware_InvalidCIDRPanics(t *testing.T) {
	assert.Panics(t, func() {
		MetricsIPAllowlistMiddleware([]string{"not-a-cidr"})
	})
}
