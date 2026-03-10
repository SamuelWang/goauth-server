package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupCORSRouter creates a minimal Gin router with CORSMiddleware applied
// globally and a simple GET /test handler registered.
func setupCORSRouter(allowedOrigins []string, env string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORSMiddleware(allowedOrigins, env))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

// doCORSRequest sends a request with the given method, origin, and optional
// Access-Control-Request-Method (used in preflight).
func doCORSRequest(t *testing.T, r *gin.Engine, method, path, origin, requestMethod string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req, err := http.NewRequest(method, path, nil)
	require.NoError(t, err)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if requestMethod != "" {
		req.Header.Set("Access-Control-Request-Method", requestMethod)
	}
	r.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// Non-cross-origin requests
// ---------------------------------------------------------------------------

// TestCORS_NoOriginHeader verifies that requests without an Origin header are
// passed through untouched (no CORS headers set).
func TestCORS_NoOriginHeader(t *testing.T) {
	r := setupCORSRouter([]string{"https://example.com"}, "production")
	w := doCORSRequest(t, r, http.MethodGet, "/test", "", "")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

// ---------------------------------------------------------------------------
// Development (non-production) with no origins configured
// ---------------------------------------------------------------------------

// TestCORS_DevWildcard_AllowsAnyOrigin verifies wildcard behaviour in dev
// when no origins are configured.
func TestCORS_DevWildcard_AllowsAnyOrigin(t *testing.T) {
	r := setupCORSRouter(nil, "development")
	w := doCORSRequest(t, r, http.MethodGet, "/test", "http://localhost:3000", "")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	// Credentials MUST NOT be set when using wildcard (W3C spec).
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
}

// TestCORS_ProductionNoOrigins_BlocksAllCrossOrigin confirms that in production
// the wildcard fallback is disabled and cross-origin requests are rejected with 403.
func TestCORS_ProductionNoOrigins_BlocksAllCrossOrigin(t *testing.T) {
	r := setupCORSRouter(nil, "production")
	w := doCORSRequest(t, r, http.MethodGet, "/test", "https://attacker.example.com", "")

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

// ---------------------------------------------------------------------------
// Allowlist (both dev and prod)
// ---------------------------------------------------------------------------

// TestCORS_AllowlistedOrigin_SetsSpecificOriginAndCredentials verifies that an
// allowed origin receives an exact-match Access-Control-Allow-Origin header and
// the credentials flag.
func TestCORS_AllowlistedOrigin_SetsSpecificOriginAndCredentials(t *testing.T) {
	origins := []string{"https://app.example.com", "https://admin.example.com"}
	r := setupCORSRouter(origins, "production")
	w := doCORSRequest(t, r, http.MethodGet, "/test", "https://app.example.com", "")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}

// TestCORS_NonAllowlistedOrigin_Rejected verifies that an origin NOT in the
// allowlist is actively rejected with 403 in production.
func TestCORS_NonAllowlistedOrigin_Rejected(t *testing.T) {
	r := setupCORSRouter([]string{"https://app.example.com"}, "production")
	w := doCORSRequest(t, r, http.MethodGet, "/test", "https://evil.example.com", "")

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
}

// TestCORS_NonAllowlistedOrigin_DevEnv_AlsoRejected verifies that an explicit
// allowlist is enforced even in dev mode and disallowed origins get 403.
func TestCORS_NonAllowlistedOrigin_DevEnv_AlsoRejected(t *testing.T) {
	r := setupCORSRouter([]string{"https://app.example.com"}, "development")
	w := doCORSRequest(t, r, http.MethodGet, "/test", "http://other.local", "")

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

// ---------------------------------------------------------------------------
// Preflight (OPTIONS) requests
// ---------------------------------------------------------------------------

// TestCORS_Preflight_AllowedOrigin_Returns204 verifies that a preflight from an
// allowed origin receives 204 with all CORS headers.
func TestCORS_Preflight_AllowedOrigin_Returns204(t *testing.T) {
	r := setupCORSRouter([]string{"https://app.example.com"}, "production")
	w := doCORSRequest(t, r, http.MethodOptions, "/test", "https://app.example.com", "POST")

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Methods"))
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Headers"))
	assert.Equal(t, "86400", w.Header().Get("Access-Control-Max-Age"))
}

// TestCORS_Preflight_DisallowedOrigin_Returns403 verifies that a preflight from
// a disallowed origin is rejected with 403.
func TestCORS_Preflight_DisallowedOrigin_Returns403(t *testing.T) {
	r := setupCORSRouter([]string{"https://app.example.com"}, "production")
	w := doCORSRequest(t, r, http.MethodOptions, "/test", "https://evil.com", "POST")

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

// TestCORS_Preflight_DevWildcard_Returns204 verifies that a dev-mode preflight
// with no origin list configured returns 204 with the wildcard.
func TestCORS_Preflight_DevWildcard_Returns204(t *testing.T) {
	r := setupCORSRouter(nil, "development")
	w := doCORSRequest(t, r, http.MethodOptions, "/test", "http://localhost:5173", "GET")

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
}

// TestCORS_Preflight_ProductionNoOrigins_Returns403 verifies that a preflight
// in production with no allowlist configured is rejected.
func TestCORS_Preflight_ProductionNoOrigins_Returns403(t *testing.T) {
	r := setupCORSRouter(nil, "production")
	w := doCORSRequest(t, r, http.MethodOptions, "/test", "https://app.example.com", "POST")

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------------------------------------------------------------------------
// Specific header checks
// ---------------------------------------------------------------------------

// TestCORS_ExposeHeaders verifies Access-Control-Expose-Headers is included.
func TestCORS_ExposeHeaders(t *testing.T) {
	r := setupCORSRouter([]string{"https://app.example.com"}, "production")
	w := doCORSRequest(t, r, http.MethodGet, "/test", "https://app.example.com", "")

	assert.Equal(t, "Content-Length", w.Header().Get("Access-Control-Expose-Headers"))
}
