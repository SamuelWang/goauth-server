package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupSecurityRouter creates a minimal Gin router with SecurityHeadersMiddleware
// applied globally and a simple GET /test handler registered.
func setupSecurityRouter(env string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(SecurityHeadersMiddleware(env))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func doSecurityRequest(t *testing.T, r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req, err := http.NewRequest(method, path, nil)
	require.NoError(t, err)
	r.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// X-Content-Type-Options
// ---------------------------------------------------------------------------

func TestSecurityHeaders_XContentTypeOptions(t *testing.T) {
	r := setupSecurityRouter("development")
	w := doSecurityRequest(t, r, http.MethodGet, "/test")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
}

// ---------------------------------------------------------------------------
// X-Frame-Options
// ---------------------------------------------------------------------------

func TestSecurityHeaders_XFrameOptions(t *testing.T) {
	r := setupSecurityRouter("development")
	w := doSecurityRequest(t, r, http.MethodGet, "/test")

	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
}

// ---------------------------------------------------------------------------
// X-XSS-Protection
// ---------------------------------------------------------------------------

func TestSecurityHeaders_XXSSProtection(t *testing.T) {
	r := setupSecurityRouter("development")
	w := doSecurityRequest(t, r, http.MethodGet, "/test")

	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
}

// ---------------------------------------------------------------------------
// Content-Security-Policy
// ---------------------------------------------------------------------------

func TestSecurityHeaders_CSP(t *testing.T) {
	r := setupSecurityRouter("development")
	w := doSecurityRequest(t, r, http.MethodGet, "/test")

	assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", w.Header().Get("Content-Security-Policy"))
}

// ---------------------------------------------------------------------------
// Strict-Transport-Security
// ---------------------------------------------------------------------------

// TestSecurityHeaders_HSTS_SetInProduction verifies that HSTS is included
// when the environment is "production".
func TestSecurityHeaders_HSTS_SetInProduction(t *testing.T) {
	r := setupSecurityRouter("production")
	w := doSecurityRequest(t, r, http.MethodGet, "/test")

	hsts := w.Header().Get("Strict-Transport-Security")
	assert.NotEmpty(t, hsts, "HSTS header should be present in production")
	assert.Contains(t, hsts, "max-age=31536000")
	assert.Contains(t, hsts, "includeSubDomains")
}

// TestSecurityHeaders_HSTS_AbsentInDevelopment verifies that HSTS is NOT
// included in non-production environments to avoid locking browsers into
// HTTPS on plain-HTTP dev servers.
func TestSecurityHeaders_HSTS_AbsentInDevelopment(t *testing.T) {
	r := setupSecurityRouter("development")
	w := doSecurityRequest(t, r, http.MethodGet, "/test")

	assert.Empty(t, w.Header().Get("Strict-Transport-Security"),
		"HSTS header must not be set in development")
}

// TestSecurityHeaders_HSTS_AbsentInStaging ensures that staging environments
// (not "production") do not receive HSTS either.
func TestSecurityHeaders_HSTS_AbsentInStaging(t *testing.T) {
	r := setupSecurityRouter("staging")
	w := doSecurityRequest(t, r, http.MethodGet, "/test")

	assert.Empty(t, w.Header().Get("Strict-Transport-Security"),
		"HSTS header must not be set in staging")
}

// ---------------------------------------------------------------------------
// All headers present on POST (not only GET)
// ---------------------------------------------------------------------------

func TestSecurityHeaders_AppliedToAllMethods(t *testing.T) {
	r := setupSecurityRouter("production")
	w := doSecurityRequest(t, r, http.MethodPost, "/test")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
	assert.NotEmpty(t, w.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
}

// ---------------------------------------------------------------------------
// Referrer-Policy
// ---------------------------------------------------------------------------

func TestSecurityHeaders_ReferrerPolicy(t *testing.T) {
	r := setupSecurityRouter("development")
	w := doSecurityRequest(t, r, http.MethodGet, "/test")

	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"),
		"Referrer-Policy must be set to no-referrer to prevent authorization code leakage via Referer header")
}

func TestSecurityHeaders_ReferrerPolicy_SetInProduction(t *testing.T) {
	r := setupSecurityRouter("production")
	w := doSecurityRequest(t, r, http.MethodGet, "/test")

	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

func TestSecurityHeaders_ConstantValues(t *testing.T) {
	assert.Equal(t, "nosniff", xctoValue)
	assert.Equal(t, "DENY", xfoValue)
	assert.Equal(t, "1; mode=block", xxssValue)
	assert.Equal(t, "max-age=31536000; includeSubDomains", hstsValue)
	assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", cspValue)
	assert.Equal(t, "no-referrer", referrerPolicyValue)
}
