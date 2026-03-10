package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupCSRFRouter creates a minimal Gin router with ContextMiddleware (to set
// cookie_secure) followed by CSRFMiddleware applied to all routes. A GET and a
// POST handler are registered at /test.
func setupCSRFRouter(env string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Simulate ContextMiddleware so CSRFMiddleware can read "cookie_secure".
	r.Use(func(c *gin.Context) {
		cookieSecure := env == "production"
		c.Set("cookie_secure", cookieSecure)
		c.Set("env", env)
		c.Next()
	})
	r.Use(CSRFMiddleware())

	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.PATCH("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.DELETE("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

// csrfTokenFromResponse extracts the csrf_token cookie value from a response.
func csrfTokenFromResponse(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	for _, raw := range w.Result().Cookies() {
		if raw.Name == CSRFCookieName {
			return raw.Value
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Cookie issuance
// ---------------------------------------------------------------------------

// TestCSRF_GETSetsCSRFCookie verifies that a GET request causes the middleware
// to set a non-empty csrf_token cookie.
func TestCSRF_GETSetsCSRFCookie(t *testing.T) {
	r := setupCSRFRouter("development")
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	token := csrfTokenFromResponse(t, w)
	assert.NotEmpty(t, token, "csrf_token cookie should be set on GET")
}

// TestCSRF_CookieIsNotHttpOnly verifies that the csrf_token cookie is NOT
// HttpOnly (JS must be able to read it for the double-submit pattern).
func TestCSRF_CookieIsNotHttpOnly(t *testing.T) {
	r := setupCSRFRouter("development")
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	r.ServeHTTP(w, req)

	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == CSRFCookieName {
			found = true
			assert.False(t, c.HttpOnly, "csrf_token cookie must NOT be HttpOnly")
		}
	}
	assert.True(t, found, "csrf_token cookie should be present")
}

// TestCSRF_CookieIsSecureInProduction verifies that the Secure flag is set
// when the environment is production.
func TestCSRF_CookieIsSecureInProduction(t *testing.T) {
	r := setupCSRFRouter("production")
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	r.ServeHTTP(w, req)

	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == CSRFCookieName {
			found = true
			assert.True(t, c.Secure, "csrf_token cookie should be Secure in production")
		}
	}
	assert.True(t, found)
}

// TestCSRF_CookieIsNotSecureInDevelopment verifies that the Secure flag is NOT
// set when the environment is development.
func TestCSRF_CookieIsNotSecureInDevelopment(t *testing.T) {
	r := setupCSRFRouter("development")
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	r.ServeHTTP(w, req)

	for _, c := range w.Result().Cookies() {
		if c.Name == CSRFCookieName {
			assert.False(t, c.Secure, "csrf_token cookie should NOT be Secure in development")
			return
		}
	}
	t.Fatal("csrf_token cookie not found")
}

// TestCSRF_ExistingCookieIsReused verifies that when a valid csrf_token cookie
// is already present, the middleware reuses it rather than generating a new one.
func TestCSRF_ExistingCookieIsReused(t *testing.T) {
	r := setupCSRFRouter("development")

	// First request: obtain a token.
	w1 := httptest.NewRecorder()
	req1, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	r.ServeHTTP(w1, req1)
	firstToken := csrfTokenFromResponse(t, w1)
	require.NotEmpty(t, firstToken)

	// Second request with the cookie set.
	w2 := httptest.NewRecorder()
	req2, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	req2.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: firstToken})
	r.ServeHTTP(w2, req2)

	secondToken := csrfTokenFromResponse(t, w2)
	assert.Equal(t, firstToken, secondToken, "existing csrf_token should be reused")
}

// ---------------------------------------------------------------------------
// State-changing request validation
// ---------------------------------------------------------------------------

// TestCSRF_POSTWithValidTokenSucceeds verifies that a POST with a matching
// X-CSRF-Token header is allowed.
func TestCSRF_POSTWithValidTokenSucceeds(t *testing.T) {
	r := setupCSRFRouter("development")

	token := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "/test", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	req.Header.Set(CSRFHeaderName, token)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestCSRF_POSTWithoutTokenReturns403 verifies that a POST missing the
// X-CSRF-Token header is rejected with 403.
func TestCSRF_POSTWithoutTokenReturns403(t *testing.T) {
	r := setupCSRFRouter("development")

	token := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "/test", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	// No X-CSRF-Token header.
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "invalid or missing CSRF token")
}

// TestCSRF_POSTWithMismatchedTokenReturns403 verifies that a token mismatch
// between the cookie and the header yields 403.
func TestCSRF_POSTWithMismatchedTokenReturns403(t *testing.T) {
	r := setupCSRFRouter("development")

	cookieToken := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	headerToken := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "/test", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: cookieToken})
	req.Header.Set(CSRFHeaderName, headerToken)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestCSRF_PATCHWithValidTokenSucceeds verifies PATCH is also covered.
func TestCSRF_PATCHWithValidTokenSucceeds(t *testing.T) {
	r := setupCSRFRouter("development")
	token := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPatch, "/test", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	req.Header.Set(CSRFHeaderName, token)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestCSRF_DELETEWithValidTokenSucceeds verifies DELETE is also covered.
func TestCSRF_DELETEWithValidTokenSucceeds(t *testing.T) {
	r := setupCSRFRouter("development")
	token := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodDelete, "/test", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	req.Header.Set(CSRFHeaderName, token)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestCSRF_DELETEWithoutCookieReturns403 verifies that a DELETE with no
// cookie (hence no expected token) is rejected.
func TestCSRF_DELETEWithoutCookieReturns403(t *testing.T) {
	r := setupCSRFRouter("development")

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodDelete, "/test", nil)
	require.NoError(t, err)
	// Sends a header token but no cookie — the middleware generates a NEW
	// random token for the cookie, so header won't match.
	req.Header.Set(CSRFHeaderName, "sometoken")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestCSRF_GETDoesNotRequireToken verifies that GET requests are never blocked
// even when no CSRF header is present.
func TestCSRF_GETDoesNotRequireToken(t *testing.T) {
	r := setupCSRFRouter("development")

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	// No cookie, no header.
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// secureCompare
// ---------------------------------------------------------------------------

// TestSecureCompare verifies constant-time comparison behaviour.
func TestSecureCompare_EqualStrings(t *testing.T) {
	assert.True(t, secureCompare("abcdef", "abcdef"))
}

func TestSecureCompare_UnequalStrings(t *testing.T) {
	assert.False(t, secureCompare("abcdef", "abcdeg"))
}

func TestSecureCompare_DifferentLengths(t *testing.T) {
	assert.False(t, secureCompare("abc", "abcd"))
}

func TestSecureCompare_EmptyStrings(t *testing.T) {
	assert.True(t, secureCompare("", ""))
}
