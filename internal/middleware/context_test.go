package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestContextMiddleware_ProductionEnvironment(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Env:    "production",
			Scheme: "https",
		},
	}

	var capturedEnv string
	var capturedCookieSecure bool

	router.Use(ContextMiddleware(cfg))
	router.GET("/test", func(c *gin.Context) {
		env, _ := c.Get("env")
		capturedEnv = env.(string)

		cookieSecure, _ := c.Get("cookie_secure")
		capturedCookieSecure = cookieSecure.(bool)

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Execute
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "production", capturedEnv)
	assert.True(t, capturedCookieSecure, "cookie_secure should be true in production")
}

func TestContextMiddleware_DevelopmentEnvironment(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Env:    "development",
			Scheme: "http",
		},
	}

	var capturedEnv string
	var capturedCookieSecure bool

	router.Use(ContextMiddleware(cfg))
	router.GET("/test", func(c *gin.Context) {
		env, _ := c.Get("env")
		capturedEnv = env.(string)

		cookieSecure, _ := c.Get("cookie_secure")
		capturedCookieSecure = cookieSecure.(bool)

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Execute
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "development", capturedEnv)
	assert.False(t, capturedCookieSecure, "cookie_secure should be false in development with http")
}

func TestContextMiddleware_DevelopmentWithHTTPS(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Env:    "development",
			Scheme: "https",
		},
	}

	var capturedCookieSecure bool

	router.Use(ContextMiddleware(cfg))
	router.GET("/test", func(c *gin.Context) {
		cookieSecure, _ := c.Get("cookie_secure")
		capturedCookieSecure = cookieSecure.(bool)

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Execute
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, capturedCookieSecure, "cookie_secure should be true when scheme is https")
}

func TestContextMiddleware_StagingEnvironment(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Env:    "staging",
			Scheme: "https",
		},
	}

	var capturedEnv string
	var capturedCookieSecure bool

	router.Use(ContextMiddleware(cfg))
	router.GET("/test", func(c *gin.Context) {
		env, _ := c.Get("env")
		capturedEnv = env.(string)

		cookieSecure, _ := c.Get("cookie_secure")
		capturedCookieSecure = cookieSecure.(bool)

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Execute
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "staging", capturedEnv)
	assert.True(t, capturedCookieSecure, "cookie_secure should be true when scheme is https")
}

func TestContextMiddleware_ContinuesRequestChain(t *testing.T) {
	// Setup
	router := setupTestRouter()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Env:    "test",
			Scheme: "http",
		},
	}

	var handlerCalled bool

	router.Use(ContextMiddleware(cfg))
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Execute
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert
	assert.True(t, handlerCalled, "Handler should be called after middleware")
	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// X-Request-ID sanitization
// ---------------------------------------------------------------------------

func TestContextMiddleware_RequestID_ValidHeaderAccepted(t *testing.T) {
	router := setupTestRouter()
	cfg := &config.Config{Server: config.ServerConfig{Env: "development", Scheme: "http"}}

	var capturedID string
	router.Use(ContextMiddleware(cfg))
	router.GET("/test", func(c *gin.Context) {
		capturedID = c.GetString("request_id")
		c.JSON(http.StatusOK, gin.H{})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Request-ID", "abc-123_XYZ")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, "abc-123_XYZ", capturedID, "valid request IDs should be propagated")
	assert.Equal(t, "abc-123_XYZ", w.Header().Get("X-Request-ID"))
}

func TestContextMiddleware_RequestID_MaliciousHeaderReplaced(t *testing.T) {
	router := setupTestRouter()
	cfg := &config.Config{Server: config.ServerConfig{Env: "development", Scheme: "http"}}

	var capturedID string
	router.Use(ContextMiddleware(cfg))
	router.GET("/test", func(c *gin.Context) {
		capturedID = c.GetString("request_id")
		c.JSON(http.StatusOK, gin.H{})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// Attempt log injection via control characters / JSON payload in the header.
	req.Header.Set("X-Request-ID", `{"injected":"payload"}\n`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// The middleware must generate a fresh UUID, not echo the malicious value.
	assert.NotEqual(t, `{"injected":"payload"}\n`, capturedID, "malicious request IDs must be replaced")
	assert.NotEmpty(t, capturedID)
}

func TestContextMiddleware_RequestID_TooLongReplaced(t *testing.T) {
	router := setupTestRouter()
	cfg := &config.Config{Server: config.ServerConfig{Env: "development", Scheme: "http"}}

	var capturedID string
	router.Use(ContextMiddleware(cfg))
	router.GET("/test", func(c *gin.Context) {
		capturedID = c.GetString("request_id")
		c.JSON(http.StatusOK, gin.H{})
	})

	tooLong := "a"
	for i := 0; i < 65; i++ {
		tooLong += "a"
	}
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Request-ID", tooLong)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.NotEqual(t, tooLong, capturedID, "oversized request IDs must be replaced")
	assert.NotEmpty(t, capturedID)
}

func TestContextMiddleware_RequestID_GeneratedWhenMissing(t *testing.T) {
	router := setupTestRouter()
	cfg := &config.Config{Server: config.ServerConfig{Env: "development", Scheme: "http"}}

	var capturedID string
	router.Use(ContextMiddleware(cfg))
	router.GET("/test", func(c *gin.Context) {
		capturedID = c.GetString("request_id")
		c.JSON(http.StatusOK, gin.H{})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.NotEmpty(t, capturedID, "a request ID must be generated when the header is absent")
	assert.Equal(t, capturedID, w.Header().Get("X-Request-ID"))
}
