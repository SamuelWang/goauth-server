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
