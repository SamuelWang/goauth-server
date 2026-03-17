package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupRateLimitRouter creates a minimal Gin router with the given middleware
// applied to GET /test.
func setupRateLimitRouter(mw gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/test", mw, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

// doGet performs a GET /test request against r from IP 192.0.2.1 and returns the recorder.
func doGet(t *testing.T, r *gin.Engine) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	// Set RemoteAddr so Gin's c.ClientIP() returns a consistent address.
	req.RemoteAddr = "192.0.2.1:12345"
	r.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// RateLimitByIP tests
// ---------------------------------------------------------------------------

// TestRateLimitByIP_AllowsBurstRequests verifies that up to `burst` requests
// are permitted immediately.
func TestRateLimitByIP_AllowsBurstRequests(t *testing.T) {
	const burst = 3
	r := setupRateLimitRouter(RateLimitByIP(burst*60, burst)) // rate == burst req/min → each token = 1 s

	for i := 0; i < burst; i++ {
		w := doGet(t, r)
		assert.Equal(t, http.StatusOK, w.Code, "request %d should be allowed", i+1)
	}
}

// TestRateLimitByIP_Blocks429WhenExceeded verifies that the (burst+1)th request
// in a fresh burst window is rejected with 429.
func TestRateLimitByIP_Blocks429WhenExceeded(t *testing.T) {
	const burst = 2
	r := setupRateLimitRouter(RateLimitByIP(burst*60, burst))

	for i := 0; i < burst; i++ {
		doGet(t, r) // exhaust the burst
	}

	w := doGet(t, r)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

// TestRateLimitByIP_RetryAfterHeader verifies that a 429 response includes the
// Retry-After header.
func TestRateLimitByIP_RetryAfterHeader(t *testing.T) {
	r := setupRateLimitRouter(RateLimitByIP(1*60, 1)) // allow exactly 1 req/min, burst 1

	doGet(t, r) // exhaust the single token

	w := doGet(t, r)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"), "Retry-After header should be set on 429")
}

// TestRateLimitByIP_ErrorBody verifies that the JSON error body is present on 429.
func TestRateLimitByIP_ErrorBody(t *testing.T) {
	r := setupRateLimitRouter(RateLimitByIP(1*60, 1))
	doGet(t, r) // exhaust token

	w := doGet(t, r)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "too_many_requests")
}

// TestRateLimitByIP_DifferentIPsHaveSeparateLimits verifies that distinct IPs
// do not share a rate limit bucket.
func TestRateLimitByIP_DifferentIPsHaveSeparateLimits(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/test", RateLimitByIP(1*60, 1), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	sendFrom := func(ip string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		require.NoError(t, err)
		// Use RemoteAddr so Gin's c.ClientIP() picks up the correct IP.
		req.RemoteAddr = ip + ":12345"
		router.ServeHTTP(w, req)
		return w
	}

	// IP-A exhausts its single token.
	sendFrom("10.0.0.1")
	w := sendFrom("10.0.0.1")
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "IP-A should be rate-limited")

	// IP-B still has a fresh bucket.
	w = sendFrom("10.0.0.2")
	assert.Equal(t, http.StatusOK, w.Code, "IP-B should not be affected by IP-A's limit")
}

// ---------------------------------------------------------------------------
// RateLimitByUser tests
// ---------------------------------------------------------------------------

// setupRateLimitByUserRouter creates a router that pre-populates "user_id" in
// the Gin context before the rate limit middleware runs (simulating AuthMiddleware).
func setupRateLimitByUserRouter(userID string, burst int) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/test",
		func(c *gin.Context) {
			if userID != "" {
				c.Set("user_id", userID)
			}
			c.Next()
		},
		RateLimitByUser(burst*60, burst),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)
	return r
}

// TestRateLimitByUser_AllowsBurstRequests verifies that a user can make up to
// burst requests immediately.
func TestRateLimitByUser_AllowsBurstRequests(t *testing.T) {
	const burst = 3
	r := setupRateLimitByUserRouter("user-abc", burst)

	for i := 0; i < burst; i++ {
		w := doGet(t, r)
		assert.Equal(t, http.StatusOK, w.Code, "request %d should be allowed", i+1)
	}
}

// TestRateLimitByUser_Blocks429WhenExceeded verifies that the (burst+1)th
// request from the same user is rejected with 429.
func TestRateLimitByUser_Blocks429WhenExceeded(t *testing.T) {
	const burst = 2
	r := setupRateLimitByUserRouter("user-xyz", burst)

	for i := 0; i < burst; i++ {
		doGet(t, r)
	}

	w := doGet(t, r)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

// TestRateLimitByUser_DifferentUsersHaveSeparateLimits verifies that separate
// user IDs maintain independent rate limit buckets.
func TestRateLimitByUser_DifferentUsersHaveSeparateLimits(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const burst = 1

	makeRouter := func(uid string) *gin.Engine {
		return setupRateLimitByUserRouter(uid, burst)
	}

	rA := makeRouter("user-A")
	doGet(t, rA) // exhaust user-A
	assert.Equal(t, http.StatusTooManyRequests, doGet(t, rA).Code)

	// A different router with a different user – its bucket is fresh.
	rB := makeRouter("user-B")
	assert.Equal(t, http.StatusOK, doGet(t, rB).Code)
}

// TestRateLimitByUser_FallsBackToIPWhenNoUserID verifies that the middleware
// uses the client IP as the key when no "user_id" is present in context.
func TestRateLimitByUser_FallsBackToIPWhenNoUserID(t *testing.T) {
	const burst = 1
	r := setupRateLimitByUserRouter("" /* no user_id */, burst)

	w := doGet(t, r)
	assert.Equal(t, http.StatusOK, w.Code, "first request should be allowed")

	w = doGet(t, r)
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "second request should be rate-limited by IP")
}

// TestRateLimitByUser_RetryAfterHeader verifies the Retry-After header on 429.
func TestRateLimitByUser_RetryAfterHeader(t *testing.T) {
	r := setupRateLimitByUserRouter("user-hdr", 1)
	doGet(t, r)

	w := doGet(t, r)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}

// ---------------------------------------------------------------------------
// Constants sanity check
// ---------------------------------------------------------------------------

// TestRateLimitConstants ensures the exported constants have the expected values
// from the requirements document.
func TestRateLimitConstants(t *testing.T) {
	assert.Equal(t, 10, TokenRatePerMin, "token endpoint: 10 req/min")
	assert.Equal(t, 20, AuthRatePerMin, "auth endpoint: 20 req/min")
	assert.Equal(t, 30, AdminRatePerMin, "admin endpoints: 30 req/min")
}
