package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	// CSRFCookieName is the name of the cookie that holds the CSRF token.
	// HttpOnly is deliberately false so that browser JavaScript can read
	// the value and echo it back in the X-CSRF-Token request header.
	CSRFCookieName = "csrf_token"

	// CSRFHeaderName is the request header the client must send on every
	// state-changing request (POST, PUT, PATCH, DELETE).
	CSRFHeaderName = "X-CSRF-Token"

	csrfTokenBytes   = 32
	csrfCookieMaxAge = 3600 // 1 hour
)

// CSRFMiddleware implements the double-submit cookie pattern.
//
// On every request the middleware ensures that a csrf_token cookie is present;
// if one does not exist it generates a new cryptographically random token and
// sets the cookie.
//
// On state-changing requests (POST, PUT, PATCH, DELETE) it validates that
// the value of the X-CSRF-Token request header matches the csrf_token cookie.
// Mismatches are rejected with HTTP 403.
//
// The Secure attribute of the cookie is derived from the "cookie_secure"
// value stored in the Gin context by ContextMiddleware.
//
// OAuth callbacks do not require this middleware because they use the state
// parameter for CSRF protection. The token exchange endpoint is also exempt
// because client_secret serves as the equivalent CSRF defence for that flow.
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Read the existing CSRF token from the cookie.
		cookieToken, err := c.Cookie(CSRFCookieName)
		if err != nil || cookieToken == "" {
			cookieToken, err = generateCSRFToken()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":             "internal_server_error",
					"error_description": "failed to generate CSRF token",
				})
				c.Abort()
				return
			}
		}

		secure := getCookieSecureFromCtx(c)

		// Refresh/set the CSRF token cookie.
		// SameSite=Lax prevents the cookie from being sent on cross-site
		// requests initiated by third-party pages, which provides a second
		// layer of CSRF protection on top of the double-submit check.
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(
			CSRFCookieName,
			cookieToken,
			csrfCookieMaxAge,
			"/",
			"",
			secure,
			false, // HttpOnly=false: JS must be able to read the value.
		)

		// Validate state-changing requests.
		switch c.Request.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			headerToken := c.GetHeader(CSRFHeaderName)
			if headerToken == "" || !secureCompare(headerToken, cookieToken) {
				c.JSON(http.StatusForbidden, gin.H{
					"error":             "forbidden",
					"error_description": "invalid or missing CSRF token",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// generateCSRFToken returns a cryptographically random hex-encoded token.
func generateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// secureCompare performs a constant-time string comparison to prevent
// timing-based side-channel attacks.
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	// XOR all bytes; result is 0 only when all bytes are equal.
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// getCookieSecureFromCtx reads the cookie_secure flag set by ContextMiddleware.
func getCookieSecureFromCtx(c *gin.Context) bool {
	if val, exists := c.Get("cookie_secure"); exists {
		if secure, ok := val.(bool); ok {
			return secure
		}
	}
	return false
}
