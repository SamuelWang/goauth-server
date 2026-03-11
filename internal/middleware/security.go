package middleware

import (
	"github.com/gin-gonic/gin"
)

// Standard security header values applied to every response.
const (
	// xctoValue prevents browsers from MIME-sniffing the Content-Type of a
	// response, which helps mitigate certain cross-site scripting attacks.
	xctoValue = "nosniff"

	// xfoValue prevents the page from being loaded inside a frame or iframe,
	// mitigating clickjacking attacks.
	xfoValue = "DENY"

	// xxssValue enables the browser's built-in XSS filter and instructs it to
	// block the page when a reflected XSS attack is detected.
	xxssValue = "1; mode=block"

	// hstsValue instructs browsers to always use HTTPS for 1 year (max-age =
	// 31536000 seconds) and to apply the policy to all sub-domains. Applied
	// only in production where TLS is expected.
	hstsValue = "max-age=31536000; includeSubDomains"

	// cspValue is a restrictive Content-Security-Policy suitable for an API /
	// OAuth server. It denies all resource loading by default and prevents
	// embedding in any frame (which reinforces X-Frame-Options: DENY).
	// The server does not serve scripts, styles, images, or fonts from
	// browser contexts, so denying everything is the correct baseline.
	cspValue = "default-src 'none'; frame-ancestors 'none'"

	// referrerPolicyValue instructs browsers not to send a Referer header,
	// preventing sensitive path or query-string information (including
	// authorization codes that may appear in redirect URIs) from being
	// leaked to third-party origins via the Referer header.
	referrerPolicyValue = "no-referrer"
)

// SecurityHeadersMiddleware sets defensive HTTP security headers on every
// response.
//
// Headers set unconditionally:
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - X-XSS-Protection: 1; mode=block
//   - Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
//   - Referrer-Policy: no-referrer
//
// Headers set only in production (where HTTPS is expected):
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains
func SecurityHeadersMiddleware(env string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", xctoValue)
		c.Header("X-Frame-Options", xfoValue)
		c.Header("X-XSS-Protection", xxssValue)
		c.Header("Content-Security-Policy", cspValue)
		c.Header("Referrer-Policy", referrerPolicyValue)

		// HSTS must only be sent over HTTPS; sending it over HTTP would break
		// plain-HTTP access permanently for affected browsers. Restrict to
		// production where TLS is required.
		if env == "production" {
			c.Header("Strict-Transport-Security", hstsValue)
		}

		c.Next()
	}
}
