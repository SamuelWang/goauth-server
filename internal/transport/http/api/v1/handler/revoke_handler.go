package handler

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Revoke handles POST /api/v1/auth/revoke per RFC 7009.
//
// The caller authenticates via HTTP Basic credentials (client_id:client_secret)
// OR a Bearer access token.  Per RFC 7009 §2.2, the server MUST respond with
// HTTP 200 for both successful revocations and unknown tokens; 401 is the only
// status code returned on authentication failure.
//
// @Summary     Revoke a token (RFC 7009)
// @Description Revokes a refresh token or access token. Returns 200 in all cases
// @Description except unauthenticated requests (401). Linked tokens are also revoked.
// @Tags        Auth
// @Accept      application/x-www-form-urlencoded
// @Produce     json
// @Param       Authorization    header    string  false  "HTTP Basic (client) or Bearer (user) auth"
// @Param       token            formData  string  true   "Token value to revoke"
// @Param       token_type_hint  formData  string  false  "refresh_token or access_token"
// @Success     200
// @Failure     401  {object}  handler.ErrorResponse
// @Router      /api/v1/auth/revoke [post]
func (h *ApiV1Handler) Revoke(c *gin.Context) {
	// Step 1 — Authenticate the caller.
	// Accept HTTP Basic (client_id:client_secret) OR Bearer access token.
	// 401 is the ONLY error code permitted for auth failure per RFC 7009.
	if !h.authenticateRevokeRequest(c) {
		// Response already written by authenticateRevokeRequest.
		return
	}

	// Step 2 — Extract token and hint from the form-encoded body.
	// RFC 7009 §2.1: body must be application/x-www-form-urlencoded.
	if err := c.Request.ParseForm(); err != nil {
		// Malformed body — RFC 7009 §2.2.1 allows 400 for unsupported params, but
		// returning 200 avoids leaking information while staying compliant for the
		// common case.
		c.Status(http.StatusOK)
		return
	}
	tokenValue := c.Request.FormValue("token")
	if tokenValue == "" {
		// Missing token — treat as unknown and return 200 per RFC 7009 §2.2.
		c.Status(http.StatusOK)
		return
	}
	tokenTypeHint := c.Request.FormValue("token_type_hint")

	// Step 3 — Delegate revocation to the auth service.
	// RevokeAnyToken returns nil for both successful revocations and unknown tokens.
	if err := h.authService.RevokeAnyToken(c.Request.Context(), tokenValue, tokenTypeHint); err != nil {
		log.Printf("Revoke: unexpected error: %v", err)
		// RFC 7009 §2.2 does not define a 500 response; return 200 to avoid leaking
		// internal state while not silently masking the problem (it is logged above).
	}

	c.Status(http.StatusOK)
}

// authenticateRevokeRequest validates the caller's identity using either HTTP
// Basic authentication (client_id:client_secret) or a Bearer access token.
// Returns true when authentication succeeds; writes a 401 response and returns
// false otherwise.
func (h *ApiV1Handler) authenticateRevokeRequest(c *gin.Context) bool {
	// net/http's BasicAuth() parses the Authorization: Basic <base64> header.
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if ok {
		valid, err := h.authService.ValidateClientCredentials(c.Request.Context(), clientID, clientSecret)
		if err != nil {
			log.Printf("Revoke: validating client credentials: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return false
		}
		if !valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return false
		}
		return true
	}

	// Fall back to Bearer token authentication.
	if bearerToken := extractBearerToken(c); bearerToken != "" {
		if _, err := h.authService.ValidateAccessToken(bearerToken); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return false
		}
		return true
	}

	c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	return false
}

// extractBearerToken returns the token value from an "Authorization: Bearer
// <token>" header, or an empty string when the header is absent or malformed.
func extractBearerToken(c *gin.Context) string {
	const prefix = "Bearer "
	v := c.GetHeader("Authorization")
	if len(v) > len(prefix) && v[:len(prefix)] == prefix {
		return v[len(prefix):]
	}
	return ""
}
