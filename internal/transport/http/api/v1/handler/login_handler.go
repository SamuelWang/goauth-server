package handler

import (
	"errors"
	"log"
	"net/http"
	"net/mail"
	"strings"

	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/gin-gonic/gin"
)

// Login handles POST /api/v1/auth/login — direct username/password authentication
// with account lockout enforcement.
//
// On success with force_password_change=false: returns an access token.
// On success with force_password_change=true: returns {"require":"password_change"}
// (T7.4 will extend this to return a challenge token).
//
// @Summary     Direct login with email and password
// @Description Authenticates a user with email + password. Subject to rate limiting and account lockout.
// @Tags        Auth
// @Accept      json
// @Produce     json
// @Param       body  body      handler.LoginRequest  true  "Login credentials"
// @Success     200  {object}  handler.LoginResponse
// @Failure     400  {object}  handler.ErrorResponse
// @Failure     401  {object}  handler.ErrorResponse
// @Failure     429  {object}  handler.ErrorResponse
// @Failure     500  {object}  handler.ErrorResponse
// @Router      /api/v1/auth/login [post]
func (h *ApiV1Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	if _, err := mail.ParseAddress(req.Email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "email is not a valid email address"})
		return
	}

	// Extract the real client IP for lockout tracking and audit logging.
	sourceIP := extractSourceIP(c)

	result, err := h.authService.VerifyCredentials(c.Request.Context(), req.Email, req.Password, sourceIP)
	if err != nil {
		if errors.Is(err, auth.ErrAccountLocked) {
			retryAfter := ""
			if result != nil && result.LockedUntil != nil {
				retryAfter = result.LockedUntil.UTC().Format(http.TimeFormat)
			}
			c.Header("Retry-After", retryAfter)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "account_locked",
				"retry_after": retryAfter,
			})
			return
		}
		if errors.Is(err, auth.ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
			return
		}
		log.Printf("Login: unexpected error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Users flagged for a forced password change receive a short-lived challenge
	// token instead of an access token. The challenge token must be exchanged via
	// POST /api/v1/auth/change-password before a regular access token is issued.
	if result.ForcePasswordChange {
		challengeToken, err := h.authService.GenerateChallengeToken(result.User.ID)
		if err != nil {
			log.Printf("Login: generating challenge token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"challenge_token": challengeToken,
			"require":         "password_change",
		})
		return
	}

	tokenStr, err := h.authService.GenerateAccessToken(result.User.ID.String(), result.User.Email)
	if err != nil {
		log.Printf("Login: generating access token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	if err := h.authService.StoreDirectLoginToken(c.Request.Context(), tokenStr, result.User.ID); err != nil {
		log.Printf("Login: storing access token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken: tokenStr,
		TokenType:   "Bearer",
		ExpiresIn:   int64(h.authService.Expiry().Seconds()),
	})
}

// extractSourceIP returns the real client IP address. It checks
// X-Forwarded-For first (uses the first hop only) and falls back to
// RemoteAddr from the raw request.
func extractSourceIP(c *gin.Context) string {
	if fwd := c.GetHeader("X-Forwarded-For"); fwd != "" {
		if ip := strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0]); ip != "" {
			return ip
		}
	}
	return c.Request.RemoteAddr
}
