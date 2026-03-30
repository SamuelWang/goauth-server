package handler

import (
	"errors"
	"log"
	"net/http"

	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/gin-gonic/gin"
)

// ChangePassword handles POST /api/v1/auth/change-password.
//
// This endpoint is the second step of the force-password-change flow. The caller
// supplies the challenge_token received from POST /api/v1/auth/login (when
// force_password_change is true) together with the desired new password. On
// success the force_password_change flag is cleared and a new access token is
// returned, allowing the user to proceed normally.
//
// The challenge token acts as the authentication credential for this endpoint;
// no Authorization header is required.
//
// @Summary     Exchange challenge token for a new password
// @Description Completes the force-password-change flow. Validates the challenge
// @Description token and the new password, persists the password change, and
// @Description issues a new access token.
// @Tags        Auth
// @Accept      json
// @Produce     json
// @Param       body  body      handler.ChangePasswordRequest  true  "Change password request"
// @Success     200  {object}  handler.LoginResponse
// @Failure     400  {object}  handler.ErrorResponse
// @Failure     409  {object}  handler.ErrorResponse
// @Failure     500  {object}  handler.ErrorResponse
// @Router      /api/v1/auth/change-password [post]
func (h *ApiV1Handler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	// 1. Validate challenge token and extract user ID.
	userID, err := h.authService.ValidateChallengeToken(req.ChallengeToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_challenge_token", "error_description": err.Error()})
		return
	}

	// 2. Perform the password change (validates policy, hashes, persists, audits).
	result, err := h.authService.ChangePassword(c.Request.Context(), userID, req.NewPassword)
	if err != nil {
		if errors.Is(err, auth.ErrForcePasswordChangeSatisfied) {
			c.JSON(http.StatusConflict, gin.H{"error": "password_change_already_satisfied"})
			return
		}
		if errors.Is(err, auth.ErrUserNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_challenge_token", "error_description": "user not found"})
			return
		}
		// Password policy validation errors are returned as plain error messages.
		// They are user-visible (non-sensitive) so pass them through directly.
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_new_password", "error_description": err.Error()})
		return
	}

	// 3. Issue a new access token now that the password has been updated.
	tokenStr, err := h.authService.GenerateAccessToken(result.UserID, result.Email)
	if err != nil {
		log.Printf("ChangePassword: generating access token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken: tokenStr,
		TokenType:   "Bearer",
		ExpiresIn:   int64(h.authService.Expiry().Seconds()),
	})
}
