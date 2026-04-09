package handler_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/models"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// POST /api/v1/auth/change-password — handler integration tests (sub-task 9.11)
// ---------------------------------------------------------------------------

// buildForceChangeUser returns a repository.User with force_password_change=true.
func buildForceChangeUser(userID uuid.UUID, email string) repository.User {
	isAdmin := false
	isActive := true
	hashStr := "placeholder-existing-hash"
	return repository.User{
		ID:                  userID,
		Email:               email,
		EmailVerified:       true,
		IsActive:            isActive,
		IsAdmin:             &isAdmin,
		Locale:              "en-US",
		PasswordHash:        &hashStr,
		ForcePasswordChange: true,
		ProviderData:        &models.OAuthProviderData{},
		LastLoginAt:         time.Now().Add(-24 * time.Hour),
		CreatedAt:           time.Now().Add(-48 * time.Hour),
		UpdatedAt:           time.Now(),
	}
}

// TestChangePassword_Success verifies the complete happy-path: a valid challenge
// token + a password that meets the complexity policy results in HTTP 200 with
// an access token, and the DB is updated (force_password_change cleared).
func TestChangePassword_Success(t *testing.T) {
	env := newExtendedTestEnv(t)

	userID := uuid.New()
	user := buildForceChangeUser(userID, "frank@example.com")

	// Generate a genuine challenge token using the auth service.
	challengeToken, err := env.authSvc.GenerateChallengeToken(userID)
	require.NoError(t, err)

	const newPassword = "Str0ng&NewPassword!"

	updatedUser := user
	updatedUser.ForcePasswordChange = false

	env.mockQ.On("GetUserByID", mock.Anything, userID).Return(user, nil)
	env.mockQ.On("UpdatePasswordHash", mock.Anything, mock.AnythingOfType("repository.UpdatePasswordHashParams")).Return(updatedUser, nil)
	env.mockQ.On("SetForcePasswordChange", mock.Anything, repository.SetForcePasswordChangeParams{
		ID:                  userID,
		ForcePasswordChange: false,
	}).Return(updatedUser, nil)
	// Refresh token revocation on password change.
	env.mockQ.On("RevokeRefreshTokensByUser", mock.Anything, mock.AnythingOfType("repository.RevokeRefreshTokensByUserParams")).Return(nil)
	// StoreDirectLoginToken persists the new access token after password change.
	env.mockQ.On("CreateAccessToken", mock.Anything, mock.AnythingOfType("repository.CreateAccessTokenParams")).Return(repository.AccessToken{ID: uuid.New()}, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/change-password", map[string]interface{}{
		"challenge_token": challengeToken,
		"new_password":    newPassword,
	})

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	parseJSON(t, w, &resp)
	assert.NotEmpty(t, resp["access_token"], "expected access_token after successful password change")
	assert.Equal(t, "Bearer", resp["token_type"])

	env.mockQ.AssertExpectations(t)
}

// TestChangePassword_InvalidChallengeToken verifies that an invalid (malformed
// or expired) challenge token returns HTTP 400.
func TestChangePassword_InvalidChallengeToken(t *testing.T) {
	env := newExtendedTestEnv(t)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/change-password", map[string]interface{}{
		"challenge_token": "this.is.not.a.valid.jwt",
		"new_password":    "Str0ng&NewPassword!",
	})

	require.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "invalid_challenge_token", resp["error"])
}

// TestChangePassword_AlreadyCleared verifies that when the force_password_change
// flag has already been cleared (challenge token reuse), HTTP 409 is returned.
func TestChangePassword_AlreadyCleared(t *testing.T) {
	env := newExtendedTestEnv(t)

	userID := uuid.New()
	user := buildForceChangeUser(userID, "grace@example.com")
	user.ForcePasswordChange = false // already cleared — challenge token was already used

	challengeToken, err := env.authSvc.GenerateChallengeToken(userID)
	require.NoError(t, err)

	env.mockQ.On("GetUserByID", mock.Anything, userID).Return(user, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/change-password", map[string]interface{}{
		"challenge_token": challengeToken,
		"new_password":    "Str0ng&NewPassword!",
	})

	require.Equal(t, http.StatusConflict, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "password_change_already_satisfied", resp["error"])

	env.mockQ.AssertExpectations(t)
}

// TestChangePassword_WeakPassword verifies that a new password that fails the
// complexity policy returns HTTP 400 with an error describing the failed rule.
func TestChangePassword_WeakPassword(t *testing.T) {
	env := newExtendedTestEnv(t)

	userID := uuid.New()
	user := buildForceChangeUser(userID, "hank@example.com")

	challengeToken, err := env.authSvc.GenerateChallengeToken(userID)
	require.NoError(t, err)

	env.mockQ.On("GetUserByID", mock.Anything, userID).Return(user, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/change-password", map[string]interface{}{
		"challenge_token": challengeToken,
		"new_password":    "weak", // too short, missing required character classes
	})

	require.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "invalid_new_password", resp["error"])
	assert.NotEmpty(t, resp["error_description"], "expected a description of the policy violation")

	env.mockQ.AssertExpectations(t)
}
