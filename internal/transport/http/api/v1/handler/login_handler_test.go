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
// POST /api/v1/auth/login — handler integration tests (sub-task 9.8)
// ---------------------------------------------------------------------------

// buildLoginUser returns a repository.User for login tests. The PasswordHash
// field is set to an Argon2id hash of correctPassword.
func buildLoginUser(t *testing.T, email, correctPassword string) repository.User {
	t.Helper()
	hashStr := buildArgon2Hash(t, correctPassword)
	isAdmin := false
	isActive := true
	return repository.User{
		ID:            uuid.New(),
		Email:         email,
		EmailVerified: true,
		IsActive:      isActive,
		IsAdmin:       &isAdmin,
		Locale:        "en-US",
		PasswordHash:  &hashStr,
		ProviderData:  &models.OAuthProviderData{},
		LastLoginAt:   time.Now().Add(-24 * time.Hour),
		CreatedAt:     time.Now().Add(-48 * time.Hour),
		UpdatedAt:     time.Now(),
	}
}

// TestLogin_Success verifies that a correct email/password combination returns
// HTTP 200 with an access token in the response body.
func TestLogin_Success(t *testing.T) {
	env := newExtendedTestEnv(t)

	const password = "Correct$Password1!"
	user := buildLoginUser(t, "alice@example.com", password)

	env.mockQ.On("GetUserByEmailForAuth", mock.Anything, "alice@example.com").Return(user, nil)
	env.mockQ.On("ResetLoginAttempts", mock.Anything, user.ID).Return(user, nil)
	env.mockQ.On("UpdateLastLogin", mock.Anything, mock.Anything).Return(user, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/login", map[string]interface{}{
		"email":    "alice@example.com",
		"password": password,
	})

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	parseJSON(t, w, &resp)
	assert.NotEmpty(t, resp["access_token"], "expected access_token in response")
	assert.Equal(t, "Bearer", resp["token_type"])
	assert.Nil(t, resp["challenge_token"], "should not contain challenge_token on normal login")

	env.mockQ.AssertExpectations(t)
}

// TestLogin_ForcePasswordChange verifies that a user flagged with
// force_password_change=true receives a challenge token instead of an access
// token.
func TestLogin_ForcePasswordChange(t *testing.T) {
	env := newExtendedTestEnv(t)

	const password = "Correct$Password1!"
	user := buildLoginUser(t, "bob@example.com", password)
	user.ForcePasswordChange = true

	env.mockQ.On("GetUserByEmailForAuth", mock.Anything, "bob@example.com").Return(user, nil)
	env.mockQ.On("ResetLoginAttempts", mock.Anything, user.ID).Return(user, nil)
	env.mockQ.On("UpdateLastLogin", mock.Anything, mock.Anything).Return(user, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/login", map[string]interface{}{
		"email":    "bob@example.com",
		"password": password,
	})

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	parseJSON(t, w, &resp)
	assert.NotEmpty(t, resp["challenge_token"], "expected challenge_token when force_password_change=true")
	assert.Equal(t, "password_change", resp["require"])
	assert.Empty(t, resp["access_token"], "should not issue access_token when force_password_change=true")

	env.mockQ.AssertExpectations(t)
}

// TestLogin_WrongPassword verifies that an incorrect password returns HTTP 401
// with a generic "invalid_credentials" error (no lockout since this is the
// first failure and there is no recent failed-login history).
func TestLogin_WrongPassword(t *testing.T) {
	env := newExtendedTestEnv(t)

	const correctPassword = "Correct$Password1!"
	user := buildLoginUser(t, "carol@example.com", correctPassword)
	// No prior failed attempts — LastFailedLoginAt is nil, so withinWindow=false.
	user.LastFailedLoginAt = nil

	env.mockQ.On("GetUserByEmailForAuth", mock.Anything, "carol@example.com").Return(user, nil)
	// After a failed attempt the counter is incremented (returns 1, still below MaxAttempts=3).
	updatedUser := user
	updatedUser.FailedLoginAttempts = 1
	env.mockQ.On("IncrementFailedLoginAttempts", mock.Anything, user.ID).Return(updatedUser, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/login", map[string]interface{}{
		"email":    "carol@example.com",
		"password": "WrongPassword123!",
	})

	require.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "invalid_credentials", resp["error"])

	env.mockQ.AssertExpectations(t)
}

// TestLogin_NthWrongPassword_Lockout verifies that when a user hits the
// MaxAttempts threshold within the configured window, the account is locked
// and HTTP 429 is returned with a Retry-After header.
func TestLogin_NthWrongPassword_Lockout(t *testing.T) {
	env := newExtendedTestEnv(t)

	const correctPassword = "Correct$Password1!"
	user := buildLoginUser(t, "dave@example.com", correctPassword)
	// Simulate two prior failures within the window so the 3rd attempt triggers lockout.
	recentFailure := time.Now().Add(-30 * time.Second) // 30s ago — within 600s window
	user.LastFailedLoginAt = &recentFailure
	user.FailedLoginAttempts = 2

	lockedUntil := time.Now().Add(900 * time.Second)
	lockedUser := user
	lockedUser.FailedLoginAttempts = 3 // 3 >= MaxAttempts(3) → triggers lockout
	lockedUser.LockedUntil = &lockedUntil

	env.mockQ.On("GetUserByEmailForAuth", mock.Anything, "dave@example.com").Return(user, nil)
	env.mockQ.On("IncrementFailedLoginAttempts", mock.Anything, user.ID).Return(lockedUser, nil)
	env.mockQ.On("LockUserAccount", mock.Anything, mock.Anything).Return(lockedUser, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/login", map[string]interface{}{
		"email":    "dave@example.com",
		"password": "WrongPassword123!",
	})

	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"), "expected Retry-After header on lockout response")

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "account_locked", resp["error"])

	env.mockQ.AssertExpectations(t)
}

// TestLogin_ActiveLockout verifies that when the user's account is already
// locked (locked_until is in the future), HTTP 429 is returned immediately
// without performing any password verification.
func TestLogin_ActiveLockout(t *testing.T) {
	env := newExtendedTestEnv(t)

	const correctPassword = "Correct$Password1!"
	user := buildLoginUser(t, "eve@example.com", correctPassword)
	// Account is locked until 15 minutes from now.
	lockedUntil := time.Now().Add(15 * time.Minute)
	user.LockedUntil = &lockedUntil

	env.mockQ.On("GetUserByEmailForAuth", mock.Anything, "eve@example.com").Return(user, nil)
	// IncrementFailedLoginAttempts must NOT be called for an actively locked account.

	w := env.doRequest(http.MethodPost, "/api/v1/auth/login", map[string]interface{}{
		"email":    "eve@example.com",
		"password": correctPassword,
	})

	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"), "expected Retry-After header for locked account")

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "account_locked", resp["error"])

	env.mockQ.AssertExpectations(t)
}

// TestLogin_InvalidEmail verifies that a non-email address in the request body
// returns HTTP 400.
func TestLogin_InvalidEmail(t *testing.T) {
	env := newExtendedTestEnv(t)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/login", map[string]interface{}{
		"email":    "not-an-email",
		"password": "SomePassword1!",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
