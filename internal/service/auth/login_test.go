package auth

import (
	"context"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/models"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/audit"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newLockoutTestService creates an auth Service with a LockoutConfig (MaxAttempts=3,
// WindowSeconds=600, DurationSeconds=900) and a real audit.Service backed by
// the supplied MockQuerier. This lets tests assert on both primary repo calls
// and CreateAuditLogEntry calls with a single mock.
func newLockoutTestService(t *testing.T, q *mocks.MockQuerier) *Service {
	t.Helper()
	privPEM, pubPEM := generateTestPEMKeys(t)
	cfg := &config.Config{
		App: config.AppConfig{Name: "test-app"},
		AccessToken: config.AccessTokenConfig{
			PrivateKey: privPEM,
			PublicKey:  pubPEM,
			Expiry:     60,
		},
		Lockout: config.LockoutConfig{
			MaxAttempts:     3,
			WindowSeconds:   600,
			DurationSeconds: 900,
		},
	}
	auditSvc := audit.New(q)
	svc, err := New(q, cfg, nil, auditSvc)
	require.NoError(t, err)
	return svc
}

// userWithArgon2Hash returns a repository.User whose PasswordHash is an
// Argon2id hash of correctPassword, and the plain correctPassword string.
// It uses the hashArgon2id helper that lives in the same package.
func userWithArgon2Hash(t *testing.T, email, correctPassword string) repository.User {
	t.Helper()
	hash, err := hashArgon2id(correctPassword)
	require.NoError(t, err)

	isAdmin := false
	return repository.User{
		ID:            uuid.New(),
		Email:         email,
		EmailVerified: true,
		IsActive:      true,
		Locale:        "en-US",
		LastLoginAt:   time.Now().Add(-24 * time.Hour),
		CreatedAt:     time.Now().Add(-48 * time.Hour),
		UpdatedAt:     time.Now(),
		IsAdmin:       &isAdmin,
		PasswordHash:  &hash,
		ProviderData:  &models.OAuthProviderData{},
	}
}

// ---- Active lockout ----

// TestVerifyCredentials_ActiveLockout verifies that when LockedUntil is in the
// future, VerifyCredentials returns ErrAccountLocked immediately — without
// checking the password (IncrementFailedLoginAttempts must not be called).
func TestVerifyCredentials_ActiveLockout(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newLockoutTestService(t, q)

	lockedUntil := time.Now().Add(15 * time.Minute)
	isAdmin := false
	user := repository.User{
		ID:            uuid.New(),
		Email:         "locked@example.com",
		EmailVerified: true,
		IsActive:      true,
		Locale:        "en-US",
		IsAdmin:       &isAdmin,
		ProviderData:  &models.OAuthProviderData{},
		LockedUntil:   &lockedUntil,
	}

	q.On("GetUserByEmailForAuth", mock.Anything, user.Email).Return(user, nil)

	result, err := svc.VerifyCredentials(context.Background(), user.Email, "any-password", "10.0.0.1")

	require.ErrorIs(t, err, ErrAccountLocked)
	require.NotNil(t, result)
	assert.NotNil(t, result.LockedUntil)
	assert.WithinDuration(t, lockedUntil, *result.LockedUntil, time.Second)

	// Password check must have been entirely skipped.
	q.AssertNotCalled(t, "IncrementFailedLoginAttempts")
	q.AssertExpectations(t)
}

// ---- Expired lockout ----

// TestVerifyCredentials_ExpiredLockout verifies that a LockedUntil in the past
// is cleared (ResetLoginAttempts called) before login proceeds, and that a
// correct password results in a successful response.
func TestVerifyCredentials_ExpiredLockout(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newLockoutTestService(t, q)

	const password = "C0rrectP@ss!"
	user := userWithArgon2Hash(t, "user@example.com", password)

	// Set an expired lockout timestamp (5 minutes in the past).
	expiredLockout := time.Now().Add(-5 * time.Minute)
	user.LockedUntil = &expiredLockout

	clearedUser := user
	clearedUser.LockedUntil = nil
	clearedUser.FailedLoginAttempts = 0

	updatedUser := clearedUser
	lastLogin := time.Now()
	updatedUser.LastLoginAt = lastLogin

	q.On("GetUserByEmailForAuth", mock.Anything, user.Email).Return(user, nil)
	// First ResetLoginAttempts: clears the expired lockout.
	q.On("ResetLoginAttempts", mock.Anything, user.ID).Return(clearedUser, nil).Once()
	// Second ResetLoginAttempts: clears attempt counter after successful login.
	q.On("ResetLoginAttempts", mock.Anything, user.ID).Return(clearedUser, nil).Once()
	q.On("UpdateLastLogin", mock.Anything, mock.MatchedBy(func(p repository.UpdateLastLoginParams) bool {
		return p.ID == user.ID
	})).Return(updatedUser, nil)

	result, err := svc.VerifyCredentials(context.Background(), user.Email, password, "10.0.0.1")

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	assert.Equal(t, user.ID, result.User.ID)
	q.AssertExpectations(t)
}

// ---- N-1 failures (no lockout) ----

// TestVerifyCredentials_NMinusOneFailures verifies that a wrong password when
// the account already has MaxAttempts-2 failures increments the counter to
// MaxAttempts-1 without triggering lockout or the EventAccountLocked audit entry.
func TestVerifyCredentials_NMinusOneFailures(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newLockoutTestService(t, q)
	// MaxAttempts = 3.  User currently has 1 prior failure; this is the 2nd.

	const correctPassword = "C0rrectP@ss!"
	user := userWithArgon2Hash(t, "user@example.com", correctPassword)

	recentFailure := time.Now().Add(-30 * time.Second)
	user.FailedLoginAttempts = 1
	user.LastFailedLoginAt = &recentFailure

	// After increment: 2 attempts, still below MaxAttempts.
	afterIncrement := user
	afterIncrement.FailedLoginAttempts = 2

	q.On("GetUserByEmailForAuth", mock.Anything, user.Email).Return(user, nil)
	q.On("IncrementFailedLoginAttempts", mock.Anything, user.ID).Return(afterIncrement, nil)
	// EventLoginFailed audit entry is written for non-locking failures.
	q.On("CreateAuditLogEntry", mock.Anything, mock.MatchedBy(func(p repository.CreateAuditLogEntryParams) bool {
		return p.EventType == string(audit.EventLoginFailed)
	})).Return(uuid.New(), nil)

	_, err := svc.VerifyCredentials(context.Background(), user.Email, "wrongpassword", "10.0.0.1")

	assert.ErrorIs(t, err, ErrInvalidCredentials)
	q.AssertNotCalled(t, "LockUserAccount")
	q.AssertExpectations(t)
}

// ---- Nth failure (lockout transition) ----

// TestVerifyCredentials_NthFailureLocks verifies that on the Nth failed attempt
// within the sliding window, LockUserAccount is called exactly once and the
// EventAccountLocked audit entry is written — not EventLoginFailed.
func TestVerifyCredentials_NthFailureLocks(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newLockoutTestService(t, q)
	// MaxAttempts = 3.  User already has 2 prior failures; this is the 3rd.

	const correctPassword = "C0rrectP@ss!"
	user := userWithArgon2Hash(t, "user@example.com", correctPassword)

	recentFailure := time.Now().Add(-30 * time.Second)
	user.FailedLoginAttempts = 2
	user.LastFailedLoginAt = &recentFailure

	// After increment: exactly MaxAttempts.
	afterIncrement := user
	afterIncrement.FailedLoginAttempts = 3

	lockedUser := afterIncrement
	lockedTime := time.Now().Add(900 * time.Second)
	lockedUser.LockedUntil = &lockedTime

	q.On("GetUserByEmailForAuth", mock.Anything, user.Email).Return(user, nil)
	q.On("IncrementFailedLoginAttempts", mock.Anything, user.ID).Return(afterIncrement, nil)
	q.On("LockUserAccount", mock.Anything, mock.MatchedBy(func(p repository.LockUserAccountParams) bool {
		return p.ID == user.ID
	})).Return(lockedUser, nil)
	// Only EventAccountLocked is written on the lockout transition.
	q.On("CreateAuditLogEntry", mock.Anything, mock.MatchedBy(func(p repository.CreateAuditLogEntryParams) bool {
		return p.EventType == string(audit.EventAccountLocked)
	})).Return(uuid.New(), nil)

	result, err := svc.VerifyCredentials(context.Background(), user.Email, "wrongpassword", "10.0.0.1")

	require.ErrorIs(t, err, ErrAccountLocked)
	require.NotNil(t, result)
	assert.NotNil(t, result.LockedUntil)
	// EventLoginFailed must NOT be emitted on the locking transition.
	q.AssertNotCalled(t, "CreateAuditLogEntry", mock.Anything, mock.MatchedBy(func(p repository.CreateAuditLogEntryParams) bool {
		return p.EventType == string(audit.EventLoginFailed)
	}))
	q.AssertExpectations(t)
}

// ---- Successful login ----

// TestVerifyCredentials_SuccessfulLogin verifies that a correct password after
// prior failures resets the attempt counter (ResetLoginAttempts) and updates
// the last login timestamp (UpdateLastLogin).
func TestVerifyCredentials_SuccessfulLogin(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newLockoutTestService(t, q)

	const password = "C0rrectP@ss!"
	user := userWithArgon2Hash(t, "user@example.com", password)

	// Simulate 1 prior failed attempt to confirm they are cleared on success.
	recentFailure := time.Now().Add(-60 * time.Second)
	user.FailedLoginAttempts = 1
	user.LastFailedLoginAt = &recentFailure

	clearedUser := user
	clearedUser.FailedLoginAttempts = 0
	clearedUser.LastFailedLoginAt = nil

	updatedUser := clearedUser
	updatedUser.LastLoginAt = time.Now()

	q.On("GetUserByEmailForAuth", mock.Anything, user.Email).Return(user, nil)
	q.On("ResetLoginAttempts", mock.Anything, user.ID).Return(clearedUser, nil)
	q.On("UpdateLastLogin", mock.Anything, mock.MatchedBy(func(p repository.UpdateLastLoginParams) bool {
		return p.ID == user.ID
	})).Return(updatedUser, nil)

	result, err := svc.VerifyCredentials(context.Background(), user.Email, password, "10.0.0.1")

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	assert.Equal(t, user.ID, result.User.ID)
	assert.False(t, result.ForcePasswordChange)
	q.AssertExpectations(t)
}
