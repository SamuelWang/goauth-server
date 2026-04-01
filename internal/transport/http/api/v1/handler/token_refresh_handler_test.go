package handler_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// POST /api/v1/auth/token – grant_type=refresh_token (sub-task 9.9)
//
// The authorization_code grant regression tests live in auth_handler_test.go.
// This file covers the refresh_token grant cases exclusively.
// ---------------------------------------------------------------------------

// buildClientWithRefreshTokens returns an active repository.Client that
// permits refresh tokens, together with the plain-text secret to use in tests.
func buildClientWithRefreshTokens(t *testing.T) (repository.Client, string) {
	t.Helper()
	const plainSecret = "refresh-test-secret"
	isActive := true
	cl := repository.Client{
		ID:                 uuid.New(),
		Name:               "refresh-client",
		ClientSecretHash:   util.SHA256Hex(plainSecret),
		RedirectUris:       []string{"https://app.example.com/callback"},
		GrantTypes:         []string{"authorization_code", "refresh_token"},
		IsActive:           &isActive,
		AllowRefreshTokens: true,
		CreatedBy:          uuid.New(),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	return cl, plainSecret
}

// buildValidRefreshTokenRecord returns a non-revoked, non-expired refresh token
// record for the given client and user.
func buildValidRefreshTokenRecord(clientID, userID uuid.UUID) repository.RefreshToken {
	return repository.RefreshToken{
		ID:            uuid.New(),
		TokenFamilyID: uuid.New(),
		TokenHash:     "placeholder-hash",
		ClientID:      clientID,
		UserID:        userID,
		AccessTokenID: uuid.New(),
		Scope:         "openid offline_access",
		ExpiresAt:     time.Now().Add(30 * 24 * time.Hour),
		IsRevoked:     false,
	}
}

// TestTokenExchange_RefreshToken_ValidRotation verifies that a valid
// refresh_token grant rotates the token, issues a new access token, and returns
// HTTP 200 with both access_token and refresh_token fields.
func TestTokenExchange_RefreshToken_ValidRotation(t *testing.T) {
	env := newExtendedTestEnv(t)

	cl, plainSecret := buildClientWithRefreshTokens(t)
	userID := uuid.New()
	rawRefreshToken := "raw-refresh-token-value-abc123"
	tokenHash := util.SHA256Hex(rawRefreshToken)

	rtRecord := buildValidRefreshTokenRecord(cl.ID, userID)

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)
	env.mockQ.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(rtRecord, nil)
	env.mockQ.On("MarkRefreshTokenUsed", mock.Anything, rtRecord.ID).Return(nil)
	env.mockQ.On("GetUserByID", mock.Anything, userID).Return(buildRegularUser(userID), nil)
	env.mockQ.On("CreateAccessToken", mock.Anything, mock.AnythingOfType("repository.CreateAccessTokenParams")).
		Return(repository.AccessToken{
			ID:        uuid.New(),
			TokenHash: "new-access-token-hash",
			ClientID:  cl.ID,
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil)
	env.mockQ.On("CreateRefreshToken", mock.Anything, mock.AnythingOfType("repository.CreateRefreshTokenParams")).
		Return(repository.RefreshToken{
			ID:            uuid.New(),
			TokenFamilyID: rtRecord.TokenFamilyID,
			ClientID:      cl.ID,
			UserID:        userID,
			ExpiresAt:     time.Now().Add(30 * 24 * time.Hour),
		}, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "refresh_token",
		"refresh_token": rawRefreshToken,
		"client_id":     cl.ID.String(),
		"client_secret": plainSecret,
	})

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	parseJSON(t, w, &resp)
	assert.NotEmpty(t, resp["access_token"], "expected new access_token")
	assert.NotEmpty(t, resp["refresh_token"], "expected new refresh_token")
	assert.Equal(t, "Bearer", resp["token_type"])

	env.mockQ.AssertExpectations(t)
}

// TestTokenExchange_RefreshToken_Expired verifies that presenting an expired
// refresh token returns HTTP 400 with error=invalid_grant.
func TestTokenExchange_RefreshToken_Expired(t *testing.T) {
	env := newExtendedTestEnv(t)

	cl, plainSecret := buildClientWithRefreshTokens(t)
	userID := uuid.New()
	rawRefreshToken := "raw-expired-token-value"
	tokenHash := util.SHA256Hex(rawRefreshToken)

	expiredRecord := buildValidRefreshTokenRecord(cl.ID, userID)
	expiredRecord.ExpiresAt = time.Now().Add(-24 * time.Hour) // expired yesterday

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)
	env.mockQ.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(expiredRecord, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "refresh_token",
		"refresh_token": rawRefreshToken,
		"client_id":     cl.ID.String(),
		"client_secret": plainSecret,
	})

	require.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "invalid_grant", resp["error"])

	env.mockQ.AssertExpectations(t)
}

// TestTokenExchange_RefreshToken_Replay verifies that presenting an already-revoked
// refresh token (replay attack) triggers family revocation and returns HTTP 400
// with error=invalid_grant.
func TestTokenExchange_RefreshToken_Replay(t *testing.T) {
	env := newExtendedTestEnv(t)

	cl, plainSecret := buildClientWithRefreshTokens(t)
	userID := uuid.New()
	rawRefreshToken := "raw-replayed-token-value"
	tokenHash := util.SHA256Hex(rawRefreshToken)

	revokedRecord := buildValidRefreshTokenRecord(cl.ID, userID)
	revokedRecord.IsRevoked = true // simulate a previously-used / revoked token

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)
	env.mockQ.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(revokedRecord, nil)
	// Replay detection must revoke the entire token family.
	env.mockQ.On("RevokeRefreshTokenFamily", mock.Anything, mock.AnythingOfType("repository.RevokeRefreshTokenFamilyParams")).
		Return(nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "refresh_token",
		"refresh_token": rawRefreshToken,
		"client_id":     cl.ID.String(),
		"client_secret": plainSecret,
	})

	require.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "invalid_grant", resp["error"])

	// Verify the family revocation was called, ensuring replay detection ran.
	env.mockQ.AssertExpectations(t)
}
