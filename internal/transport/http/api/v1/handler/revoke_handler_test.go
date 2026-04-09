package handler_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// POST /api/v1/auth/revoke — handler integration tests (sub-task 9.10)
// ---------------------------------------------------------------------------

// doRevokeRequest sends a POST /api/v1/auth/revoke request with an
// application/x-www-form-urlencoded body and the provided Authorization header.
// When authHeader is empty no Authorization header is set.
func (e *testEnv) doRevokeRequest(t *testing.T, tokenValue, tokenTypeHint, authHeader string) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{}
	form.Set("token", tokenValue)
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

// buildRawBearerToken generates a valid JWT and returns the raw token string.
// The token is cryptographically valid so ValidateAccessToken succeeds without
// any DB mock — Bearer auth in the revoke handler does NOT call IsTokenRevoked.
func buildRawBearerToken(t *testing.T, env *testEnv) string {
	t.Helper()
	token := env.generateToken(t, uuid.New().String(), "user@example.com")
	return token
}

// TestRevoke_ValidRefreshToken verifies that presenting a valid, non-revoked
// refresh token (authenticated via Bearer JWT) returns HTTP 200 and revokes
// both the refresh token and its linked access token in the database.
func TestRevoke_ValidRefreshToken(t *testing.T) {
	env := newTestEnv(t)
	bearerToken := buildRawBearerToken(t, env)
	bearerTokenHash := util.SHA256Hex(bearerToken)

	linkedAccessTokenID := uuid.New()
	rawRevokeToken := "raw-rt-to-revoke"
	rtHash := util.SHA256Hex(rawRevokeToken)
	notRevoked := false

	rt := repository.RefreshToken{
		ID:            uuid.New(),
		TokenFamilyID: uuid.New(),
		TokenHash:     rtHash,
		ClientID:      uuid.New(),
		UserID:        uuid.New(),
		AccessTokenID: linkedAccessTokenID,
		Scope:         "openid",
		ExpiresAt:     time.Now().Add(30 * 24 * time.Hour),
		IsRevoked:     false,
	}

	linkedAT := repository.AccessToken{
		ID:        linkedAccessTokenID,
		TokenHash: util.SHA256Hex("linked-at-raw"),
		ClientID:  &rt.ClientID,
		UserID:    rt.UserID,
		ExpiresAt: time.Now().Add(time.Hour),
		IsRevoked: &notRevoked,
	}

	env.mockQ.On("GetRefreshTokenByHash", mock.Anything, rtHash).Return(rt, nil)
	env.mockQ.On("RevokeRefreshToken", mock.Anything, mock.AnythingOfType("repository.RevokeRefreshTokenParams")).Return(nil)
	env.mockQ.On("GetAccessToken", mock.Anything, bearerTokenHash).Return(repository.AccessToken{}, pgx.ErrNoRows)
	env.mockQ.On("GetAccessTokenByID", mock.Anything, linkedAccessTokenID).Return(linkedAT, nil)
	env.mockQ.On("RevokeAccessToken", mock.Anything, linkedAccessTokenID).Return(nil)

	w := env.doRevokeRequest(t, rawRevokeToken, "refresh_token", "Bearer "+bearerToken)

	assert.Equal(t, http.StatusOK, w.Code)
	env.mockQ.AssertExpectations(t)
}

// TestRevoke_ValidAccessToken verifies that presenting a valid access token hash
// (when hinted as access_token) returns HTTP 200 and revokes the access token.
func TestRevoke_ValidAccessToken(t *testing.T) {
	env := newTestEnv(t)
	bearerToken := buildRawBearerToken(t, env)
	bearerTokenHash := util.SHA256Hex(bearerToken)

	rawTokenToRevoke := "raw-at-to-revoke"
	atHash := util.SHA256Hex(rawTokenToRevoke)
	notRevoked := false

	at := repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: atHash,
		ClientID:  func() *uuid.UUID { id := uuid.New(); return &id }(),
		UserID:    uuid.New(),
		ExpiresAt: time.Now().Add(time.Hour),
		IsRevoked: &notRevoked,
	}

	// token_type_hint=access_token skips the refresh token lookup path.
	// IsTokenRevoked (bearer auth) calls GetAccessToken with the bearer token hash.
	env.mockQ.On("GetAccessToken", mock.Anything, bearerTokenHash).Return(repository.AccessToken{}, pgx.ErrNoRows)
	env.mockQ.On("GetAccessToken", mock.Anything, atHash).Return(at, nil)
	env.mockQ.On("RevokeAccessToken", mock.Anything, at.ID).Return(nil)

	w := env.doRevokeRequest(t, rawTokenToRevoke, "access_token", "Bearer "+bearerToken)

	assert.Equal(t, http.StatusOK, w.Code)
	env.mockQ.AssertExpectations(t)
}

// TestRevoke_UnknownToken verifies that presenting a token that does not exist
// in the database still returns HTTP 200 per RFC 7009 §2.2.
func TestRevoke_UnknownToken(t *testing.T) {
	env := newTestEnv(t)
	bearerToken := buildRawBearerToken(t, env)
	bearerTokenHash := util.SHA256Hex(bearerToken)

	rawUnknown := "completely-unknown-token-value"
	unknownHash := util.SHA256Hex(rawUnknown)

	// IsTokenRevoked (bearer auth) calls GetAccessToken with the bearer token hash.
	env.mockQ.On("GetAccessToken", mock.Anything, bearerTokenHash).Return(repository.AccessToken{}, pgx.ErrNoRows)
	// Neither refresh token nor access token lookup finds this hash.
	env.mockQ.On("GetRefreshTokenByHash", mock.Anything, unknownHash).Return(repository.RefreshToken{}, pgx.ErrNoRows)
	env.mockQ.On("GetAccessToken", mock.Anything, unknownHash).Return(repository.AccessToken{}, pgx.ErrNoRows)

	w := env.doRevokeRequest(t, rawUnknown, "", "Bearer "+bearerToken)

	// RFC 7009 §2.2: unknown tokens MUST NOT cause an error.
	assert.Equal(t, http.StatusOK, w.Code)
	env.mockQ.AssertExpectations(t)
}

// TestRevoke_Unauthenticated verifies that a request without any Authorization
// header returns HTTP 401 — the only error code permitted by RFC 7009 §2.2.
func TestRevoke_Unauthenticated(t *testing.T) {
	env := newTestEnv(t)

	// No Authorization header — pass empty string so none is set.
	w := env.doRevokeRequest(t, "some-token", "", "")

	require.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	if w.Body.Len() > 0 {
		parseJSON(t, w, &resp)
		assert.Equal(t, "unauthorized", resp["error"])
	}
}
