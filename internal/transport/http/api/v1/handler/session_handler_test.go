package handler_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// buildAuthorizationCodeRow creates a repository.AuthorizationCode suitable for mock responses.
func buildAuthorizationCodeRow(id, clientID, userID, providerID uuid.UUID) repository.AuthorizationCode {
	isRevoked := false
	return repository.AuthorizationCode{
		ID:          id,
		Code:        "test-code-" + id.String(),
		ClientID:    clientID,
		UserID:      userID,
		ProviderID:  providerID,
		RedirectUri: "https://app.example.com/callback",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		IsRevoked:   &isRevoked,
		CreatedAt:   time.Now(),
	}
}

// buildAccessTokenSessionRow creates a repository.AccessToken suitable for session mock responses.
// Note: this is distinct from activeTokenRow which is used by the auth middleware.
func buildAccessTokenSessionRow(id, clientID, userID uuid.UUID) repository.AccessToken {
	isRevoked := false
	return repository.AccessToken{
		ID:        id,
		TokenHash: "some-token-hash-" + id.String(),
		ClientID:  clientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour),
		IsRevoked: &isRevoked,
		CreatedAt: time.Now(),
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/sessions/codes
// ---------------------------------------------------------------------------

func TestListAuthorizationCodes_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	codeID := uuid.New()
	env.mockQ.On("ListAuthorizationCodes", mock.Anything, repository.ListAuthorizationCodesParams{
		Limit:  20,
		Offset: 0,
	}).Return([]repository.AuthorizationCode{
		buildAuthorizationCodeRow(codeID, uuid.New(), uuid.New(), uuid.New()),
	}, nil)
	env.mockQ.On("CountAuthorizationCodes", mock.Anything, repository.CountAuthorizationCodesParams{}).
		Return(int64(1), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/codes", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Codes []struct {
			ID string `json:"id"`
		} `json:"codes"`
		Total int64 `json:"total"`
	}
	parseJSON(t, w, &resp)
	assert.Len(t, resp.Codes, 1)
	assert.Equal(t, int64(1), resp.Total)
	env.mockQ.AssertExpectations(t)
}

func TestListAuthorizationCodes_Unauthenticated(t *testing.T) {
	env := newTestEnv(t)

	w := env.doRequest(http.MethodGet, "/api/v1/sessions/codes", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListAuthorizationCodes_NonAdmin(t *testing.T) {
	env := newTestEnv(t)
	token := nonAdminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/codes", nil, token)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestListAuthorizationCodes_FilterByClientID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	filterClientID := uuid.New()

	env.mockQ.On("ListAuthorizationCodes", mock.Anything, repository.ListAuthorizationCodesParams{
		Column1: filterClientID,
		Limit:   20,
		Offset:  0,
	}).Return([]repository.AuthorizationCode{}, nil)
	env.mockQ.On("CountAuthorizationCodes", mock.Anything, repository.CountAuthorizationCodesParams{
		Column1: filterClientID,
	}).Return(int64(0), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/codes?client_id="+filterClientID.String(), nil, token)
	assert.Equal(t, http.StatusOK, w.Code)
	env.mockQ.AssertExpectations(t)
}

func TestListAuthorizationCodes_InvalidClientID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/codes?client_id=not-a-uuid", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAuthorizationCodes_FilterByRevoked(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	isRevoked := true
	env.mockQ.On("ListAuthorizationCodes", mock.Anything, repository.ListAuthorizationCodesParams{
		Column3: isRevoked,
		Limit:   20,
		Offset:  0,
	}).Return([]repository.AuthorizationCode{}, nil)
	env.mockQ.On("CountAuthorizationCodes", mock.Anything, repository.CountAuthorizationCodesParams{
		Column3: isRevoked,
	}).Return(int64(0), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/codes?is_revoked=true", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)
	env.mockQ.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/sessions/codes/:id
// ---------------------------------------------------------------------------

func TestRevokeAuthorizationCode_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	codeID := uuid.New()
	codeRow := buildAuthorizationCodeRow(codeID, uuid.New(), uuid.New(), uuid.New())

	// RevokeAuthorizationCode calls GetAuthorizationCodeByID then RevokeAuthorizationCode
	env.mockQ.On("GetAuthorizationCodeByID", mock.Anything, codeID).Return(codeRow, nil)
	env.mockQ.On("RevokeAuthorizationCode", mock.Anything, codeID).Return(nil)

	w := env.doAuthRequest(http.MethodDelete, "/api/v1/sessions/codes/"+codeID.String(), nil, token)
	assert.Equal(t, http.StatusNoContent, w.Code)
	env.mockQ.AssertExpectations(t)
}

func TestRevokeAuthorizationCode_NotFound(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	codeID := uuid.New()

	env.mockQ.On("GetAuthorizationCodeByID", mock.Anything, codeID).Return(repository.AuthorizationCode{}, pgx.ErrNoRows)

	w := env.doAuthRequest(http.MethodDelete, "/api/v1/sessions/codes/"+codeID.String(), nil, token)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRevokeAuthorizationCode_InvalidID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodDelete, "/api/v1/sessions/codes/not-a-uuid", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// GET /api/v1/sessions/tokens
// ---------------------------------------------------------------------------

func TestListAccessTokens_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	tokenID := uuid.New()
	env.mockQ.On("ListAccessTokens", mock.Anything, repository.ListAccessTokensParams{
		Limit:  20,
		Offset: 0,
	}).Return([]repository.AccessToken{
		buildAccessTokenSessionRow(tokenID, uuid.New(), uuid.New()),
	}, nil)
	env.mockQ.On("CountAccessTokens", mock.Anything, repository.CountAccessTokensParams{}).
		Return(int64(1), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/tokens", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Tokens []struct {
			ID string `json:"id"`
		} `json:"tokens"`
		Total int64 `json:"total"`
	}
	parseJSON(t, w, &resp)
	assert.Len(t, resp.Tokens, 1)
	assert.Equal(t, int64(1), resp.Total)
	env.mockQ.AssertExpectations(t)
}

func TestListAccessTokens_Unauthenticated(t *testing.T) {
	env := newTestEnv(t)

	w := env.doRequest(http.MethodGet, "/api/v1/sessions/tokens", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListAccessTokens_NonAdmin(t *testing.T) {
	env := newTestEnv(t)
	token := nonAdminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/tokens", nil, token)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestListAccessTokens_FilterByUserID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	filterUserID := uuid.New()

	env.mockQ.On("ListAccessTokens", mock.Anything, repository.ListAccessTokensParams{
		Column2: filterUserID,
		Limit:   20,
		Offset:  0,
	}).Return([]repository.AccessToken{}, nil)
	env.mockQ.On("CountAccessTokens", mock.Anything, repository.CountAccessTokensParams{
		Column2: filterUserID,
	}).Return(int64(0), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/tokens?user_id="+filterUserID.String(), nil, token)
	assert.Equal(t, http.StatusOK, w.Code)
	env.mockQ.AssertExpectations(t)
}

func TestListAccessTokens_InvalidUserID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/tokens?user_id=not-a-uuid", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListAccessTokens_ResponseOmitsTokenHash verifies that the token hash is
// never included in the list response.
func TestListAccessTokens_ResponseOmitsTokenHash(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	tokenID := uuid.New()

	env.mockQ.On("ListAccessTokens", mock.Anything, repository.ListAccessTokensParams{
		Limit:  20,
		Offset: 0,
	}).Return([]repository.AccessToken{
		buildAccessTokenSessionRow(tokenID, uuid.New(), uuid.New()),
	}, nil)
	env.mockQ.On("CountAccessTokens", mock.Anything, repository.CountAccessTokensParams{}).
		Return(int64(1), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/tokens", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	parseJSON(t, w, &resp)
	tokens := resp["tokens"].([]interface{})
	tkn := tokens[0].(map[string]interface{})
	assert.NotContains(t, tkn, "token_hash")
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/sessions/tokens/:id
// ---------------------------------------------------------------------------

func TestRevokeAccessToken_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	tokenID := uuid.New()
	tokenRow := buildAccessTokenSessionRow(tokenID, uuid.New(), uuid.New())

	// RevokeAccessToken calls GetAccessTokenByID then RevokeAccessToken
	env.mockQ.On("GetAccessTokenByID", mock.Anything, tokenID).Return(tokenRow, nil)
	env.mockQ.On("RevokeAccessToken", mock.Anything, tokenID).Return(nil)

	w := env.doAuthRequest(http.MethodDelete, "/api/v1/sessions/tokens/"+tokenID.String(), nil, token)
	assert.Equal(t, http.StatusNoContent, w.Code)
	env.mockQ.AssertExpectations(t)
}

func TestRevokeAccessToken_NotFound(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	tokenID := uuid.New()

	env.mockQ.On("GetAccessTokenByID", mock.Anything, tokenID).Return(repository.AccessToken{}, pgx.ErrNoRows)

	w := env.doAuthRequest(http.MethodDelete, "/api/v1/sessions/tokens/"+tokenID.String(), nil, token)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRevokeAccessToken_InvalidID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodDelete, "/api/v1/sessions/tokens/not-a-uuid", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeAccessToken_Unauthenticated(t *testing.T) {
	env := newTestEnv(t)
	tokenID := uuid.New()

	w := env.doRequest(http.MethodDelete, "/api/v1/sessions/tokens/"+tokenID.String(), nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// handleSessionError internal error branches
// ---------------------------------------------------------------------------

// TestListAuthorizationCodes_DBError exercises the 500 branch of ListAuthorizationCodes.
func TestListAuthorizationCodes_DBError(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	env.mockQ.On("ListAuthorizationCodes", mock.Anything, repository.ListAuthorizationCodesParams{
		Limit:  20,
		Offset: 0,
	}).Return(nil, errors.New("database error"))

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/codes", nil, token)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	env.mockQ.AssertExpectations(t)
}

// TestListAccessTokens_DBError exercises the 500 branch of ListAccessTokens.
func TestListAccessTokens_DBError(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	env.mockQ.On("ListAccessTokens", mock.Anything, repository.ListAccessTokensParams{
		Limit:  20,
		Offset: 0,
	}).Return(nil, errors.New("database error"))

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/tokens", nil, token)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	env.mockQ.AssertExpectations(t)
}

// TestListAuthorizationCodes_InvalidIsRevoked exercises the bad is_revoked parse branch.
func TestListAuthorizationCodes_InvalidIsRevoked(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/codes?is_revoked=notbool", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListAccessTokens_InvalidIsRevoked exercises the bad is_revoked parse branch.
func TestListAccessTokens_InvalidIsRevoked(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/tokens?is_revoked=notbool", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListAccessTokens_FilterByClientID exercises the client_id filter branch.
func TestListAccessTokens_FilterByClientID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	filterClientID := uuid.New()

	env.mockQ.On("ListAccessTokens", mock.Anything, repository.ListAccessTokensParams{
		Column1: filterClientID,
		Limit:   20,
		Offset:  0,
	}).Return([]repository.AccessToken{}, nil)
	env.mockQ.On("CountAccessTokens", mock.Anything, repository.CountAccessTokensParams{
		Column1: filterClientID,
	}).Return(int64(0), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/tokens?client_id="+filterClientID.String(), nil, token)
	assert.Equal(t, http.StatusOK, w.Code)
	env.mockQ.AssertExpectations(t)
}

// TestListAccessTokens_InvalidClientID exercises the bad client_id parse branch.
func TestListAccessTokens_InvalidClientID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/tokens?client_id=not-a-uuid", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
