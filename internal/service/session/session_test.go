package session

import (
"context"
"errors"
"testing"
"time"

"github.com/SamuelWang/goauth-server/internal/repository"
"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
"github.com/google/uuid"
"github.com/jackc/pgx/v5"
"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/require"
)

func newTestSession() (*Service, *mocks.MockQuerier) {
	m := &mocks.MockQuerier{}
	return New(m), m
}

func sampleAuthCode() repository.AuthorizationCode {
	t := time.Now().Add(5 * time.Minute)
	return repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "testcode",
		ClientID:    uuid.New(),
		UserID:      uuid.New(),
		ProviderID:  uuid.New(),
		RedirectUri: "https://example.com/callback",
		ExpiresAt:   t,
		CreatedAt:   time.Now(),
	}
}

func sampleAccessToken() repository.AccessToken {
	return repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: "hash123",
		ClientID:  uuid.New(),
		UserID:    uuid.New(),
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
}

// ListAuthorizationCodes tests

func TestListAuthorizationCodes_DefaultLimit(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	expectedCodes := []repository.AuthorizationCode{sampleAuthCode()}
	repoParams := repository.ListAuthorizationCodesParams{Limit: 20, Offset: 0}
	countParams := repository.CountAuthorizationCodesParams{}

	m.On("ListAuthorizationCodes", ctx, repoParams).Return(expectedCodes, nil)
	m.On("CountAuthorizationCodes", ctx, countParams).Return(int64(1), nil)

	result, err := svc.ListAuthorizationCodes(ctx, ListAuthorizationCodesParams{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Len(t, result.Codes, 1)
	m.AssertExpectations(t)
}

func TestListAuthorizationCodes_WithClientIDFilter(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	clientID := uuid.New()
	repoParams := repository.ListAuthorizationCodesParams{
		Column1: clientID,
		Limit:   5,
		Offset:  0,
	}
	countParams := repository.CountAuthorizationCodesParams{Column1: clientID}

	m.On("ListAuthorizationCodes", ctx, repoParams).Return([]repository.AuthorizationCode{}, nil)
	m.On("CountAuthorizationCodes", ctx, countParams).Return(int64(0), nil)

	result, err := svc.ListAuthorizationCodes(ctx, ListAuthorizationCodesParams{
ClientID: &clientID,
		Limit:    5,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
	m.AssertExpectations(t)
}

func TestListAuthorizationCodes_RepoErrorOnList(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	repoParams := repository.ListAuthorizationCodesParams{Limit: 20}
	m.On("ListAuthorizationCodes", ctx, repoParams).Return(nil, errors.New("db error"))

	_, err := svc.ListAuthorizationCodes(ctx, ListAuthorizationCodesParams{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listing authorization codes")
	m.AssertExpectations(t)
}

func TestListAuthorizationCodes_RepoErrorOnCount(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	repoParams := repository.ListAuthorizationCodesParams{Limit: 20}
	countParams := repository.CountAuthorizationCodesParams{}

	m.On("ListAuthorizationCodes", ctx, repoParams).Return([]repository.AuthorizationCode{}, nil)
	m.On("CountAuthorizationCodes", ctx, countParams).Return(int64(0), errors.New("db error"))

	_, err := svc.ListAuthorizationCodes(ctx, ListAuthorizationCodesParams{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "counting authorization codes")
	m.AssertExpectations(t)
}

// RevokeAuthorizationCode tests

func TestRevokeAuthorizationCode_Success(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	code := sampleAuthCode()
	m.On("GetAuthorizationCodeByID", ctx, code.ID).Return(code, nil)
	m.On("RevokeAuthorizationCode", ctx, code.ID).Return(nil)

	err := svc.RevokeAuthorizationCode(ctx, code.ID)
	require.NoError(t, err)
	m.AssertExpectations(t)
}

func TestRevokeAuthorizationCode_NotFound(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	id := uuid.New()
	m.On("GetAuthorizationCodeByID", ctx, id).Return(repository.AuthorizationCode{}, pgx.ErrNoRows)

	err := svc.RevokeAuthorizationCode(ctx, id)
	require.ErrorIs(t, err, ErrAuthorizationCodeNotFound)
	m.AssertExpectations(t)
}

func TestRevokeAuthorizationCode_GetError(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	id := uuid.New()
	m.On("GetAuthorizationCodeByID", ctx, id).Return(repository.AuthorizationCode{}, errors.New("db error"))

	err := svc.RevokeAuthorizationCode(ctx, id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting authorization code")
	m.AssertExpectations(t)
}

func TestRevokeAuthorizationCode_RevokeError(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	code := sampleAuthCode()
	m.On("GetAuthorizationCodeByID", ctx, code.ID).Return(code, nil)
	m.On("RevokeAuthorizationCode", ctx, code.ID).Return(errors.New("db error"))

	err := svc.RevokeAuthorizationCode(ctx, code.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoking authorization code")
	m.AssertExpectations(t)
}

// ListAccessTokens tests

func TestListAccessTokens_DefaultLimit(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	expectedTokens := []repository.AccessToken{sampleAccessToken()}
	repoParams := repository.ListAccessTokensParams{Limit: 20, Offset: 0}
	countParams := repository.CountAccessTokensParams{}

	m.On("ListAccessTokens", ctx, repoParams).Return(expectedTokens, nil)
	m.On("CountAccessTokens", ctx, countParams).Return(int64(1), nil)

	result, err := svc.ListAccessTokens(ctx, ListAccessTokensParams{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Len(t, result.Tokens, 1)
	m.AssertExpectations(t)
}

func TestListAccessTokens_WithUserIDFilter(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	userID := uuid.New()
	repoParams := repository.ListAccessTokensParams{
		Column2: userID,
		Limit:   10,
		Offset:  0,
	}
	countParams := repository.CountAccessTokensParams{Column2: userID}

	m.On("ListAccessTokens", ctx, repoParams).Return([]repository.AccessToken{}, nil)
	m.On("CountAccessTokens", ctx, countParams).Return(int64(0), nil)

	result, err := svc.ListAccessTokens(ctx, ListAccessTokensParams{
UserID: &userID,
		Limit:  10,
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
	m.AssertExpectations(t)
}

func TestListAccessTokens_RepoError(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	repoParams := repository.ListAccessTokensParams{Limit: 20}
	m.On("ListAccessTokens", ctx, repoParams).Return(nil, errors.New("db error"))

	_, err := svc.ListAccessTokens(ctx, ListAccessTokensParams{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listing access tokens")
	m.AssertExpectations(t)
}

// RevokeAccessToken tests

func TestRevokeAccessToken_Success(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	token := sampleAccessToken()
	m.On("GetAccessTokenByID", ctx, token.ID).Return(token, nil)
	m.On("RevokeAccessToken", ctx, token.ID).Return(nil)

	err := svc.RevokeAccessToken(ctx, token.ID)
	require.NoError(t, err)
	m.AssertExpectations(t)
}

func TestRevokeAccessToken_NotFound(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	id := uuid.New()
	m.On("GetAccessTokenByID", ctx, id).Return(repository.AccessToken{}, pgx.ErrNoRows)

	err := svc.RevokeAccessToken(ctx, id)
	require.ErrorIs(t, err, ErrAccessTokenNotFound)
	m.AssertExpectations(t)
}

func TestRevokeAccessToken_RevokeError(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	token := sampleAccessToken()
	m.On("GetAccessTokenByID", ctx, token.ID).Return(token, nil)
	m.On("RevokeAccessToken", ctx, token.ID).Return(errors.New("db error"))

	err := svc.RevokeAccessToken(ctx, token.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoking access token")
	m.AssertExpectations(t)
}

// RevokeUserSessions tests

func TestRevokeUserSessions_Success(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	userID := uuid.New()
	m.On("RevokeAccessTokensByUser", ctx, userID).Return(nil)

	err := svc.RevokeUserSessions(ctx, userID)
	require.NoError(t, err)
	m.AssertExpectations(t)
}

func TestRevokeUserSessions_Error(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	userID := uuid.New()
	m.On("RevokeAccessTokensByUser", ctx, userID).Return(errors.New("db error"))

	err := svc.RevokeUserSessions(ctx, userID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoking user sessions")
	m.AssertExpectations(t)
}

// RevokeClientSessions tests

func TestRevokeClientSessions_Success(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	clientID := uuid.New()
	m.On("RevokeAccessTokensByClient", ctx, clientID).Return(nil)

	err := svc.RevokeClientSessions(ctx, clientID)
	require.NoError(t, err)
	m.AssertExpectations(t)
}

func TestRevokeClientSessions_Error(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	clientID := uuid.New()
	m.On("RevokeAccessTokensByClient", ctx, clientID).Return(errors.New("db error"))

	err := svc.RevokeClientSessions(ctx, clientID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoking client sessions")
	m.AssertExpectations(t)
}

// CleanupExpiredCodes tests

func TestCleanupExpiredCodes_Success(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	m.On("DeleteExpiredAuthorizationCodes", ctx).Return(nil)

	err := svc.CleanupExpiredCodes(ctx)
	require.NoError(t, err)
	m.AssertExpectations(t)
}

func TestCleanupExpiredCodes_Error(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	m.On("DeleteExpiredAuthorizationCodes", ctx).Return(errors.New("db error"))

	err := svc.CleanupExpiredCodes(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cleaning up expired authorization codes")
	m.AssertExpectations(t)
}

// CleanupExpiredTokens tests

func TestCleanupExpiredTokens_Success(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	m.On("DeleteExpiredAccessTokens", ctx).Return(nil)

	err := svc.CleanupExpiredTokens(ctx)
	require.NoError(t, err)
	m.AssertExpectations(t)
}

func TestCleanupExpiredTokens_Error(t *testing.T) {
	svc, m := newTestSession()
	ctx := context.Background()

	m.On("DeleteExpiredAccessTokens", ctx).Return(errors.New("db error"))

	err := svc.CleanupExpiredTokens(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cleaning up expired access tokens")
	m.AssertExpectations(t)
}
