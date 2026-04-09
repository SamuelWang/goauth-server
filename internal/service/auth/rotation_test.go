package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/audit"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// errDB is a sentinel error representing a database failure, used in rotation
// error-path tests.
var errDB = errors.New("database error")

// newTestServiceWithAudit creates a Service with an in-process audit.Service
// backed by the same MockQuerier. This allows asserting on CreateAuditLogEntry
// calls alongside the primary repo calls.
func newTestServiceWithAudit(t *testing.T, q *mocks.MockQuerier) *Service {
	t.Helper()
	privPEM, pubPEM := generateTestPEMKeys(t)
	cfg := &config.Config{
		App: config.AppConfig{Name: "test-app"},
		AccessToken: config.AccessTokenConfig{
			PrivateKey: privPEM,
			PublicKey:  pubPEM,
			Expiry:     60,
		},
		RefreshToken: config.RefreshTokenConfig{
			ExpiryDays:      30,
			RotationEnabled: true,
			MaxLifetimeDays: 90,
		},
	}
	auditSvc := audit.New(q)
	svc, err := New(q, cfg, nil, auditSvc)
	require.NoError(t, err)
	return svc
}

// revokedRefreshToken builds a repository.RefreshToken already marked revoked.
func revokedRefreshToken(clientID, userID uuid.UUID) repository.RefreshToken {
	familyID := uuid.New()
	return repository.RefreshToken{
		ID:            uuid.New(),
		TokenFamilyID: familyID,
		TokenHash:     "some-hash",
		ClientID:      clientID,
		UserID:        userID,
		Scope:         "openid offline_access",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		IsRevoked:     true,
	}
}

// TestRotateRefreshToken_ReplayDetected verifies that presenting a revoked
// token causes the entire token family to be revoked in a single DB call and
// both audit events (replay_detected and refresh_token_family_revoked) to be
// written before returning ErrInvalidGrant.
func TestRotateRefreshToken_ReplayDetected(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newTestServiceWithAudit(t, q)

	rawSecret := "super-secret"
	clientID := uuid.New()
	userID := uuid.New()

	client := activeClient(t, util.SHA256Hex(rawSecret))
	client.ID = clientID

	record := revokedRefreshToken(clientID, userID)
	rawToken := "raw-token-value"
	tokenHash := util.SHA256Hex(rawToken)

	// auth: fetch client, then look up token by hash
	q.On("GetClient", mock.Anything, clientID).Return(client, nil)
	q.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(record, nil)

	// replay: revoke entire family in one statement
	q.On("RevokeRefreshTokenFamily", mock.Anything, repository.RevokeRefreshTokenFamilyParams{
		TokenFamilyID: record.TokenFamilyID,
		RevokeReason:  util.StrPtr("replay_detected"),
	}).Return(nil)

	// audit: EventReplayDetected
	q.On("CreateAuditLogEntry", mock.Anything, mock.MatchedBy(func(p repository.CreateAuditLogEntryParams) bool {
		return p.EventType == string(audit.EventReplayDetected)
	})).Return(uuid.New(), nil)

	// audit: EventRefreshTokenFamilyRevoked
	q.On("CreateAuditLogEntry", mock.Anything, mock.MatchedBy(func(p repository.CreateAuditLogEntryParams) bool {
		return p.EventType == string(audit.EventRefreshTokenFamilyRevoked)
	})).Return(uuid.New(), nil)

	resp, err := svc.RotateRefreshToken(context.Background(), rawToken, clientID.String(), rawSecret)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidGrant)
	q.AssertExpectations(t)
}

// TestRotateRefreshToken_FamilyMemberAfterReplay verifies that a different
// token in the same family — which was revoked by a prior replay detection
// pass — also triggers replay detection when presented. This confirms that
// the property "all family members become is_revoked=true after revocation"
// guarantees subsequent attempts are also caught.
func TestRotateRefreshToken_FamilyMemberAfterReplay(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newTestServiceWithAudit(t, q)

	rawSecret := "super-secret"
	clientID := uuid.New()
	userID := uuid.New()
	familyID := uuid.New()

	client := activeClient(t, util.SHA256Hex(rawSecret))
	client.ID = clientID

	// This is a different token in the same family, but also revoked
	// (because RevokeRefreshTokenFamily set is_revoked=true on all rows
	// with the same token_family_id).
	siblingToken := repository.RefreshToken{
		ID:            uuid.New(),
		TokenFamilyID: familyID,
		TokenHash:     "sibling-hash",
		ClientID:      clientID,
		UserID:        userID,
		Scope:         "openid offline_access",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		IsRevoked:     true,
	}

	rawToken := "sibling-raw-value"
	tokenHash := util.SHA256Hex(rawToken)

	q.On("GetClient", mock.Anything, clientID).Return(client, nil)
	q.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(siblingToken, nil)

	q.On("RevokeRefreshTokenFamily", mock.Anything, repository.RevokeRefreshTokenFamilyParams{
		TokenFamilyID: familyID,
		RevokeReason:  util.StrPtr("replay_detected"),
	}).Return(nil)

	q.On("CreateAuditLogEntry", mock.Anything, mock.MatchedBy(func(p repository.CreateAuditLogEntryParams) bool {
		return p.EventType == string(audit.EventReplayDetected)
	})).Return(uuid.New(), nil)

	q.On("CreateAuditLogEntry", mock.Anything, mock.MatchedBy(func(p repository.CreateAuditLogEntryParams) bool {
		return p.EventType == string(audit.EventRefreshTokenFamilyRevoked)
	})).Return(uuid.New(), nil)

	resp, err := svc.RotateRefreshToken(context.Background(), rawToken, clientID.String(), rawSecret)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidGrant)
	q.AssertExpectations(t)
}

// TestRotateRefreshToken_RevokesFamilyInSingleStatement verifies that the
// family revocation is issued as a single call to RevokeRefreshTokenFamily
// (not per-token), satisfying the "single DB statement" acceptance criterion.
func TestRotateRefreshToken_RevokesFamilyInSingleStatement(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newTestServiceWithAudit(t, q)

	rawSecret := "secret"
	clientID := uuid.New()
	userID := uuid.New()

	client := activeClient(t, util.SHA256Hex(rawSecret))
	client.ID = clientID

	record := revokedRefreshToken(clientID, userID)
	rawToken := "token-val"
	tokenHash := util.SHA256Hex(rawToken)

	q.On("GetClient", mock.Anything, clientID).Return(client, nil)
	q.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(record, nil)
	q.On("RevokeRefreshTokenFamily", mock.Anything, mock.Anything).Return(nil).Once()
	q.On("CreateAuditLogEntry", mock.Anything, mock.Anything).Return(uuid.New(), nil)

	_, err := svc.RotateRefreshToken(context.Background(), rawToken, clientID.String(), rawSecret)

	require.ErrorIs(t, err, ErrInvalidGrant)
	// AssertExpectations confirms RevokeRefreshTokenFamily was called exactly
	// once (the .Once() call above would fail if called more than once).
	q.AssertExpectations(t)
	q.AssertNumberOfCalls(t, "RevokeRefreshTokenFamily", 1)
}

// validRefreshToken builds a non-revoked, non-expired repository.RefreshToken
// for use in happy-path rotation tests.
func validRefreshToken(clientID, userID uuid.UUID) repository.RefreshToken {
	return repository.RefreshToken{
		ID:            uuid.New(),
		TokenFamilyID: uuid.New(),
		TokenHash:     "some-hash",
		ClientID:      clientID,
		UserID:        userID,
		Scope:         "openid offline_access",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		IsRevoked:     false,
	}
}

// TestRotateRefreshToken_ValidRotation verifies the happy-path: the old token
// is marked as used, a new access token is issued, a new refresh token is
// created, and the rotation audit event is written.
func TestRotateRefreshToken_ValidRotation(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newTestServiceWithAudit(t, q)

	rawSecret := "super-secret"
	clientID := uuid.New()
	userID := uuid.New()

	client := activeClient(t, util.SHA256Hex(rawSecret))
	client.ID = clientID

	record := validRefreshToken(clientID, userID)
	rawToken := "valid-raw-token"
	tokenHash := util.SHA256Hex(rawToken)

	user := sampleUser()
	user.ID = userID

	accessTokenRecord := repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: "access-token-hash",
		ClientID:  &clientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(60 * time.Minute),
	}
	newRefreshTokenRecord := repository.RefreshToken{
		ID:            uuid.New(),
		TokenFamilyID: record.TokenFamilyID,
		ClientID:      clientID,
		UserID:        userID,
		ExpiresAt:     time.Now().Add(30 * 24 * time.Hour),
		IsRevoked:     false,
	}

	q.On("GetClient", mock.Anything, clientID).Return(client, nil)
	q.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(record, nil)
	q.On("MarkRefreshTokenUsed", mock.Anything, record.ID).Return(nil)
	q.On("GetUserByID", mock.Anything, userID).Return(user, nil)
	q.On("CreateAccessToken", mock.Anything, mock.Anything).Return(accessTokenRecord, nil)
	q.On("CreateRefreshToken", mock.Anything, mock.MatchedBy(func(p repository.CreateRefreshTokenParams) bool {
		return p.TokenFamilyID == record.TokenFamilyID && p.ClientID == clientID && p.UserID == userID
	})).Return(newRefreshTokenRecord, nil)
	q.On("CreateAuditLogEntry", mock.Anything, mock.MatchedBy(func(p repository.CreateAuditLogEntryParams) bool {
		return p.EventType == string(audit.EventRefreshTokenRotated)
	})).Return(uuid.New(), nil)

	resp, err := svc.RotateRefreshToken(context.Background(), rawToken, clientID.String(), rawSecret)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Greater(t, resp.ExpiresIn, int64(0))
	q.AssertExpectations(t)
}

// TestRotateRefreshToken_ExpiredToken verifies that presenting an expired
// refresh token returns ErrTokenExpired without issuing any new tokens.
func TestRotateRefreshToken_ExpiredToken(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newTestServiceWithAudit(t, q)

	rawSecret := "super-secret"
	clientID := uuid.New()
	userID := uuid.New()

	client := activeClient(t, util.SHA256Hex(rawSecret))
	client.ID = clientID

	expiredToken := repository.RefreshToken{
		ID:            uuid.New(),
		TokenFamilyID: uuid.New(),
		TokenHash:     "expired-hash",
		ClientID:      clientID,
		UserID:        userID,
		Scope:         "openid offline_access",
		ExpiresAt:     time.Now().Add(-1 * time.Hour), // expired
		IsRevoked:     false,
	}
	rawToken := "expired-raw-token"
	tokenHash := util.SHA256Hex(rawToken)

	q.On("GetClient", mock.Anything, clientID).Return(client, nil)
	q.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(expiredToken, nil)

	resp, err := svc.RotateRefreshToken(context.Background(), rawToken, clientID.String(), rawSecret)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrTokenExpired)
	q.AssertExpectations(t)
}

// TestRotateRefreshToken_ClientMismatch verifies that a valid, non-expired
// refresh token issued for client B is rejected when client A presents it,
// returning ErrInvalidGrant without issuing any new tokens.
func TestRotateRefreshToken_ClientMismatch(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newTestServiceWithAudit(t, q)

	rawSecret := "super-secret"
	clientA := uuid.New()
	clientB := uuid.New() // token belongs to this client
	userID := uuid.New()

	client := activeClient(t, util.SHA256Hex(rawSecret))
	client.ID = clientA // authenticating as client A

	// Token was issued for client B, not client A.
	mismatchedToken := repository.RefreshToken{
		ID:            uuid.New(),
		TokenFamilyID: uuid.New(),
		TokenHash:     "mismatched-hash",
		ClientID:      clientB,
		UserID:        userID,
		Scope:         "openid offline_access",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		IsRevoked:     false,
	}
	rawToken := "mismatched-raw-token"
	tokenHash := util.SHA256Hex(rawToken)

	q.On("GetClient", mock.Anything, clientA).Return(client, nil)
	q.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(mismatchedToken, nil)

	resp, err := svc.RotateRefreshToken(context.Background(), rawToken, clientA.String(), rawSecret)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidGrant)
	q.AssertExpectations(t)
}

// TestExchangeCodeForToken_AllowRefreshTokensFalse verifies that when a
// client has AllowRefreshTokens=false, no refresh token is issued even when
// the granted scope includes "offline_access". The response RefreshToken field
// must be empty and CreateRefreshToken must never be called.
func TestExchangeCodeForToken_AllowRefreshTokensFalse(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	const plainSecret = "client-secret-value"

	// Build a client that explicitly disallows refresh tokens.
	client := activeClient(t, util.SHA256Hex(plainSecret))
	client.AllowRefreshTokens = false

	user := sampleUser()
	isRevoked := false
	offlineScope := "openid offline_access"
	codeRow := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "auth-code-offline",
		ClientID:    client.ID,
		UserID:      user.ID,
		ProviderID:  uuid.New(),
		RedirectUri: "https://app.example.com/callback",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		UsedAt:      nil,
		IsRevoked:   &isRevoked,
		Scope:       &offlineScope,
	}

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	q.On("GetAuthorizationCode", mock.Anything, "auth-code-offline").Return(codeRow, nil)
	q.On("MarkAuthorizationCodeUsed", mock.Anything, codeRow.ID).Return(codeRow, nil)
	q.On("GetUserByID", mock.Anything, user.ID).Return(user, nil)
	q.On("CreateAccessToken", mock.Anything, mock.Anything).Return(repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: "hash",
		ClientID:  &client.ID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(60 * time.Minute),
	}, nil)
	// CreateRefreshToken must NOT be called — we deliberately do not register
	// a mock expectation for it; any unexpected call would cause a test failure.

	svc := newTestService(t, q, psvc)
	resp, err := svc.ExchangeCodeForToken(
		context.Background(),
		"auth-code-offline",
		client.ID,
		plainSecret,
		"https://app.example.com/callback",
	)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Empty(t, resp.RefreshToken, "no refresh token should be issued when AllowRefreshTokens=false")
	q.AssertExpectations(t)
	q.AssertNumberOfCalls(t, "CreateRefreshToken", 0)
}

// TestRotateRefreshToken_MarkUsedError verifies that a DB error from
// MarkRefreshTokenUsed propagates correctly to the caller.
func TestRotateRefreshToken_MarkUsedError(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newTestServiceWithAudit(t, q)

	rawSecret := "super-secret"
	clientID := uuid.New()
	userID := uuid.New()

	client := activeClient(t, util.SHA256Hex(rawSecret))
	client.ID = clientID

	record := validRefreshToken(clientID, userID)
	rawToken := "valid-raw-token"
	tokenHash := util.SHA256Hex(rawToken)

	q.On("GetClient", mock.Anything, clientID).Return(client, nil)
	q.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(record, nil)
	q.On("MarkRefreshTokenUsed", mock.Anything, record.ID).Return(errDB)

	resp, err := svc.RotateRefreshToken(context.Background(), rawToken, clientID.String(), rawSecret)

	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "marking refresh token as used")
	q.AssertExpectations(t)
}

// TestRotateRefreshToken_GetUserError verifies that a DB error from
// GetUserByID propagates correctly to the caller.
func TestRotateRefreshToken_GetUserError(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newTestServiceWithAudit(t, q)

	rawSecret := "super-secret"
	clientID := uuid.New()
	userID := uuid.New()

	client := activeClient(t, util.SHA256Hex(rawSecret))
	client.ID = clientID

	record := validRefreshToken(clientID, userID)
	rawToken := "valid-raw-token-user-err"
	tokenHash := util.SHA256Hex(rawToken)

	q.On("GetClient", mock.Anything, clientID).Return(client, nil)
	q.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(record, nil)
	q.On("MarkRefreshTokenUsed", mock.Anything, record.ID).Return(nil)
	q.On("GetUserByID", mock.Anything, userID).Return(repository.User{}, errDB)

	resp, err := svc.RotateRefreshToken(context.Background(), rawToken, clientID.String(), rawSecret)

	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "getting user")
	q.AssertExpectations(t)
}

// TestRotateRefreshToken_CreateAccessTokenError verifies that a DB error from
// CreateAccessToken propagates correctly to the caller.
func TestRotateRefreshToken_CreateAccessTokenError(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newTestServiceWithAudit(t, q)

	rawSecret := "super-secret"
	clientID := uuid.New()
	userID := uuid.New()

	client := activeClient(t, util.SHA256Hex(rawSecret))
	client.ID = clientID

	record := validRefreshToken(clientID, userID)
	rawToken := "valid-raw-token-at-err"
	tokenHash := util.SHA256Hex(rawToken)

	user := sampleUser()
	user.ID = userID

	q.On("GetClient", mock.Anything, clientID).Return(client, nil)
	q.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(record, nil)
	q.On("MarkRefreshTokenUsed", mock.Anything, record.ID).Return(nil)
	q.On("GetUserByID", mock.Anything, userID).Return(user, nil)
	q.On("CreateAccessToken", mock.Anything, mock.Anything).Return(repository.AccessToken{}, errDB)

	resp, err := svc.RotateRefreshToken(context.Background(), rawToken, clientID.String(), rawSecret)

	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "storing access token")
	q.AssertExpectations(t)
}

// TestRotateRefreshToken_CreateRefreshTokenError verifies that a DB error from
// CreateRefreshToken propagates correctly to the caller.
func TestRotateRefreshToken_CreateRefreshTokenError(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newTestServiceWithAudit(t, q)

	rawSecret := "super-secret"
	clientID := uuid.New()
	userID := uuid.New()

	client := activeClient(t, util.SHA256Hex(rawSecret))
	client.ID = clientID

	record := validRefreshToken(clientID, userID)
	rawToken := "valid-raw-token-rt-err"
	tokenHash := util.SHA256Hex(rawToken)

	user := sampleUser()
	user.ID = userID

	accessTokenRecord := repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: "access-token-hash",
		ClientID:  &clientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(60 * time.Minute),
	}

	q.On("GetClient", mock.Anything, clientID).Return(client, nil)
	q.On("GetRefreshTokenByHash", mock.Anything, tokenHash).Return(record, nil)
	q.On("MarkRefreshTokenUsed", mock.Anything, record.ID).Return(nil)
	q.On("GetUserByID", mock.Anything, userID).Return(user, nil)
	q.On("CreateAccessToken", mock.Anything, mock.Anything).Return(accessTokenRecord, nil)
	q.On("CreateRefreshToken", mock.Anything, mock.Anything).Return(repository.RefreshToken{}, errDB)

	resp, err := svc.RotateRefreshToken(context.Background(), rawToken, clientID.String(), rawSecret)

	assert.Nil(t, resp)
	assert.ErrorContains(t, err, "storing new refresh token")
	q.AssertExpectations(t)
}
