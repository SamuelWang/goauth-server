package auth

import (
	"context"
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
