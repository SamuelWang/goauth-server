package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/audit"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Sentinel errors for the refresh token rotation flow.
var (
	ErrInvalidGrant = errors.New("invalid grant")
	ErrTokenExpired = errors.New("refresh token has expired")
)

// RotateRefreshToken validates the supplied raw refresh token, marks it as
// used, issues a new access token, and issues a rotated refresh token in the
// same token family. On replay detection (a revoked token is presented), the
// entire token family is revoked before returning ErrInvalidGrant.
func (s *Service) RotateRefreshToken(ctx context.Context, rawToken, clientID, clientSecret string) (*TokenResponse, error) {
	// 1. Authenticate client with SHA-256 constant-time comparison.
	cid, err := uuid.Parse(clientID)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	client, err := s.repo.GetClient(ctx, cid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, fmt.Errorf("getting client: %w", err)
	}
	if client.IsActive == nil || !*client.IsActive {
		return nil, ErrClientInactive
	}
	secretHash := util.SHA256Hex(clientSecret)
	if subtle.ConstantTimeCompare([]byte(client.ClientSecretHash), []byte(secretHash)) != 1 {
		return nil, ErrInvalidClientSecret
	}

	// 2. Look up the refresh token record by hash.
	tokenHash := util.SHA256Hex(rawToken)
	record, err := s.repo.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidGrant
		}
		return nil, fmt.Errorf("getting refresh token: %w", err)
	}

	// 3. Replay detection: a revoked token means a prior rotation was replayed.
	// Revoke the entire token family and return ErrInvalidGrant.
	if record.IsRevoked {
		reason := util.StrPtr("replay_detected")
		_ = s.repo.RevokeRefreshTokenFamily(ctx, repository.RevokeRefreshTokenFamilyParams{
			TokenFamilyID: record.TokenFamilyID,
			RevokeReason:  reason,
		})
		if s.auditSvc != nil {
			uid := record.UserID
			cliID := record.ClientID
			fid := record.TokenFamilyID.String()
			_ = s.auditSvc.LogEvent(ctx, audit.AuditEntry{
				EventType: audit.EventReplayDetected,
				UserID:    &uid,
				ClientID:  &cliID,
				Metadata:  map[string]any{"family_id": fid},
			})
			_ = s.auditSvc.LogEvent(ctx, audit.AuditEntry{
				EventType: audit.EventRefreshTokenFamilyRevoked,
				UserID:    &uid,
				ClientID:  &cliID,
				Metadata:  map[string]any{"family_id": fid, "reason": "replay_detected"},
			})
		}
		return nil, ErrInvalidGrant
	}

	// 4. Expiry check.
	if time.Now().After(record.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// 5. Client binding check — token must belong to the authenticating client.
	if record.ClientID != cid {
		return nil, ErrInvalidGrant
	}

	// 6. Mark old token as used (sets is_revoked=true, used_at=now, revoke_reason='used').
	if err := s.repo.MarkRefreshTokenUsed(ctx, record.ID); err != nil {
		return nil, fmt.Errorf("marking refresh token as used: %w", err)
	}

	// 7. Load user for new access token claims.
	user, err := s.repo.GetUserByID(ctx, record.UserID)
	if err != nil {
		return nil, fmt.Errorf("getting user: %w", err)
	}

	// 8. Issue new access token.
	tokenString, err := s.GenerateAccessToken(user.ID.String(), user.Email)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}
	accessTokenHash := util.SHA256Hex(tokenString)
	expiresAt := time.Now().Add(s.Expiry())
	scopeStr := record.Scope
	accessTokenRecord, err := s.repo.CreateAccessToken(ctx, repository.CreateAccessTokenParams{
		TokenHash: accessTokenHash,
		ClientID:  cid,
		UserID:    user.ID,
		Scope:     util.StrPtr(scopeStr),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("storing access token: %w", err)
	}

	// 9. Issue new refresh token in the same family, linking back to the old token.
	newTokenValue, err := util.GenerateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("generating new refresh token value: %w", err)
	}
	newTokenHash := util.SHA256Hex(newTokenValue)
	rtExpiresAt := time.Now().Add(time.Duration(s.cfg.RefreshToken.ExpiryDays) * 24 * time.Hour)
	_, err = s.repo.CreateRefreshToken(ctx, repository.CreateRefreshTokenParams{
		TokenHash:       newTokenHash,
		TokenFamilyID:   record.TokenFamilyID,
		ClientID:        cid,
		UserID:          user.ID,
		AccessTokenID:   accessTokenRecord.ID,
		PreviousTokenID: &record.ID,
		Scope:           record.Scope,
		ExpiresAt:       rtExpiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("storing new refresh token: %w", err)
	}

	// 10. Write audit event (non-blocking — failure must not abort the response).
	if s.auditSvc != nil {
		uid := user.ID
		cliID := cid
		_ = s.auditSvc.LogEvent(ctx, audit.AuditEntry{
			EventType: audit.EventRefreshTokenRotated,
			UserID:    &uid,
			ClientID:  &cliID,
			Metadata: map[string]any{
				"family_id":  record.TokenFamilyID.String(),
				"scope":      record.Scope,
				"expires_at": rtExpiresAt.UTC().Format(time.RFC3339),
			},
		})
	}

	var scopePtr *string
	if scopeStr != "" {
		scopePtr = &scopeStr
	}
	return &TokenResponse{
		AccessToken:  tokenString,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.Expiry().Seconds()),
		Scope:        scopePtr,
		RefreshToken: newTokenValue,
	}, nil
}
