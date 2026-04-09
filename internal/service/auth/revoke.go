package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/audit"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RevokeAnyToken attempts to revoke rawToken as a refresh token first, then as
// an access token.  When tokenTypeHint is "access_token" the refresh-token path
// is skipped.  Per RFC 7009 §2.2, a token that cannot be found is NOT an error;
// this function returns nil in that case.
//
// When a refresh token is successfully revoked its linked access token (if any)
// is also revoked.
func (s *Service) RevokeAnyToken(ctx context.Context, rawToken, tokenTypeHint string) error {
	tokenHash := util.SHA256Hex(rawToken)

	if tokenTypeHint != "access_token" {
		// --- Try refresh token path first ---
		rt, err := s.repo.GetRefreshTokenByHash(ctx, tokenHash)
		if err == nil {
			return s.revokeRefreshTokenAndLinkedAccess(ctx, rt)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("looking up refresh token: %w", err)
		}
		// Not found as a refresh token — fall through.
	}

	// --- Try access token path ---
	at, err := s.repo.GetAccessToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Token not found — RFC 7009 requires 200; treat as success.
			return nil
		}
		return fmt.Errorf("looking up access token: %w", err)
	}
	return s.revokeAccessTokenRecord(ctx, at)
}

// revokeRefreshTokenAndLinkedAccess revokes a refresh token record and, when
// present, its linked access token.  Audit events are written for each revoked
// token.
func (s *Service) revokeRefreshTokenAndLinkedAccess(ctx context.Context, rt repository.RefreshToken) error {
	if rt.IsRevoked {
		// Already revoked — nothing to do.
		return nil
	}

	revokeReason := util.StrPtr("client_revoked")
	if err := s.repo.RevokeRefreshToken(ctx, repository.RevokeRefreshTokenParams{
		ID:           rt.ID,
		RevokeReason: revokeReason,
	}); err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}

	if s.auditSvc != nil {
		uid := rt.UserID
		cid := rt.ClientID
		_ = s.auditSvc.LogEvent(ctx, audit.AuditEntry{
			EventType: audit.EventRefreshTokenRevoked,
			UserID:    &uid,
			ClientID:  &cid,
			Metadata:  map[string]any{"reason": "client_revoked"},
		})
	}

	// Revoke the linked access token when it exists and is not the zero-value UUID.
	if rt.AccessTokenID != uuid.Nil {
		at, err := s.repo.GetAccessTokenByID(ctx, rt.AccessTokenID)
		if err == nil {
			_ = s.revokeAccessTokenRecord(ctx, at)
		} else if !errors.Is(err, pgx.ErrNoRows) {
			// Log but don't abort — the refresh token has already been revoked.
			return fmt.Errorf("looking up linked access token: %w", err)
		}
	}
	return nil
}

// revokeAccessTokenRecord revokes an access token record and writes an audit
// event.
func (s *Service) revokeAccessTokenRecord(ctx context.Context, at repository.AccessToken) error {
	if at.IsRevoked != nil && *at.IsRevoked {
		// Already revoked — nothing to do.
		return nil
	}
	if err := s.repo.RevokeAccessToken(ctx, at.ID); err != nil {
		return fmt.Errorf("revoking access token: %w", err)
	}
	if s.auditSvc != nil {
		uid := at.UserID
		_ = s.auditSvc.LogEvent(ctx, audit.AuditEntry{
			EventType: audit.EventAccessTokenRevoked,
			UserID:    &uid,
			ClientID:  at.ClientID,
			Metadata:  map[string]any{"reason": "client_revoked"},
		})
	}
	return nil
}

// ValidateClientCredentials authenticates a client by its string ID and plain
// secret.  Returns (true, nil) on success, (false, nil) on credential mismatch,
// and (false, err) on an unexpected repository error.
func (s *Service) ValidateClientCredentials(ctx context.Context, clientIDStr, clientSecret string) (bool, error) {
	cid, err := uuid.Parse(clientIDStr)
	if err != nil {
		// Non-UUID client ID is always invalid.
		return false, nil
	}
	client, err := s.repo.GetClient(ctx, cid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("getting client: %w", err)
	}
	if client.IsActive == nil || !*client.IsActive {
		return false, nil
	}
	secretHash := util.SHA256Hex(clientSecret)
	match := subtle.ConstantTimeCompare([]byte(client.ClientSecretHash), []byte(secretHash)) == 1
	return match, nil
}
