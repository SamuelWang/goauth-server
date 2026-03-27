package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AuthorizationCode is the service-level view of an authorization code session.
type AuthorizationCode struct {
	ID          uuid.UUID
	Code        string
	ClientID    uuid.UUID
	UserID      uuid.UUID
	ProviderID  uuid.UUID
	RedirectURI string
	Scope       *string
	ExpiresAt   time.Time
	UsedAt      *time.Time
	IsRevoked   bool
	CreatedAt   time.Time
}

// AccessToken is the service-level view of an access token session.
// TokenHash is included for administrative visibility but must never be
// returned directly in API responses.
type AccessToken struct {
	ID        uuid.UUID
	ClientID  uuid.UUID
	UserID    uuid.UUID
	Scope     *string
	ExpiresAt time.Time
	IsRevoked bool
	CreatedAt time.Time
}

// Sentinel errors returned by the session Service.
var (
	ErrAuthorizationCodeNotFound = errors.New("authorization code not found")
	ErrAccessTokenNotFound       = errors.New("access token not found")
)

// ListAuthorizationCodesParams holds optional filters and pagination for
// authorization code listings. Nil UUID pointers disable that dimension of
// filtering; a nil IsRevoked pointer returns codes of all revocation states.
//
// Note: when both ClientID and UserID are nil the underlying repository query
// matches by the zero UUID, which will return no rows. Always provide at least
// one UUID filter for a meaningful result.
type ListAuthorizationCodesParams struct {
	ClientID  *uuid.UUID
	UserID    *uuid.UUID
	IsRevoked *bool
	Limit     int32
	Offset    int32
}

// ListAuthorizationCodesResult is the paginated result of a codes listing.
type ListAuthorizationCodesResult struct {
	Codes []AuthorizationCode
	Total int64
}

// ListAccessTokensParams holds optional filters and pagination for access token
// listings. The same nil-UUID caveat from ListAuthorizationCodesParams applies.
type ListAccessTokensParams struct {
	ClientID  *uuid.UUID
	UserID    *uuid.UUID
	IsRevoked *bool
	Limit     int32
	Offset    int32
}

// ListAccessTokensResult is the paginated result of a token listing.
type ListAccessTokensResult struct {
	Tokens []AccessToken
	Total  int64
}

// Service manages authorization code and access token sessions.
type Service struct {
	repo repository.Querier
}

// New creates a new session Service.
func New(repo repository.Querier) *Service {
	return &Service{repo: repo}
}

// ListAuthorizationCodes returns a paginated, optionally filtered list of
// authorization codes. Intended for admin use only.
func (s *Service) ListAuthorizationCodes(ctx context.Context, params ListAuthorizationCodesParams) (*ListAuthorizationCodesResult, error) {
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}

	repoParams := repository.ListAuthorizationCodesParams{
		Limit:  limit,
		Offset: params.Offset,
	}
	countParams := repository.CountAuthorizationCodesParams{}

	if params.ClientID != nil {
		repoParams.Column1 = *params.ClientID
		countParams.Column1 = *params.ClientID
	}
	if params.UserID != nil {
		repoParams.Column2 = *params.UserID
		countParams.Column2 = *params.UserID
	}
	if params.IsRevoked != nil {
		repoParams.Column3 = *params.IsRevoked
		countParams.Column3 = *params.IsRevoked
	}

	codes, err := s.repo.ListAuthorizationCodes(ctx, repoParams)
	if err != nil {
		return nil, fmt.Errorf("listing authorization codes: %w", err)
	}

	total, err := s.repo.CountAuthorizationCodes(ctx, countParams)
	if err != nil {
		return nil, fmt.Errorf("counting authorization codes: %w", err)
	}

	return &ListAuthorizationCodesResult{
		Codes: toAuthorizationCodes(codes),
		Total: total,
	}, nil
}

// RevokeAuthorizationCode marks a single authorization code as revoked by its
// ID. Intended for admin use only.
func (s *Service) RevokeAuthorizationCode(ctx context.Context, id uuid.UUID) error {
	_, err := s.repo.GetAuthorizationCodeByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAuthorizationCodeNotFound
		}
		return fmt.Errorf("getting authorization code: %w", err)
	}

	if err := s.repo.RevokeAuthorizationCode(ctx, id); err != nil {
		return fmt.Errorf("revoking authorization code: %w", err)
	}
	return nil
}

// ListAccessTokens returns a paginated, optionally filtered list of access
// tokens. Intended for admin use only.
func (s *Service) ListAccessTokens(ctx context.Context, params ListAccessTokensParams) (*ListAccessTokensResult, error) {
	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}

	repoParams := repository.ListAccessTokensParams{
		Limit:  limit,
		Offset: params.Offset,
	}
	countParams := repository.CountAccessTokensParams{}

	if params.ClientID != nil {
		repoParams.Column1 = *params.ClientID
		countParams.Column1 = *params.ClientID
	}
	if params.UserID != nil {
		repoParams.Column2 = *params.UserID
		countParams.Column2 = *params.UserID
	}
	if params.IsRevoked != nil {
		repoParams.Column3 = *params.IsRevoked
		countParams.Column3 = *params.IsRevoked
	}

	tokens, err := s.repo.ListAccessTokens(ctx, repoParams)
	if err != nil {
		return nil, fmt.Errorf("listing access tokens: %w", err)
	}

	total, err := s.repo.CountAccessTokens(ctx, countParams)
	if err != nil {
		return nil, fmt.Errorf("counting access tokens: %w", err)
	}

	return &ListAccessTokensResult{
		Tokens: toAccessTokens(tokens),
		Total:  total,
	}, nil
}

// RevokeAccessToken marks a single access token as revoked by its ID.
// Intended for admin use only.
func (s *Service) RevokeAccessToken(ctx context.Context, id uuid.UUID) error {
	_, err := s.repo.GetAccessTokenByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAccessTokenNotFound
		}
		return fmt.Errorf("getting access token: %w", err)
	}

	if err := s.repo.RevokeAccessToken(ctx, id); err != nil {
		return fmt.Errorf("revoking access token: %w", err)
	}
	return nil
}

// RevokeUserSessions revokes all access tokens belonging to the given user.
func (s *Service) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	if err := s.repo.RevokeAccessTokensByUser(ctx, userID); err != nil {
		return fmt.Errorf("revoking user sessions: %w", err)
	}
	return nil
}

// RevokeClientSessions revokes all access tokens issued for the given client.
func (s *Service) RevokeClientSessions(ctx context.Context, clientID uuid.UUID) error {
	if err := s.repo.RevokeAccessTokensByClient(ctx, clientID); err != nil {
		return fmt.Errorf("revoking client sessions: %w", err)
	}
	return nil
}

// CleanupExpiredCodes deletes all authorization codes whose expiry has passed.
// This is intended to be called periodically as a background cleanup job.
func (s *Service) CleanupExpiredCodes(ctx context.Context) error {
	if err := s.repo.DeleteExpiredAuthorizationCodes(ctx); err != nil {
		return fmt.Errorf("cleaning up expired authorization codes: %w", err)
	}
	return nil
}

// CleanupExpiredTokens deletes all access tokens whose expiry has passed.
// This is intended to be called periodically as a background cleanup job.
func (s *Service) CleanupExpiredTokens(ctx context.Context) error {
	if err := s.repo.DeleteExpiredAccessTokens(ctx); err != nil {
		return fmt.Errorf("cleaning up expired access tokens: %w", err)
	}
	return nil
}

// toAuthorizationCode maps a repository AuthorizationCode to the service model.
func toAuthorizationCode(r repository.AuthorizationCode) AuthorizationCode {
	isRevoked := false
	if r.IsRevoked != nil {
		isRevoked = *r.IsRevoked
	}
	return AuthorizationCode{
		ID:          r.ID,
		Code:        r.Code,
		ClientID:    r.ClientID,
		UserID:      r.UserID,
		ProviderID:  r.ProviderID,
		RedirectURI: r.RedirectUri,
		Scope:       r.Scope,
		ExpiresAt:   r.ExpiresAt,
		UsedAt: r.UsedAt,
		IsRevoked: isRevoked,
		CreatedAt: r.CreatedAt,
	}
}

// toAuthorizationCodes converts a slice of repository records to service models.
func toAuthorizationCodes(rows []repository.AuthorizationCode) []AuthorizationCode {
	codes := make([]AuthorizationCode, len(rows))
	for i, row := range rows {
		codes[i] = toAuthorizationCode(row)
	}
	return codes
}

// toAccessToken maps a repository AccessToken to the service model.
func toAccessToken(r repository.AccessToken) AccessToken {
	isRevoked := false
	if r.IsRevoked != nil {
		isRevoked = *r.IsRevoked
	}
	return AccessToken{
		ID:        r.ID,
		ClientID:  r.ClientID,
		UserID:    r.UserID,
		Scope:     r.Scope,
		ExpiresAt: r.ExpiresAt,
		IsRevoked: isRevoked,
		CreatedAt: r.CreatedAt,
	}
}

// toAccessTokens converts a slice of repository records to service models.
func toAccessTokens(rows []repository.AccessToken) []AccessToken {
	tokens := make([]AccessToken, len(rows))
	for i, row := range rows {
		tokens[i] = toAccessToken(row)
	}
	return tokens
}
