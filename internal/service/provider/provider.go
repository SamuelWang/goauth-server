package provider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// OAuthProvider is the service-level representation of an OAuth provider.
// The provider client secret is never included to prevent accidental exposure.
type OAuthProvider struct {
	ID          uuid.UUID
	ClientID    uuid.UUID
	Name        string
	DisplayName string
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	Scopes      []string
	IsEnabled   bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// OAuthProviderWithSecret extends OAuthProvider with decrypted credentials.
// This type is for internal use only (OAuth flow) and must never be serialised
// into an API response.
type OAuthProviderWithSecret struct {
	OAuthProvider
	ProviderClientID     string
	ProviderClientSecret string
}

// Sentinel errors returned by the provider Service.
var (
	ErrProviderNotFound       = errors.New("provider not found")
	ErrProviderClientMismatch = errors.New("provider does not belong to the specified client")
	ErrDuplicateProviderName  = errors.New("a provider with this name already exists for this client")
)

// CreateProviderDTO carries the data required to create a new OAuth provider.
type CreateProviderDTO struct {
	Name                 string
	DisplayName          string
	ProviderClientID     string
	ProviderClientSecret string
	AuthURL              string
	TokenURL             string
	UserInfoURL          string
	Scopes               []string
	IsEnabled            bool
}

// UpdateProviderDTO carries the data for updating an existing OAuth provider.
// ProviderClientSecret is optional: leaving it empty retains the current secret.
type UpdateProviderDTO struct {
	DisplayName          string
	ProviderClientID     string
	ProviderClientSecret string
	AuthURL              string
	TokenURL             string
	UserInfoURL          string
	Scopes               []string
	IsEnabled            bool
}

// Service manages OAuth providers for client applications.
type Service struct {
	repo          repository.Querier
	encryptionKey []byte
}

// New creates a new provider Service.
// encryptionKey must be exactly 32 bytes (required for AES-256-GCM).
func New(repo repository.Querier, encryptionKey []byte) (*Service, error) {
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("provider encryption key must be exactly 32 bytes, got %d", len(encryptionKey))
	}
	return &Service{
		repo:          repo,
		encryptionKey: encryptionKey,
	}, nil
}

// ListProvidersByClient returns all providers for a client (secrets excluded).
func (s *Service) ListProvidersByClient(ctx context.Context, clientID uuid.UUID) ([]OAuthProvider, error) {
	rows, err := s.repo.ListOAuthProvidersByClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("listing providers: %w", err)
	}
	return toOAuthProviders(rows), nil
}

// ListEnabledProvidersByClient returns only enabled providers for a client.
// Intended for public-facing endpoints; secrets are excluded.
func (s *Service) ListEnabledProvidersByClient(ctx context.Context, clientID uuid.UUID) ([]OAuthProvider, error) {
	rows, err := s.repo.ListEnabledOAuthProvidersByClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("listing enabled providers: %w", err)
	}
	return toOAuthProviders(rows), nil
}

// GetProvider returns a provider by ID (secret excluded).
func (s *Service) GetProvider(ctx context.Context, id uuid.UUID) (*OAuthProvider, error) {
	row, err := s.repo.GetOAuthProvider(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderNotFound
		}
		return nil, fmt.Errorf("getting provider: %w", err)
	}
	p := toOAuthProvider(row)
	return &p, nil
}

// GetProviderByClientAndName returns a provider by client ID and provider name (secret excluded).
func (s *Service) GetProviderByClientAndName(ctx context.Context, clientID uuid.UUID, name string) (*OAuthProvider, error) {
	row, err := s.repo.GetOAuthProviderByClientAndName(ctx, repository.GetOAuthProviderByClientAndNameParams{
		ClientID: clientID,
		Name:     name,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderNotFound
		}
		return nil, fmt.Errorf("getting provider by client and name: %w", err)
	}
	p := toOAuthProvider(row)
	return &p, nil
}

// GetProviderWithSecret returns a provider by ID with its decrypted credentials.
// For internal OAuth flow use only — never include in API responses.
func (s *Service) GetProviderWithSecret(ctx context.Context, id uuid.UUID) (*OAuthProviderWithSecret, error) {
	row, err := s.repo.GetOAuthProvider(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderNotFound
		}
		return nil, fmt.Errorf("getting provider: %w", err)
	}

	decryptedSecret, err := decrypt(s.encryptionKey, row.ProviderClientSecret)
	if err != nil {
		return nil, fmt.Errorf("decrypting provider secret: %w", err)
	}

	return &OAuthProviderWithSecret{
		OAuthProvider:        toOAuthProvider(row),
		ProviderClientID:     row.ProviderClientID,
		ProviderClientSecret: decryptedSecret,
	}, nil
}

// GetProviderWithSecretByClientAndName returns a provider by client ID and name
// with its decrypted credentials. For internal OAuth flow use only — never
// include in API responses.
func (s *Service) GetProviderWithSecretByClientAndName(ctx context.Context, clientID uuid.UUID, name string) (*OAuthProviderWithSecret, error) {
	row, err := s.repo.GetOAuthProviderByClientAndName(ctx, repository.GetOAuthProviderByClientAndNameParams{
		ClientID: clientID,
		Name:     name,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderNotFound
		}
		return nil, fmt.Errorf("getting provider by client and name: %w", err)
	}

	decryptedSecret, err := decrypt(s.encryptionKey, row.ProviderClientSecret)
	if err != nil {
		return nil, fmt.Errorf("decrypting provider secret: %w", err)
	}

	return &OAuthProviderWithSecret{
		OAuthProvider:        toOAuthProvider(row),
		ProviderClientID:     row.ProviderClientID,
		ProviderClientSecret: decryptedSecret,
	}, nil
}

// CreateProvider creates a new OAuth provider for a client, encrypting the client secret at rest.
func (s *Service) CreateProvider(ctx context.Context, clientID uuid.UUID, dto CreateProviderDTO) (*OAuthProvider, error) {
	if err := validateCreateDTO(dto); err != nil {
		return nil, err
	}

	encryptedSecret, err := encrypt(s.encryptionKey, dto.ProviderClientSecret)
	if err != nil {
		return nil, fmt.Errorf("encrypting provider secret: %w", err)
	}

	isEnabled := dto.IsEnabled
	row, err := s.repo.CreateOAuthProvider(ctx, repository.CreateOAuthProviderParams{
		ClientID:             clientID,
		Name:                 dto.Name,
		DisplayName:          dto.DisplayName,
		ProviderClientID:     dto.ProviderClientID,
		ProviderClientSecret: encryptedSecret,
		AuthUrl:              dto.AuthURL,
		TokenUrl:             dto.TokenURL,
		UserInfoUrl:          dto.UserInfoURL,
		Scopes:               dto.Scopes,
		IsEnabled:            &isEnabled,
	})
	if err != nil {
		if isDuplicateKeyError(err) {
			return nil, ErrDuplicateProviderName
		}
		return nil, fmt.Errorf("creating provider: %w", err)
	}

	p := toOAuthProvider(row)
	return &p, nil
}

// UpdateProvider updates a provider after validating that it belongs to clientID.
// If dto.ProviderClientSecret is empty, the existing encrypted secret is retained.
func (s *Service) UpdateProvider(ctx context.Context, id uuid.UUID, clientID uuid.UUID, dto UpdateProviderDTO) (*OAuthProvider, error) {
	if err := validateUpdateDTO(dto); err != nil {
		return nil, err
	}

	existing, err := s.repo.GetOAuthProvider(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrProviderNotFound
		}
		return nil, fmt.Errorf("getting provider: %w", err)
	}

	if existing.ClientID != clientID {
		return nil, ErrProviderClientMismatch
	}

	encryptedSecret := existing.ProviderClientSecret
	if dto.ProviderClientSecret != "" {
		encryptedSecret, err = encrypt(s.encryptionKey, dto.ProviderClientSecret)
		if err != nil {
			return nil, fmt.Errorf("encrypting updated provider secret: %w", err)
		}
	}

	isEnabled := dto.IsEnabled
	row, err := s.repo.UpdateOAuthProvider(ctx, repository.UpdateOAuthProviderParams{
		ID:                   id,
		DisplayName:          dto.DisplayName,
		ProviderClientID:     dto.ProviderClientID,
		ProviderClientSecret: encryptedSecret,
		AuthUrl:              dto.AuthURL,
		TokenUrl:             dto.TokenURL,
		UserInfoUrl:          dto.UserInfoURL,
		Scopes:               dto.Scopes,
		IsEnabled:            &isEnabled,
	})
	if err != nil {
		return nil, fmt.Errorf("updating provider: %w", err)
	}

	p := toOAuthProvider(row)
	return &p, nil
}

// EnableProvider enables a provider after validating that it belongs to clientID.
func (s *Service) EnableProvider(ctx context.Context, id uuid.UUID, clientID uuid.UUID) error {
	existing, err := s.repo.GetOAuthProvider(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrProviderNotFound
		}
		return fmt.Errorf("getting provider: %w", err)
	}

	if existing.ClientID != clientID {
		return ErrProviderClientMismatch
	}

	isEnabled := true
	_, err = s.repo.UpdateOAuthProvider(ctx, repository.UpdateOAuthProviderParams{
		ID:                   id,
		DisplayName:          existing.DisplayName,
		ProviderClientID:     existing.ProviderClientID,
		ProviderClientSecret: existing.ProviderClientSecret,
		AuthUrl:              existing.AuthUrl,
		TokenUrl:             existing.TokenUrl,
		UserInfoUrl:          existing.UserInfoUrl,
		Scopes:               existing.Scopes,
		IsEnabled:            &isEnabled,
	})
	return err
}

// DisableProvider disables a provider after validating that it belongs to clientID.
func (s *Service) DisableProvider(ctx context.Context, id uuid.UUID, clientID uuid.UUID) error {
	if err := s.validateOwnership(ctx, id, clientID); err != nil {
		return err
	}
	return s.repo.DisableOAuthProvider(ctx, id)
}

// DeleteProvider permanently deletes a provider after validating that it belongs to clientID.
func (s *Service) DeleteProvider(ctx context.Context, id uuid.UUID, clientID uuid.UUID) error {
	if err := s.validateOwnership(ctx, id, clientID); err != nil {
		return err
	}
	return s.repo.DeleteOAuthProvider(ctx, id)
}

// validateOwnership fetches the provider and returns ErrProviderClientMismatch if it does
// not belong to the given client, or ErrProviderNotFound if it does not exist.
func (s *Service) validateOwnership(ctx context.Context, id uuid.UUID, clientID uuid.UUID) error {
	existing, err := s.repo.GetOAuthProvider(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrProviderNotFound
		}
		return fmt.Errorf("getting provider: %w", err)
	}
	if existing.ClientID != clientID {
		return ErrProviderClientMismatch
	}
	return nil
}

// toOAuthProvider maps a repository record to the service model, stripping the secret.
func toOAuthProvider(r repository.OauthProvider) OAuthProvider {
	isEnabled := false
	if r.IsEnabled != nil {
		isEnabled = *r.IsEnabled
	}
	return OAuthProvider{
		ID:          r.ID,
		ClientID:    r.ClientID,
		Name:        r.Name,
		DisplayName: r.DisplayName,
		AuthURL:     r.AuthUrl,
		TokenURL:    r.TokenUrl,
		UserInfoURL: r.UserInfoUrl,
		Scopes:      r.Scopes,
		IsEnabled:   isEnabled,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

// toOAuthProviders converts a slice of repository records to service models.
func toOAuthProviders(rows []repository.OauthProvider) []OAuthProvider {
	providers := make([]OAuthProvider, len(rows))
	for i, row := range rows {
		providers[i] = toOAuthProvider(row)
	}
	return providers
}

// isDuplicateKeyError returns true when err is a PostgreSQL unique-constraint violation.
func isDuplicateKeyError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
