package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Client is the service-level representation of a client application.
// The client secret hash is never included to prevent accidental exposure.
type Client struct {
	ID           uuid.UUID
	Name         string
	Description  *string
	RedirectURIs []string
	GrantTypes   []string
	IsActive     bool
	CreatedBy    uuid.UUID
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ClientWithSecret extends Client with the plain client secret.
// This is only returned once upon creation or secret regeneration, and must
// never be stored or included in subsequent API responses.
type ClientWithSecret struct {
	Client
	PlainSecret string
}

// Sentinel errors returned by the client Service.
var (
	ErrClientNotFound      = errors.New("client not found")
	ErrDuplicateClientName = errors.New("a client with this name already exists")
)

// CreateClientDTO carries the data required to create a new client.
type CreateClientDTO struct {
	Name         string
	Description  *string
	RedirectURIs []string
	GrantTypes   []string
	IsActive     bool
}

// UpdateClientDTO carries the data for updating an existing client's configuration.
type UpdateClientDTO struct {
	Name         string
	Description  *string
	RedirectURIs []string
	GrantTypes   []string
}

// ListClientsParams carries filter and pagination parameters.
type ListClientsParams struct {
	// IsActive filters by active status. nil defaults to active clients only.
	IsActive *bool
	Limit    int32
	Offset   int32
}

// ListClientsResult is the paginated list result.
type ListClientsResult struct {
	Clients []Client
	Total   int64
}

// Service manages client applications.
type Service struct {
	repo     repository.Querier
	auditSvc *audit.Service
	// env is consulted for redirect URI validation (e.g., "production" enforces HTTPS).
	env string
}

// New creates a new client Service.
// env should match config.Server.Env (e.g., "production", "development").
// auditSvc may be nil; if non-nil, audit events are written for sensitive operations.
func New(repo repository.Querier, env string, auditSvc *audit.Service) *Service {
	return &Service{repo: repo, env: env, auditSvc: auditSvc}
}

// ListClients returns a paginated list of clients filtered by active status.
// When params.IsActive is nil, only active clients are returned.
func (s *Service) ListClients(ctx context.Context, params ListClientsParams) (*ListClientsResult, error) {
	isActive := true
	if params.IsActive != nil {
		isActive = *params.IsActive
	}

	limit := params.Limit
	if limit <= 0 {
		limit = 20
	}

	clients, err := s.repo.ListClients(ctx, repository.ListClientsParams{
		Column1: isActive,
		Limit:   limit,
		Offset:  params.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("listing clients: %w", err)
	}

	total, err := s.repo.CountClients(ctx, isActive)
	if err != nil {
		return nil, fmt.Errorf("counting clients: %w", err)
	}

	return &ListClientsResult{
		Clients: toClients(clients),
		Total:   total,
	}, nil
}

// GetClient returns a client by ID. It returns ErrClientNotFound if no client
// with that ID exists (active or inactive).
func (s *Service) GetClient(ctx context.Context, id uuid.UUID) (*Client, error) {
	row, err := s.repo.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, fmt.Errorf("getting client: %w", err)
	}
	c := toClient(row)
	return &c, nil
}

// CreateClient creates a new client application. It generates a cryptographically
// secure random secret, hashes it with SHA-256, and stores only the hash.
// The plain secret is returned once in ClientWithSecret and must be conveyed to
// the administrator immediately — it cannot be recovered afterwards.
func (s *Service) CreateClient(ctx context.Context, dto CreateClientDTO, adminUserID uuid.UUID) (*ClientWithSecret, error) {
	if err := validateCreateDTO(dto, s.env); err != nil {
		return nil, err
	}

	plainSecret, err := generateSecret()
	if err != nil {
		return nil, fmt.Errorf("generating client secret: %w", err)
	}

	hash := hashSecret(plainSecret)

	isActive := dto.IsActive
	row, err := s.repo.CreateClient(ctx, repository.CreateClientParams{
		Name:             dto.Name,
		Description:      dto.Description,
		ClientSecretHash: hash,
		RedirectUris:     dto.RedirectURIs,
		GrantTypes:       dto.GrantTypes,
		IsActive:         &isActive,
		CreatedBy:        adminUserID,
	})
	if err != nil {
		if isDuplicateKeyError(err) {
			return nil, ErrDuplicateClientName
		}
		return nil, fmt.Errorf("creating client: %w", err)
	}

	c := toClient(row)
	return &ClientWithSecret{Client: c, PlainSecret: plainSecret}, nil
}

// UpdateClient updates a client's mutable fields (name, description, redirect URIs,
// grant types). The client secret is not changed by this operation.
func (s *Service) UpdateClient(ctx context.Context, id uuid.UUID, dto UpdateClientDTO) (*Client, error) {
	if err := validateUpdateDTO(dto, s.env); err != nil {
		return nil, err
	}

	row, err := s.repo.UpdateClient(ctx, repository.UpdateClientParams{
		ID:           id,
		Name:         dto.Name,
		Description:  dto.Description,
		RedirectUris: dto.RedirectURIs,
		GrantTypes:   dto.GrantTypes,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		if isDuplicateKeyError(err) {
			return nil, ErrDuplicateClientName
		}
		return nil, fmt.Errorf("updating client: %w", err)
	}

	c := toClient(row)
	return &c, nil
}

// RegenerateSecret generates a new cryptographically secure client secret, hashes
// it, and stores the new hash. The plain secret is returned once in ClientWithSecret.
func (s *Service) RegenerateSecret(ctx context.Context, id uuid.UUID) (*ClientWithSecret, error) {
	// Verify the client exists before regenerating.
	existing, err := s.repo.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, fmt.Errorf("getting client: %w", err)
	}

	plainSecret, err := generateSecret()
	if err != nil {
		return nil, fmt.Errorf("generating client secret: %w", err)
	}

	hash := hashSecret(plainSecret)

	updated, err := s.repo.RegenerateClientSecret(ctx, repository.RegenerateClientSecretParams{
		ID:               existing.ID,
		ClientSecretHash: hash,
	})
	if err != nil {
		return nil, fmt.Errorf("updating client secret: %w", err)
	}

	if s.auditSvc != nil {
		_ = s.auditSvc.LogEvent(ctx, audit.AuditEntry{
			EventType: audit.EventClientSecretRegenerated,
			ClientID:  &updated.ID,
		})
	}

	c := toClient(updated)
	return &ClientWithSecret{Client: c, PlainSecret: plainSecret}, nil
}

// DeleteClient soft-deletes a client by setting is_active = false.
// Returns ErrClientNotFound if the client does not exist.
func (s *Service) DeleteClient(ctx context.Context, id uuid.UUID) error {
	_, err := s.repo.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrClientNotFound
		}
		return fmt.Errorf("getting client: %w", err)
	}

	if err := s.repo.DeleteClient(ctx, id); err != nil {
		return fmt.Errorf("deleting client: %w", err)
	}
	return nil
}

// generateSecret returns a URL-safe base64-encoded 32-byte random secret.
func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashSecret hashes a plain-text secret using SHA-256, returning the hex-encoded digest.
func hashSecret(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}

// ValidateClientSecret reports whether the supplied plain-text secret matches
// the stored SHA-256 hex hash. The comparison is constant-time to prevent
// timing side-channels.
func ValidateClientSecret(storedHash, suppliedSecret string) bool {
	h := sha256.Sum256([]byte(suppliedSecret))
	supplied := hex.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(supplied)) == 1
}

// toClient maps a repository Client record to the service model, stripping the secret hash.
func toClient(r repository.Client) Client {
	isActive := false
	if r.IsActive != nil {
		isActive = *r.IsActive
	}
	return Client{
		ID:           r.ID,
		Name:         r.Name,
		Description:  r.Description,
		RedirectURIs: r.RedirectUris,
		GrantTypes:   r.GrantTypes,
		IsActive:     isActive,
		CreatedBy:    r.CreatedBy,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}

// toClients converts a slice of repository Client records to service models.
func toClients(rows []repository.Client) []Client {
	clients := make([]Client, len(rows))
	for i, row := range rows {
		clients[i] = toClient(row)
	}
	return clients
}

// isDuplicateKeyError returns true when err is a PostgreSQL unique-constraint violation.
func isDuplicateKeyError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
