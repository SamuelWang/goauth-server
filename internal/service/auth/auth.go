package auth

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/audit"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// providerServicer is the subset of provider.Service used by the auth service.
// Using an interface here enables mock injection in unit tests.
type providerServicer interface {
	GetProviderWithSecretByClientAndName(ctx context.Context, clientID uuid.UUID, name string) (*provider.OAuthProviderWithSecret, error)
}

type Service struct {
	cfg         *config.Config
	privateKey  *ecdsa.PrivateKey
	publicKey   *ecdsa.PublicKey
	repo        repository.Querier
	providerSvc providerServicer
	auditSvc    *audit.Service
}

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// New creates an auth Service. auditSvc may be nil; when provided, sensitive
// events (failed logins, lockouts) are written to the audit log.
func New(repo repository.Querier, cfg *config.Config, providerSvc providerServicer, auditSvc *audit.Service) (*Service, error) {
	// Parse private key
	privateKey, err := parsePrivateKey(cfg.AccessToken.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Parse public key
	publicKey, err := parsePublicKey(cfg.AccessToken.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	svc := &Service{
		cfg:         cfg,
		privateKey:  privateKey,
		publicKey:   publicKey,
		repo:        repo,
		providerSvc: providerSvc,
		auditSvc:    auditSvc,
	}

	return svc, nil
}
