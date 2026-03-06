package auth

import (
	"context"

	"github.com/SamuelWang/goauth-server/internal/auth"
	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/google/uuid"
)

// providerQuerier is the subset of provider.Service used by the auth service.
// Using an interface here enables mock injection in unit tests.
type providerQuerier interface {
	GetProviderWithSecretByClientAndName(ctx context.Context, clientID uuid.UUID, name string) (*provider.OAuthProviderWithSecret, error)
}

type Service struct {
	cfg                *config.Config
	repo               repository.Querier
	accessTokenManager *auth.AccessTokenManager
	providerSvc        providerQuerier
}

func New(repo repository.Querier, cfg *config.Config, accessTokenManager *auth.AccessTokenManager, providerSvc *provider.Service) *Service {
	svc := &Service{
		cfg:                cfg,
		repo:               repo,
		accessTokenManager: accessTokenManager,
		providerSvc:        providerSvc,
	}

	return svc
}

func (s *Service) ValidateAccessToken(tokenString string) (*auth.Claims, error) {
	return s.accessTokenManager.ValidateToken(tokenString)
}
