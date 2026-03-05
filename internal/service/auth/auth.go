package auth

import (
	"github.com/SamuelWang/goauth-server/internal/auth"
	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
)

type Service struct {
	cfg                *config.Config
	repo               *repository.Queries
	accessTokenManager *auth.AccessTokenManager
	providerSvc        *provider.Service
}

func New(repo *repository.Queries, cfg *config.Config, accessTokenManager *auth.AccessTokenManager, providerSvc *provider.Service) *Service {
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
