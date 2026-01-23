package auth

import (
	"context"
	"fmt"

	"github.com/SamuelWang/goauth-server/internal/auth"
	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/models"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/google/uuid"
)

type AuthService struct {
	cfg                *config.Config
	repo               *repository.Queries
	accessTokenManager *auth.AccessTokenManager
}

func New(repo *repository.Queries, cfg *config.Config, accessTokenManager *auth.AccessTokenManager) *AuthService {
	svc := &AuthService{
		cfg:                cfg,
		repo:               repo,
		accessTokenManager: accessTokenManager,
	}

	return svc
}

func (s *AuthService) ValidateAccessToken(tokenString string) (*auth.Claims, error) {
	return s.accessTokenManager.ValidateToken(tokenString)
}

func (s *AuthService) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	parsedUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	user, err := s.repo.GetUserByID(ctx, parsedUUID)
	if err != nil {
		return nil, err
	}

	userModel := &models.User{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Locale:        user.Locale,
		CreatedAt:     user.CreatedAt.UTC(),
		UpdatedAt:     user.UpdatedAt.UTC(),
		Provider:      user.Provider,
		ProviderID:    user.ProviderID,
		ProviderData:  user.ProviderData,
		LastLoginAt:   user.LastLoginAt.UTC(),
	}
	return userModel, nil
}
