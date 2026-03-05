package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/models"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
}

type IDTokenClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
	Picture       string `json:"picture"`
}

func (s *Service) GetGoogleLoginURL(state string) (string, error) {
	config := getGoogleOAuthConfig(s.cfg)
	if config == nil {
		return "", fmt.Errorf("Google OAuth is not enabled")
	}

	return config.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

func (s *Service) HandleGoogleCallback(ctx context.Context, code string) (string, error) {
	config := getGoogleOAuthConfig(s.cfg)
	if config == nil {
		return "", fmt.Errorf("Google OAuth is not enabled")
	}

	// Exchange code for token
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("failed to exchange code: %w", err)
	}

	// Get user info from ID token (OpenID Connect)
	userInfo, err := getGoogleUserInfoFromIDToken(ctx, token, s.cfg)
	if err != nil {
		return "", fmt.Errorf("failed to get user info: %w", err)
	}

	// Check if user exists
	user, err := s.repo.GetUserByProviderID(ctx, repository.GetUserByProviderIDParams{
		Provider:   util.StrPtr("google"),
		ProviderID: util.StrPtr(userInfo.Sub),
	})

	providerData := &models.OAuthProviderData{}

	if err != nil {
		// User doesn't exist, create new user
		user, err = s.repo.CreateUser(ctx, repository.CreateUserParams{
			Email:         userInfo.Email,
			EmailVerified: userInfo.EmailVerified,
			FirstName:     util.StrPtr(userInfo.GivenName),
			LastName:      util.StrPtr(userInfo.FamilyName),
			Provider:      util.StrPtr("google"),
			ProviderID:    util.StrPtr(userInfo.Sub),
			ProviderData:  providerData,
			Locale: func() string {
				if userInfo.Locale == "" {
					return "en-US"
				}
				return userInfo.Locale
			}(),
			LastLoginAt: time.Now(),
		})
		if err != nil {
			return "", fmt.Errorf("failed to create user: %w", err)
		}
	} else {
		// Update last login time
		user, err = s.repo.UpdateLastLogin(ctx, repository.UpdateLastLoginParams{
			ID:           user.ID,
			ProviderData: providerData,
			LastLoginAt:  time.Now(),
		})
		if err != nil {
			return "", fmt.Errorf("failed to update last login: %w", err)
		}
	}

	// Generate access token
	accessToken, err := s.accessTokenManager.GenerateToken(user.ID.String(), user.Email)
	if err != nil {
		return "", fmt.Errorf("failed to generate access token: %w", err)
	}

	return accessToken, nil
}

// getGoogleUserInfoFromIDToken extracts user info from the ID token using OpenID Connect
func getGoogleUserInfoFromIDToken(ctx context.Context, token *oauth2.Token, cfg *config.Config) (*GoogleUserInfo, error) {
	// Get the ID token from the oauth2 token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in oauth2 token")
	}

	// Create OIDC provider
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Configure ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.OAuth.Google.ClientID,
	})

	// Verify ID token
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims
	var claims IDTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	// Convert to GoogleUserInfo
	userInfo := &GoogleUserInfo{
		Sub:           claims.Sub,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		GivenName:     claims.GivenName,
		FamilyName:    claims.FamilyName,
		Locale:        claims.Locale,
	}

	return userInfo, nil
}

func getGoogleOAuthConfig(cfg *config.Config) *oauth2.Config {
	if cfg.OAuth.Google.Enabled {
		return &oauth2.Config{
			ClientID:     cfg.OAuth.Google.ClientID,
			ClientSecret: cfg.OAuth.Google.ClientSecret,
			RedirectURL:  cfg.Server.Origin() + "/auth/google/callback",
			Scopes:       cfg.OAuth.Google.Scopes,
			Endpoint:     google.Endpoint,
		}
	}

	return nil
}
