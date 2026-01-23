package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/models"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/util"
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

func (s *AuthService) GetGoogleLoginURL(state string) (string, error) {
	config := getGoogleOAuthConfig(s.cfg)
	if config == nil {
		return "", fmt.Errorf("Google OAuth is not enabled")
	}

	return config.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

func (s *AuthService) HandleGoogleCallback(ctx context.Context, code string) (string, error) {
	config := getGoogleOAuthConfig(s.cfg)
	if config == nil {
		return "", fmt.Errorf("Google OAuth is not enabled")
	}

	// Exchange code for token
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("failed to exchange code: %w", err)
	}

	// Get user info from Google
	userInfo, err := getGoogleUserInfo(ctx, token.AccessToken)
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
			Locale:        "en-US",
			LastLoginAt:   time.Now(),
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

func getGoogleUserInfo(ctx context.Context, accessToken string) (*GoogleUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google API error: %s", string(body))
	}

	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
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
