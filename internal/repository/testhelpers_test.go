package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// createTestUser creates a test user with a unique email derived from prefix.
func createTestUser(t *testing.T, queries *Queries, prefix string) User {
	t.Helper()
	user, err := queries.CreateUser(context.Background(), CreateUserParams{
		Email:         fmt.Sprintf("%s-%s@example.com", prefix, uuid.New().String()[:8]),
		EmailVerified: true,
		Locale:        "en-US",
		LastLoginAt:   time.Now(),
	})
	require.NoError(t, err)
	return user
}

// createTestClient creates a test client owned by userID.
func createTestClient(t *testing.T, queries *Queries, prefix string, userID uuid.UUID) Client {
	t.Helper()
	isActive := true
	client, err := queries.CreateClient(context.Background(), CreateClientParams{
		Name:             fmt.Sprintf("%s-client-%s", prefix, uuid.New().String()[:8]),
		ClientSecretHash: "$2a$12$placeholder_hash_value_here",
		RedirectUris:     []string{"https://example.com/callback"},
		GrantTypes:       []string{"authorization_code"},
		IsActive:         &isActive,
		CreatedBy:        userID,
	})
	require.NoError(t, err)
	return client
}

// createTestOAuthProvider creates a test OAuth provider scoped to clientID.
func createTestOAuthProvider(t *testing.T, queries *Queries, prefix string, clientID uuid.UUID) OauthProvider {
	t.Helper()
	isEnabled := true
	provider, err := queries.CreateOAuthProvider(context.Background(), CreateOAuthProviderParams{
		ClientID:             clientID,
		Name:                 fmt.Sprintf("%s-google-%s", prefix, uuid.New().String()[:8]),
		DisplayName:          "Google",
		ProviderClientID:     "google-client-id",
		ProviderClientSecret: "google-client-secret",
		AuthUrl:              "https://accounts.google.com/o/oauth2/auth",
		TokenUrl:             "https://oauth2.googleapis.com/token",
		UserInfoUrl:          "https://www.googleapis.com/oauth2/v3/userinfo",
		Scopes:               []string{"openid", "profile", "email"},
		IsEnabled:            &isEnabled,
	})
	require.NoError(t, err)
	return provider
}
