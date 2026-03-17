package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateOAuthProvider(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "providerc")
	client := createTestClient(t, queries, "providerc", user.ID)

	t.Run("create provider with all fields", func(t *testing.T) {
		isEnabled := true
		params := CreateOAuthProviderParams{
			ClientID:             client.ID,
			Name:                 "google",
			DisplayName:          "Google",
			ProviderClientID:     "gid-123",
			ProviderClientSecret: "gsecret-456",
			AuthUrl:              "https://accounts.google.com/o/oauth2/auth",
			TokenUrl:             "https://oauth2.googleapis.com/token",
			UserInfoUrl:          "https://www.googleapis.com/oauth2/v3/userinfo",
			Scopes:               []string{"openid", "email", "profile"},
			IsEnabled:            &isEnabled,
		}

		provider, err := queries.CreateOAuthProvider(ctx, params)
		require.NoError(t, err)

		assert.NotEqual(t, uuid.Nil, provider.ID)
		assert.Equal(t, client.ID, provider.ClientID)
		assert.Equal(t, "google", provider.Name)
		assert.Equal(t, "Google", provider.DisplayName)
		assert.Equal(t, params.ProviderClientID, provider.ProviderClientID)
		assert.Equal(t, params.ProviderClientSecret, provider.ProviderClientSecret)
		assert.Equal(t, params.AuthUrl, provider.AuthUrl)
		assert.Equal(t, params.TokenUrl, provider.TokenUrl)
		assert.Equal(t, params.UserInfoUrl, provider.UserInfoUrl)
		assert.Equal(t, params.Scopes, provider.Scopes)
		assert.NotNil(t, provider.IsEnabled)
		assert.True(t, *provider.IsEnabled)
		assert.NotZero(t, provider.CreatedAt)
		assert.NotZero(t, provider.UpdatedAt)
	})

	t.Run("create provider with is_enabled false", func(t *testing.T) {
		isEnabled := false
		params := CreateOAuthProviderParams{
			ClientID:             client.ID,
			Name:                 "ep-disabled-new",
			DisplayName:          "GitHub (disabled)",
			ProviderClientID:     "gh-client",
			ProviderClientSecret: "gh-secret",
			AuthUrl:              "https://github.com/login/oauth/authorize",
			TokenUrl:             "https://github.com/login/oauth/access_token",
			UserInfoUrl:          "https://api.github.com/user",
			Scopes:               []string{"read:user", "user:email"},
			IsEnabled:            &isEnabled,
		}

		provider, err := queries.CreateOAuthProvider(ctx, params)
		require.NoError(t, err)
		assert.NotNil(t, provider.IsEnabled)
		assert.False(t, *provider.IsEnabled)
	})

	t.Run("same provider name for different clients is allowed", func(t *testing.T) {
		user2 := createTestUser(t, queries, "diffclient")
		client2 := createTestClient(t, queries, "diffclient", user2.ID)

		isEnabled := true
		sharedName := "shared-provider-name"
		paramsA := CreateOAuthProviderParams{
			ClientID:             client.ID,
			Name:                 sharedName,
			DisplayName:          "Shared",
			ProviderClientID:     "id-a",
			ProviderClientSecret: "sec-a",
			AuthUrl:              "https://auth.example.com",
			TokenUrl:             "https://token.example.com",
			UserInfoUrl:          "https://userinfo.example.com",
			Scopes:               []string{"openid"},
			IsEnabled:            &isEnabled,
		}
		paramsB := CreateOAuthProviderParams{
			ClientID:             client2.ID,
			Name:                 sharedName,
			DisplayName:          "Shared",
			ProviderClientID:     "id-b",
			ProviderClientSecret: "sec-b",
			AuthUrl:              "https://auth.example.com",
			TokenUrl:             "https://token.example.com",
			UserInfoUrl:          "https://userinfo.example.com",
			Scopes:               []string{"openid"},
			IsEnabled:            &isEnabled,
		}

		_, err := queries.CreateOAuthProvider(ctx, paramsA)
		require.NoError(t, err)
		_, err = queries.CreateOAuthProvider(ctx, paramsB)
		require.NoError(t, err)
	})

	// duplicate test last — intentional error aborts the transaction, so no subtests follow
	t.Run("duplicate provider name per client fails", func(t *testing.T) {
		isEnabled := true
		params := CreateOAuthProviderParams{
			ClientID:             client.ID,
			Name:                 "unique-constraint-test",
			DisplayName:          "Test",
			ProviderClientID:     "id1",
			ProviderClientSecret: "sec1",
			AuthUrl:              "https://auth.example.com",
			TokenUrl:             "https://token.example.com",
			UserInfoUrl:          "https://userinfo.example.com",
			Scopes:               []string{"openid"},
			IsEnabled:            &isEnabled,
		}

		_, err := queries.CreateOAuthProvider(ctx, params)
		require.NoError(t, err)

		// Same name for same client should fail
		_, err = queries.CreateOAuthProvider(ctx, params)
		require.Error(t, err)
	})
}

func TestGetOAuthProvider(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "getprovider")
	client := createTestClient(t, queries, "getprovider", user.ID)
	provider := createTestOAuthProvider(t, queries, "getprovider", client.ID)

	t.Run("get provider by ID", func(t *testing.T) {
		found, err := queries.GetOAuthProvider(ctx, provider.ID)
		require.NoError(t, err)
		assert.Equal(t, provider.ID, found.ID)
		assert.Equal(t, provider.Name, found.Name)
		assert.Equal(t, client.ID, found.ClientID)
	})

	t.Run("get non-existent provider returns error", func(t *testing.T) {
		_, err := queries.GetOAuthProvider(ctx, uuid.New())
		require.Error(t, err)
	})
}

func TestGetOAuthProviderByClientAndName(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "getbyname")
	client := createTestClient(t, queries, "getbyname", user.ID)
	provider := createTestOAuthProvider(t, queries, "getbyname", client.ID)

	t.Run("get provider by client and name", func(t *testing.T) {
		found, err := queries.GetOAuthProviderByClientAndName(ctx, GetOAuthProviderByClientAndNameParams{
			ClientID: client.ID,
			Name:     provider.Name,
		})
		require.NoError(t, err)
		assert.Equal(t, provider.ID, found.ID)
	})

	t.Run("get with wrong client ID returns error", func(t *testing.T) {
		_, err := queries.GetOAuthProviderByClientAndName(ctx, GetOAuthProviderByClientAndNameParams{
			ClientID: uuid.New(),
			Name:     provider.Name,
		})
		require.Error(t, err)
	})

	t.Run("get with wrong name returns error", func(t *testing.T) {
		_, err := queries.GetOAuthProviderByClientAndName(ctx, GetOAuthProviderByClientAndNameParams{
			ClientID: client.ID,
			Name:     "nonexistent-provider",
		})
		require.Error(t, err)
	})
}

func TestListOAuthProvidersByClient(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "listprovider")
	client := createTestClient(t, queries, "listprovider", user.ID)
	otherClient := createTestClient(t, queries, "listprovider-other", user.ID)

	// Create 2 providers for main client, 1 for other client
	createTestOAuthProvider(t, queries, "lp1", client.ID)
	createTestOAuthProvider(t, queries, "lp2", client.ID)
	createTestOAuthProvider(t, queries, "lp3", otherClient.ID)

	t.Run("list all providers for a client", func(t *testing.T) {
		providers, err := queries.ListOAuthProvidersByClient(ctx, client.ID)
		require.NoError(t, err)
		assert.Len(t, providers, 2)
		for _, p := range providers {
			assert.Equal(t, client.ID, p.ClientID)
		}
	})

	t.Run("list providers for client with no providers returns empty", func(t *testing.T) {
		emptyUser := createTestUser(t, queries, "emptyprovider")
		emptyClient := createTestClient(t, queries, "emptyprovider", emptyUser.ID)

		providers, err := queries.ListOAuthProvidersByClient(ctx, emptyClient.ID)
		require.NoError(t, err)
		assert.Empty(t, providers)
	})
}

func TestListEnabledOAuthProvidersByClient(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "enabledprovider")
	client := createTestClient(t, queries, "enabledprovider", user.ID)

	// Create one enabled and one disabled provider
	isEnabled := true
	isDisabled := false

	_, err := queries.CreateOAuthProvider(ctx, CreateOAuthProviderParams{
		ClientID: client.ID, Name: "ep-enabled", DisplayName: "Enabled", ProviderClientID: "id1",
		ProviderClientSecret: "sec1", AuthUrl: "https://auth.example.com", TokenUrl: "https://token.example.com",
		UserInfoUrl: "https://user.example.com", Scopes: []string{"openid"}, IsEnabled: &isEnabled,
	})
	require.NoError(t, err)

	_, err = queries.CreateOAuthProvider(ctx, CreateOAuthProviderParams{
		ClientID: client.ID, Name: "ep-disabled", DisplayName: "Disabled", ProviderClientID: "id2",
		ProviderClientSecret: "sec2", AuthUrl: "https://auth.example.com", TokenUrl: "https://token.example.com",
		UserInfoUrl: "https://user.example.com", Scopes: []string{"openid"}, IsEnabled: &isDisabled,
	})
	require.NoError(t, err)

	t.Run("list only enabled providers", func(t *testing.T) {
		providers, err := queries.ListEnabledOAuthProvidersByClient(ctx, client.ID)
		require.NoError(t, err)
		assert.Len(t, providers, 1)
		assert.Equal(t, "ep-enabled", providers[0].Name)
		assert.True(t, *providers[0].IsEnabled)
	})
}

func TestUpdateOAuthProvider(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "updateprovider")
	client := createTestClient(t, queries, "updateprovider", user.ID)
	provider := createTestOAuthProvider(t, queries, "updateprovider", client.ID)

	t.Run("update provider fields", func(t *testing.T) {
		isEnabled := false
		updated, err := queries.UpdateOAuthProvider(ctx, UpdateOAuthProviderParams{
			ID:                   provider.ID,
			DisplayName:          "Updated Google",
			ProviderClientID:     "new-client-id",
			ProviderClientSecret: "new-client-secret",
			AuthUrl:              "https://updated-auth.example.com",
			TokenUrl:             "https://updated-token.example.com",
			UserInfoUrl:          "https://updated-userinfo.example.com",
			Scopes:               []string{"openid", "email"},
			IsEnabled:            &isEnabled,
		})
		require.NoError(t, err)

		assert.Equal(t, provider.ID, updated.ID)
		assert.Equal(t, "Updated Google", updated.DisplayName)
		assert.Equal(t, "new-client-id", updated.ProviderClientID)
		assert.False(t, *updated.IsEnabled)
	})

	t.Run("update non-existent provider returns error", func(t *testing.T) {
		isEnabled := true
		_, err := queries.UpdateOAuthProvider(ctx, UpdateOAuthProviderParams{
			ID:          uuid.New(),
			DisplayName: "Ghost",
			IsEnabled:   &isEnabled,
		})
		require.Error(t, err)
	})
}

func TestDisableOAuthProvider(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "disableprovider")
	client := createTestClient(t, queries, "disableprovider", user.ID)
	provider := createTestOAuthProvider(t, queries, "disableprovider", client.ID)

	t.Run("disable an enabled provider", func(t *testing.T) {
		err := queries.DisableOAuthProvider(ctx, provider.ID)
		require.NoError(t, err)

		found, err := queries.GetOAuthProvider(ctx, provider.ID)
		require.NoError(t, err)
		assert.NotNil(t, found.IsEnabled)
		assert.False(t, *found.IsEnabled)
	})
}

func TestDeleteOAuthProvider(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "deleteprovider")
	client := createTestClient(t, queries, "deleteprovider", user.ID)
	provider := createTestOAuthProvider(t, queries, "deleteprovider", client.ID)

	t.Run("delete provider removes it from DB", func(t *testing.T) {
		err := queries.DeleteOAuthProvider(ctx, provider.ID)
		require.NoError(t, err)

		_, err = queries.GetOAuthProvider(ctx, provider.ID)
		require.Error(t, err)
	})

	t.Run("delete non-existent provider is a no-op", func(t *testing.T) {
		err := queries.DeleteOAuthProvider(ctx, uuid.New())
		require.NoError(t, err)
	})
}

func TestProviderCascadeDeleteOnClientDelete(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "cascadeprovider")
	client := createTestClient(t, queries, "cascadeprovider", user.ID)
	provider := createTestOAuthProvider(t, queries, "cascadeprovider", client.ID)

	t.Run("deleting client hard-deletes cascades to provider", func(t *testing.T) {
		// Hard delete the client within the same transaction
		_, err := queries.db.Exec(ctx, "DELETE FROM clients WHERE id = $1", client.ID)
		require.NoError(t, err)

		// Provider should be gone via CASCADE
		_, err = queries.GetOAuthProvider(ctx, provider.ID)
		require.Error(t, err)
	})
}
