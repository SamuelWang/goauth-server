package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateClient(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	// Prerequisites
	user := createTestUser(t, queries, "clientcreate")

	t.Run("create client with all fields", func(t *testing.T) {
		isActive := true
		desc := "My test client"
		params := CreateClientParams{
			Name:             "my-test-client",
			Description:      &desc,
			ClientSecretHash: "$2a$12$hashedpassword",
			RedirectUris:     []string{"https://example.com/callback"},
			GrantTypes:       []string{"authorization_code"},
			IsActive:         &isActive,
			CreatedBy:        user.ID,
		}

		client, err := queries.CreateClient(ctx, params)
		require.NoError(t, err)

		assert.NotEqual(t, uuid.Nil, client.ID)
		assert.Equal(t, params.Name, client.Name)
		assert.Equal(t, &desc, client.Description)
		assert.Equal(t, params.ClientSecretHash, client.ClientSecretHash)
		assert.Equal(t, params.RedirectUris, client.RedirectUris)
		assert.Equal(t, params.GrantTypes, client.GrantTypes)
		assert.Equal(t, &isActive, client.IsActive)
		assert.Equal(t, user.ID, client.CreatedBy)
		assert.NotZero(t, client.CreatedAt)
		assert.NotZero(t, client.UpdatedAt)
	})

	t.Run("create client with minimal fields", func(t *testing.T) {
		params := CreateClientParams{
			Name:             "minimal-client",
			ClientSecretHash: "$2a$12$minimal",
			RedirectUris:     []string{"https://minimal.example.com/cb"},
			GrantTypes:       []string{"authorization_code"},
			CreatedBy:        user.ID,
		}

		client, err := queries.CreateClient(ctx, params)
		require.NoError(t, err)

		assert.NotEqual(t, uuid.Nil, client.ID)
		assert.Equal(t, params.Name, client.Name)
		assert.Nil(t, client.Description)
	})
}

func TestGetClient(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "getclient")
	client := createTestClient(t, queries, "getclient", user.ID)

	t.Run("get existing client by ID", func(t *testing.T) {
		found, err := queries.GetClient(ctx, client.ID)
		require.NoError(t, err)

		assert.Equal(t, client.ID, found.ID)
		assert.Equal(t, client.Name, found.Name)
	})

	t.Run("get non-existent client returns error", func(t *testing.T) {
		_, err := queries.GetClient(ctx, uuid.New())
		require.Error(t, err)
	})
}

func TestGetClientByID(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "getclientbyid")
	client := createTestClient(t, queries, "getclientbyid", user.ID)

	t.Run("get active client by ID", func(t *testing.T) {
		found, err := queries.GetClientByID(ctx, client.ID)
		require.NoError(t, err)
		assert.Equal(t, client.ID, found.ID)
	})

	t.Run("get inactive client returns error", func(t *testing.T) {
		// Soft delete the client (sets is_active = false)
		err := queries.DeleteClient(ctx, client.ID)
		require.NoError(t, err)

		_, err = queries.GetClientByID(ctx, client.ID)
		require.Error(t, err)
	})

	t.Run("get non-existent client by ID returns error", func(t *testing.T) {
		_, err := queries.GetClientByID(ctx, uuid.New())
		require.Error(t, err)
	})
}

func TestListClients(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "listclient")

	// Create 3 clients
	for i := 0; i < 3; i++ {
		createTestClient(t, queries, "listclient", user.ID)
	}

	t.Run("list all clients with pagination", func(t *testing.T) {
		// Column1=true: is_active=true (active clients only)
		clients, err := queries.ListClients(ctx, ListClientsParams{Column1: true, Limit: 100, Offset: 0})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(clients), 3)
	})

	t.Run("list clients with limit", func(t *testing.T) {
		clients, err := queries.ListClients(ctx, ListClientsParams{Column1: true, Limit: 2, Offset: 0})
		require.NoError(t, err)
		assert.LessOrEqual(t, len(clients), 2)
	})

	t.Run("list clients with offset", func(t *testing.T) {
		allClients, err := queries.ListClients(ctx, ListClientsParams{Column1: true, Limit: 100, Offset: 0})
		require.NoError(t, err)
		offsetClients, err := queries.ListClients(ctx, ListClientsParams{Column1: true, Limit: 100, Offset: 1})
		require.NoError(t, err)
		assert.Equal(t, len(allClients)-1, len(offsetClients))
	})
}

func TestCountClients(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "countclient")

	createTestClient(t, queries, "countclient", user.ID)
	createTestClient(t, queries, "countclient", user.ID)

	t.Run("count all clients", func(t *testing.T) {
		// Pass true to count active clients
		count, err := queries.CountClients(ctx, true)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, int64(2))
	})
}

func TestUpdateClient(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "updateclient")
	client := createTestClient(t, queries, "updateclient", user.ID)

	t.Run("update client name and redirect URIs", func(t *testing.T) {
		newName := "updated-client-name"
		newDesc := "Updated description"

		updated, err := queries.UpdateClient(ctx, UpdateClientParams{
			ID:           client.ID,
			Name:         newName,
			Description:  &newDesc,
			RedirectUris: []string{"https://updated.example.com/callback"},
			GrantTypes:   []string{"authorization_code", "refresh_token"},
		})
		require.NoError(t, err)

		assert.Equal(t, client.ID, updated.ID)
		assert.Equal(t, newName, updated.Name)
		assert.Equal(t, &newDesc, updated.Description)
		assert.Equal(t, []string{"https://updated.example.com/callback"}, updated.RedirectUris)
		assert.Equal(t, []string{"authorization_code", "refresh_token"}, updated.GrantTypes)
	})

	t.Run("update non-existent client returns error", func(t *testing.T) {
		_, err := queries.UpdateClient(ctx, UpdateClientParams{
			ID:           uuid.New(),
			Name:         "ghost",
			RedirectUris: []string{"https://example.com/cb"},
			GrantTypes:   []string{"authorization_code"},
		})
		require.Error(t, err)
	})
}

func TestRegenerateClientSecret(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "regenSecret")
	client := createTestClient(t, queries, "regenSecret", user.ID)

	t.Run("regenerate client secret", func(t *testing.T) {
		newHash := "$2a$12$newhashedpasswordvalue"
		updated, err := queries.RegenerateClientSecret(ctx, RegenerateClientSecretParams{
			ID:               client.ID,
			ClientSecretHash: newHash,
		})
		require.NoError(t, err)
		assert.Equal(t, client.ID, updated.ID)
		assert.Equal(t, newHash, updated.ClientSecretHash)
		assert.NotEqual(t, client.ClientSecretHash, updated.ClientSecretHash)
	})

	t.Run("regenerate secret for non-existent client returns error", func(t *testing.T) {
		_, err := queries.RegenerateClientSecret(ctx, RegenerateClientSecretParams{
			ID:               uuid.New(),
			ClientSecretHash: "$2a$12$anyhash",
		})
		require.Error(t, err)
	})
}

func TestDeleteClient(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "deleteclient")
	client := createTestClient(t, queries, "deleteclient", user.ID)

	t.Run("soft delete client sets is_active to false", func(t *testing.T) {
		err := queries.DeleteClient(ctx, client.ID)
		require.NoError(t, err)

		// GetClient still returns it
		found, err := queries.GetClient(ctx, client.ID)
		require.NoError(t, err)
		assert.NotNil(t, found.IsActive)
		assert.False(t, *found.IsActive)

		// GetClientByID (active only) should not find it
		_, err = queries.GetClientByID(ctx, client.ID)
		require.Error(t, err)
	})

	t.Run("delete non-existent client is a no-op", func(t *testing.T) {
		// DeleteClient is an :exec query; pgx does not error on 0 rows affected
		err := queries.DeleteClient(ctx, uuid.New())
		require.NoError(t, err)
	})
}

func TestCreateClientWithV030Fields(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "createclientv030")

	t.Run("is_confidential and allow_refresh_tokens default to false when not set", func(t *testing.T) {
		client, err := queries.CreateClient(ctx, CreateClientParams{
			Name:             "default-fields-client",
			ClientSecretHash: "sha256hexhash",
			RedirectUris:     []string{"https://example.com/callback"},
			GrantTypes:       []string{"authorization_code"},
			CreatedBy:        user.ID,
		})
		require.NoError(t, err)

		assert.False(t, client.IsConfidential)
		assert.False(t, client.AllowRefreshTokens)
	})

	t.Run("creates confidential client with refresh tokens enabled", func(t *testing.T) {
		isActive := true
		client, err := queries.CreateClient(ctx, CreateClientParams{
			Name:               "confidential-refresh-client",
			ClientSecretHash:   "sha256hexhash",
			RedirectUris:       []string{"https://example.com/callback"},
			GrantTypes:         []string{"authorization_code", "refresh_token"},
			IsActive:           &isActive,
			CreatedBy:          user.ID,
			IsConfidential:     true,
			AllowRefreshTokens: true,
		})
		require.NoError(t, err)

		assert.True(t, client.IsConfidential)
		assert.True(t, client.AllowRefreshTokens)
	})

	t.Run("creates public client without refresh tokens", func(t *testing.T) {
		client, err := queries.CreateClient(ctx, CreateClientParams{
			Name:               "public-client",
			ClientSecretHash:   "sha256hexhash",
			RedirectUris:       []string{"https://example.com/callback"},
			GrantTypes:         []string{"authorization_code"},
			CreatedBy:          user.ID,
			IsConfidential:     false,
			AllowRefreshTokens: false,
		})
		require.NoError(t, err)

		assert.False(t, client.IsConfidential)
		assert.False(t, client.AllowRefreshTokens)
	})

	t.Run("GetClient returns is_confidential and allow_refresh_tokens fields", func(t *testing.T) {
		created, err := queries.CreateClient(ctx, CreateClientParams{
			Name:               "getcheck-client",
			ClientSecretHash:   "sha256hexhash",
			RedirectUris:       []string{"https://example.com/callback"},
			GrantTypes:         []string{"authorization_code"},
			CreatedBy:          user.ID,
			IsConfidential:     true,
			AllowRefreshTokens: true,
		})
		require.NoError(t, err)

		fetched, err := queries.GetClient(ctx, created.ID)
		require.NoError(t, err)

		assert.Equal(t, created.IsConfidential, fetched.IsConfidential)
		assert.Equal(t, created.AllowRefreshTokens, fetched.AllowRefreshTokens)
		assert.True(t, fetched.IsConfidential)
		assert.True(t, fetched.AllowRefreshTokens)
	})

	t.Run("UpdateClient can mutate is_confidential and allow_refresh_tokens", func(t *testing.T) {
		created, err := queries.CreateClient(ctx, CreateClientParams{
			Name:               "update-new-fields-client",
			ClientSecretHash:   "sha256hexhash",
			RedirectUris:       []string{"https://example.com/callback"},
			GrantTypes:         []string{"authorization_code"},
			CreatedBy:          user.ID,
			IsConfidential:     false,
			AllowRefreshTokens: false,
		})
		require.NoError(t, err)

		updated, err := queries.UpdateClient(ctx, UpdateClientParams{
			ID:                 created.ID,
			Name:               created.Name,
			RedirectUris:       created.RedirectUris,
			GrantTypes:         []string{"authorization_code", "refresh_token"},
			IsConfidential:     true,
			AllowRefreshTokens: true,
		})
		require.NoError(t, err)

		assert.True(t, updated.IsConfidential)
		assert.True(t, updated.AllowRefreshTokens)
	})
}
