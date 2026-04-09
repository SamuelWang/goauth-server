package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildAccessTokenParams returns a minimal valid CreateAccessTokenParams.
func buildAccessTokenParams(clientID, userID uuid.UUID) CreateAccessTokenParams {
	return CreateAccessTokenParams{
		TokenHash: uuid.New().String(), // use UUID as stand-in for a token hash
		ClientID:  &clientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(60 * time.Minute),
	}
}

func TestCreateAccessToken(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "accesstoken")
	client := createTestClient(t, queries, "accesstoken", user.ID)

	t.Run("create access token with required fields", func(t *testing.T) {
		params := buildAccessTokenParams(client.ID, user.ID)

		token, err := queries.CreateAccessToken(ctx, params)
		require.NoError(t, err)

		assert.NotEqual(t, uuid.Nil, token.ID)
		assert.Equal(t, params.TokenHash, token.TokenHash)
		assert.Equal(t, &client.ID, token.ClientID)
		assert.Equal(t, user.ID, token.UserID)
		assert.WithinDuration(t, params.ExpiresAt, token.ExpiresAt, time.Second)
		assert.NotZero(t, token.CreatedAt)
		assert.NotNil(t, token.IsRevoked)
		assert.False(t, *token.IsRevoked)
	})

	t.Run("create access token with scope", func(t *testing.T) {
		scope := "openid email profile"
		params := buildAccessTokenParams(client.ID, user.ID)
		params.Scope = &scope

		token, err := queries.CreateAccessToken(ctx, params)
		require.NoError(t, err)
		assert.Equal(t, &scope, token.Scope)
	})

	t.Run("duplicate token_hash fails", func(t *testing.T) {
		params := buildAccessTokenParams(client.ID, user.ID)

		_, err := queries.CreateAccessToken(ctx, params)
		require.NoError(t, err)

		// Same token_hash again
		_, err = queries.CreateAccessToken(ctx, params)
		require.Error(t, err)
	})
}

func TestGetAccessToken(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "gettoken")
	client := createTestClient(t, queries, "gettoken", user.ID)

	params := buildAccessTokenParams(client.ID, user.ID)
	created, err := queries.CreateAccessToken(ctx, params)
	require.NoError(t, err)

	t.Run("get existing token by hash", func(t *testing.T) {
		found, err := queries.GetAccessToken(ctx, params.TokenHash)
		require.NoError(t, err)
		assert.Equal(t, created.ID, found.ID)
		assert.Equal(t, params.TokenHash, found.TokenHash)
	})

	t.Run("get non-existent token hash returns error", func(t *testing.T) {
		_, err := queries.GetAccessToken(ctx, "nonexistent-hash")
		require.Error(t, err)
	})
}

func TestGetAccessTokenByID(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "gettokenbyid")
	client := createTestClient(t, queries, "gettokenbyid", user.ID)

	params := buildAccessTokenParams(client.ID, user.ID)
	created, err := queries.CreateAccessToken(ctx, params)
	require.NoError(t, err)

	t.Run("get token by ID", func(t *testing.T) {
		found, err := queries.GetAccessTokenByID(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, found.ID)
	})

	t.Run("get non-existent token ID returns error", func(t *testing.T) {
		_, err := queries.GetAccessTokenByID(ctx, uuid.New())
		require.Error(t, err)
	})
}

func TestRevokeAccessToken(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "revoketoken")
	client := createTestClient(t, queries, "revoketoken", user.ID)

	t.Run("revoke token by ID sets is_revoked true", func(t *testing.T) {
		params := buildAccessTokenParams(client.ID, user.ID)
		created, err := queries.CreateAccessToken(ctx, params)
		require.NoError(t, err)
		assert.False(t, *created.IsRevoked)

		err = queries.RevokeAccessToken(ctx, created.ID)
		require.NoError(t, err)

		found, err := queries.GetAccessTokenByID(ctx, created.ID)
		require.NoError(t, err)
		assert.NotNil(t, found.IsRevoked)
		assert.True(t, *found.IsRevoked)
	})
}

func TestRevokeAccessTokensByClient(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "revokebyclient")
	client := createTestClient(t, queries, "revokebyclient", user.ID)
	otherClient := createTestClient(t, queries, "revokebyclient-other", user.ID)

	// Create tokens for both clients
	t1, err := queries.CreateAccessToken(ctx, buildAccessTokenParams(client.ID, user.ID))
	require.NoError(t, err)
	t2, err := queries.CreateAccessToken(ctx, buildAccessTokenParams(client.ID, user.ID))
	require.NoError(t, err)
	t3, err := queries.CreateAccessToken(ctx, buildAccessTokenParams(otherClient.ID, user.ID))
	require.NoError(t, err)

	t.Run("revoke all tokens for a client", func(t *testing.T) {
		err := queries.RevokeAccessTokensByClient(ctx, client.ID)
		require.NoError(t, err)

		// Tokens for client should be revoked
		found1, err := queries.GetAccessTokenByID(ctx, t1.ID)
		require.NoError(t, err)
		assert.True(t, *found1.IsRevoked)

		found2, err := queries.GetAccessTokenByID(ctx, t2.ID)
		require.NoError(t, err)
		assert.True(t, *found2.IsRevoked)

		// Token for other client should not be revoked
		found3, err := queries.GetAccessTokenByID(ctx, t3.ID)
		require.NoError(t, err)
		assert.False(t, *found3.IsRevoked)
	})
}

func TestRevokeAccessTokensByUser(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user1 := createTestUser(t, queries, "revokebyuser1")
	user2 := createTestUser(t, queries, "revokebyuser2")
	client := createTestClient(t, queries, "revokebyuser", user1.ID)

	// Create tokens for both users
	t1, err := queries.CreateAccessToken(ctx, buildAccessTokenParams(client.ID, user1.ID))
	require.NoError(t, err)
	t2, err := queries.CreateAccessToken(ctx, buildAccessTokenParams(client.ID, user2.ID))
	require.NoError(t, err)

	t.Run("revoke all tokens for a user", func(t *testing.T) {
		err := queries.RevokeAccessTokensByUser(ctx, user1.ID)
		require.NoError(t, err)

		found1, err := queries.GetAccessTokenByID(ctx, t1.ID)
		require.NoError(t, err)
		assert.True(t, *found1.IsRevoked)

		// user2's token should not be revoked
		found2, err := queries.GetAccessTokenByID(ctx, t2.ID)
		require.NoError(t, err)
		assert.False(t, *found2.IsRevoked)
	})
}

func TestListAccessTokens(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "listtokens")
	client := createTestClient(t, queries, "listtokens", user.ID)

	// Create 3 tokens
	for i := 0; i < 3; i++ {
		_, err := queries.CreateAccessToken(ctx, buildAccessTokenParams(client.ID, user.ID))
		require.NoError(t, err)
	}

	t.Run("list all tokens with pagination", func(t *testing.T) {
		// Filter by client.ID and user.ID so zero-value UUID isn't used
		tokens, err := queries.ListAccessTokens(ctx, ListAccessTokensParams{
			Column1: client.ID, Column2: user.ID, Column3: false, Limit: 100, Offset: 0,
		})
		require.NoError(t, err)
		assert.Len(t, tokens, 3)
	})

	t.Run("list tokens with limit", func(t *testing.T) {
		tokens, err := queries.ListAccessTokens(ctx, ListAccessTokensParams{
			Column1: client.ID, Column2: user.ID, Column3: false, Limit: 2, Offset: 0,
		})
		require.NoError(t, err)
		assert.Len(t, tokens, 2)
	})

	t.Run("list tokens with offset", func(t *testing.T) {
		tokens, err := queries.ListAccessTokens(ctx, ListAccessTokensParams{
			Column1: client.ID, Column2: user.ID, Column3: false, Limit: 100, Offset: 1,
		})
		require.NoError(t, err)
		// 3 tokens, offset by 1 → 2 remaining
		assert.Len(t, tokens, 2)
	})
}

func TestCountAccessTokens(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "counttokens")
	client := createTestClient(t, queries, "counttokens", user.ID)

	for i := 0; i < 2; i++ {
		_, err := queries.CreateAccessToken(ctx, buildAccessTokenParams(client.ID, user.ID))
		require.NoError(t, err)
	}

	t.Run("count all tokens", func(t *testing.T) {
		// Filter by client.ID and user.ID; Column3=false means is_revoked=false
		count, err := queries.CountAccessTokens(ctx, CountAccessTokensParams{
			Column1: client.ID, Column2: user.ID, Column3: false,
		})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, int64(2))
	})
}

func TestDeleteExpiredAccessTokens(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "expiretoken")
	client := createTestClient(t, queries, "expiretoken", user.ID)

	// Create an already-expired token
	expiredParams := buildAccessTokenParams(client.ID, user.ID)
	expiredParams.ExpiresAt = time.Now().Add(-1 * time.Hour) // past
	expired, err := queries.CreateAccessToken(ctx, expiredParams)
	require.NoError(t, err)

	// Create a valid token
	validParams := buildAccessTokenParams(client.ID, user.ID)
	valid, err := queries.CreateAccessToken(ctx, validParams)
	require.NoError(t, err)

	t.Run("cleanup deletes expired tokens only", func(t *testing.T) {
		err := queries.DeleteExpiredAccessTokens(ctx)
		require.NoError(t, err)

		// Expired token should be deleted
		_, err = queries.GetAccessTokenByID(ctx, expired.ID)
		require.Error(t, err)

		// Valid token should still exist
		found, err := queries.GetAccessTokenByID(ctx, valid.ID)
		require.NoError(t, err)
		assert.Equal(t, valid.ID, found.ID)
	})
}
