package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildAuthCodeParams returns a minimal valid CreateAuthorizationCodeParams.
func buildAuthCodeParams(clientID, userID, providerID uuid.UUID) CreateAuthorizationCodeParams {
	return CreateAuthorizationCodeParams{
		Code:        uuid.New().String(),
		ClientID:    clientID,
		UserID:      userID,
		ProviderID:  providerID,
		RedirectUri: "https://example.com/callback",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
}

func TestCreateAuthorizationCode(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "authcode")
	client := createTestClient(t, queries, "authcode", user.ID)
	provider := createTestOAuthProvider(t, queries, "authcode", client.ID)

	t.Run("create authorization code with required fields", func(t *testing.T) {
		params := buildAuthCodeParams(client.ID, user.ID, provider.ID)

		code, err := queries.CreateAuthorizationCode(ctx, params)
		require.NoError(t, err)

		assert.NotEqual(t, uuid.Nil, code.ID)
		assert.Equal(t, params.Code, code.Code)
		assert.Equal(t, client.ID, code.ClientID)
		assert.Equal(t, user.ID, code.UserID)
		assert.Equal(t, provider.ID, code.ProviderID)
		assert.Equal(t, params.RedirectUri, code.RedirectUri)
		assert.WithinDuration(t, params.ExpiresAt, code.ExpiresAt, time.Second)
		assert.NotZero(t, code.CreatedAt)
	})

	t.Run("create authorization code with optional fields", func(t *testing.T) {
		scope := "openid email profile"
		state := "random-state-value"
		challenge := "code-challenge"
		method := "S256"

		params := buildAuthCodeParams(client.ID, user.ID, provider.ID)
		params.Scope = &scope
		params.State = &state
		params.CodeChallenge = &challenge
		params.CodeChallengeMethod = &method

		code, err := queries.CreateAuthorizationCode(ctx, params)
		require.NoError(t, err)

		assert.Equal(t, &scope, code.Scope)
		assert.Equal(t, &state, code.State)
		assert.Equal(t, &challenge, code.CodeChallenge)
		assert.Equal(t, &method, code.CodeChallengeMethod)
	})

	t.Run("duplicate code value fails", func(t *testing.T) {
		params := buildAuthCodeParams(client.ID, user.ID, provider.ID)

		_, err := queries.CreateAuthorizationCode(ctx, params)
		require.NoError(t, err)

		// Same code string again
		_, err = queries.CreateAuthorizationCode(ctx, params)
		require.Error(t, err)
	})
}

func TestGetAuthorizationCode(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "getauthcode")
	client := createTestClient(t, queries, "getauthcode", user.ID)
	provider := createTestOAuthProvider(t, queries, "getauthcode", client.ID)

	params := buildAuthCodeParams(client.ID, user.ID, provider.ID)
	created, err := queries.CreateAuthorizationCode(ctx, params)
	require.NoError(t, err)

	t.Run("get code by code string", func(t *testing.T) {
		found, err := queries.GetAuthorizationCode(ctx, params.Code)
		require.NoError(t, err)
		assert.Equal(t, created.ID, found.ID)
		assert.Equal(t, params.Code, found.Code)
	})

	t.Run("get non-existent code returns error", func(t *testing.T) {
		_, err := queries.GetAuthorizationCode(ctx, "nonexistent-code")
		require.Error(t, err)
	})
}

func TestGetAuthorizationCodeByID(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "getauthcodebyid")
	client := createTestClient(t, queries, "getauthcodebyid", user.ID)
	provider := createTestOAuthProvider(t, queries, "getauthcodebyid", client.ID)

	params := buildAuthCodeParams(client.ID, user.ID, provider.ID)
	created, err := queries.CreateAuthorizationCode(ctx, params)
	require.NoError(t, err)

	t.Run("get code by ID", func(t *testing.T) {
		found, err := queries.GetAuthorizationCodeByID(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, found.ID)
		assert.Equal(t, params.Code, found.Code)
	})

	t.Run("get non-existent code ID returns error", func(t *testing.T) {
		_, err := queries.GetAuthorizationCodeByID(ctx, uuid.New())
		require.Error(t, err)
	})
}

func TestMarkAuthorizationCodeUsed(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "markused")
	client := createTestClient(t, queries, "markused", user.ID)
	provider := createTestOAuthProvider(t, queries, "markused", client.ID)

	params := buildAuthCodeParams(client.ID, user.ID, provider.ID)
	created, err := queries.CreateAuthorizationCode(ctx, params)
	require.NoError(t, err)

	t.Run("mark code as used sets used_at", func(t *testing.T) {
		// used_at should be nil before marking as used
		assert.Nil(t, created.UsedAt)

		updated, err := queries.MarkAuthorizationCodeUsed(ctx, created.ID)
		require.NoError(t, err)
		assert.NotNil(t, updated.UsedAt)
	})

	t.Run("mark non-existent code returns error", func(t *testing.T) {
		_, err := queries.MarkAuthorizationCodeUsed(ctx, uuid.New())
		require.Error(t, err)
	})
}

func TestRevokeAuthorizationCode(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "revokeauthcode")
	client := createTestClient(t, queries, "revokeauthcode", user.ID)
	provider := createTestOAuthProvider(t, queries, "revokeauthcode", client.ID)

	t.Run("revoke code by ID", func(t *testing.T) {
		params := buildAuthCodeParams(client.ID, user.ID, provider.ID)
		created, err := queries.CreateAuthorizationCode(ctx, params)
		require.NoError(t, err)

		err = queries.RevokeAuthorizationCode(ctx, created.ID)
		require.NoError(t, err)

		found, err := queries.GetAuthorizationCodeByID(ctx, created.ID)
		require.NoError(t, err)
		assert.NotNil(t, found.IsRevoked)
		assert.True(t, *found.IsRevoked)
	})

	t.Run("revoke code by code string", func(t *testing.T) {
		params := buildAuthCodeParams(client.ID, user.ID, provider.ID)
		created, err := queries.CreateAuthorizationCode(ctx, params)
		require.NoError(t, err)

		err = queries.RevokeAuthorizationCodeByCode(ctx, params.Code)
		require.NoError(t, err)

		found, err := queries.GetAuthorizationCodeByID(ctx, created.ID)
		require.NoError(t, err)
		assert.NotNil(t, found.IsRevoked)
		assert.True(t, *found.IsRevoked)
	})
}

func TestListAuthorizationCodes(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "listauthcodes")
	client := createTestClient(t, queries, "listauthcodes", user.ID)
	provider := createTestOAuthProvider(t, queries, "listauthcodes", client.ID)

	// Create 3 codes
	for i := 0; i < 3; i++ {
		_, err := queries.CreateAuthorizationCode(ctx, buildAuthCodeParams(client.ID, user.ID, provider.ID))
		require.NoError(t, err)
	}

	t.Run("list all codes with pagination", func(t *testing.T) {
		// Filter by known client and user IDs
		codes, err := queries.ListAuthorizationCodes(ctx, ListAuthorizationCodesParams{
			Column1: client.ID, Column2: user.ID, Column3: false, Limit: 100, Offset: 0,
		})
		require.NoError(t, err)
		assert.Len(t, codes, 3)
	})

	t.Run("list codes with limit", func(t *testing.T) {
		codes, err := queries.ListAuthorizationCodes(ctx, ListAuthorizationCodesParams{
			Column1: client.ID, Column2: user.ID, Column3: false, Limit: 2, Offset: 0,
		})
		require.NoError(t, err)
		assert.Len(t, codes, 2)
	})
}

func TestCountAuthorizationCodes(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "countauthcodes")
	client := createTestClient(t, queries, "countauthcodes", user.ID)
	provider := createTestOAuthProvider(t, queries, "countauthcodes", client.ID)

	for i := 0; i < 2; i++ {
		_, err := queries.CreateAuthorizationCode(ctx, buildAuthCodeParams(client.ID, user.ID, provider.ID))
		require.NoError(t, err)
	}

	t.Run("count all codes", func(t *testing.T) {
		count, err := queries.CountAuthorizationCodes(ctx, CountAuthorizationCodesParams{
			Column1: client.ID, Column2: user.ID, Column3: false,
		})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, int64(2))
	})
}

func TestDeleteExpiredAuthorizationCodes(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "expireauthcode")
	client := createTestClient(t, queries, "expireauthcode", user.ID)
	provider := createTestOAuthProvider(t, queries, "expireauthcode", client.ID)

	// Create an already-expired code
	expiredParams := buildAuthCodeParams(client.ID, user.ID, provider.ID)
	expiredParams.ExpiresAt = time.Now().Add(-1 * time.Hour) // in the past
	expired, err := queries.CreateAuthorizationCode(ctx, expiredParams)
	require.NoError(t, err)

	// Create a valid code
	validParams := buildAuthCodeParams(client.ID, user.ID, provider.ID)
	valid, err := queries.CreateAuthorizationCode(ctx, validParams)
	require.NoError(t, err)

	t.Run("cleanup deletes expired codes only", func(t *testing.T) {
		err := queries.DeleteExpiredAuthorizationCodes(ctx)
		require.NoError(t, err)

		// Expired code should be gone
		_, err = queries.GetAuthorizationCodeByID(ctx, expired.ID)
		require.Error(t, err)

		// Valid code should still exist
		found, err := queries.GetAuthorizationCodeByID(ctx, valid.ID)
		require.NoError(t, err)
		assert.Equal(t, valid.ID, found.ID)
	})
}
