package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestAccessToken creates a minimal access token for use in refresh token tests.
func createTestAccessToken(t *testing.T, queries *Queries, clientID, userID uuid.UUID) AccessToken {
	t.Helper()
	token, err := queries.CreateAccessToken(context.Background(), CreateAccessTokenParams{
		TokenHash: uuid.New().String(),
		ClientID:  &clientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(60 * time.Minute),
	})
	require.NoError(t, err)
	return token
}

// createTestRefreshToken creates a minimal refresh token linked to a given access token.
func createTestRefreshToken(t *testing.T, queries *Queries, clientID, userID, accessTokenID uuid.UUID, familyID uuid.UUID) RefreshToken {
	t.Helper()
	token, err := queries.CreateRefreshToken(context.Background(), CreateRefreshTokenParams{
		TokenHash:       uuid.New().String(),
		TokenFamilyID:   familyID,
		ClientID:        clientID,
		UserID:          userID,
		AccessTokenID:   accessTokenID,
		PreviousTokenID: nil,
		Scope:           "openid offline_access",
		ExpiresAt:       time.Now().Add(30 * 24 * time.Hour),
	})
	require.NoError(t, err)
	return token
}

func TestCreateRefreshToken_GetRefreshTokenByHash(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "refreshtoken")
	client := createTestClient(t, queries, "refreshtoken", user.ID)
	accessToken := createTestAccessToken(t, queries, client.ID, user.ID)

	t.Run("create and retrieve by hash round-trip", func(t *testing.T) {
		familyID := uuid.New()
		tokenHash := uuid.New().String()

		params := CreateRefreshTokenParams{
			TokenHash:       tokenHash,
			TokenFamilyID:   familyID,
			ClientID:        client.ID,
			UserID:          user.ID,
			AccessTokenID:   accessToken.ID,
			PreviousTokenID: nil,
			Scope:           "openid offline_access",
			ExpiresAt:       time.Now().Add(30 * 24 * time.Hour),
		}

		created, err := queries.CreateRefreshToken(ctx, params)
		require.NoError(t, err)

		assert.NotEqual(t, uuid.Nil, created.ID)
		assert.Equal(t, tokenHash, created.TokenHash)
		assert.Equal(t, familyID, created.TokenFamilyID)
		assert.Equal(t, client.ID, created.ClientID)
		assert.Equal(t, user.ID, created.UserID)
		assert.Equal(t, accessToken.ID, created.AccessTokenID)
		assert.Equal(t, "openid offline_access", created.Scope)
		assert.WithinDuration(t, params.ExpiresAt, created.ExpiresAt, time.Second)
		assert.False(t, created.IsRevoked)
		assert.Nil(t, created.UsedAt)
		assert.NotZero(t, created.CreatedAt)

		// Retrieve by hash
		found, err := queries.GetRefreshTokenByHash(ctx, tokenHash)
		require.NoError(t, err)

		assert.Equal(t, created.ID, found.ID)
		assert.Equal(t, tokenHash, found.TokenHash)
		assert.Equal(t, familyID, found.TokenFamilyID)
		assert.Equal(t, client.ID, found.ClientID)
		assert.Equal(t, user.ID, found.UserID)
		assert.False(t, found.IsRevoked)
	})

	t.Run("get non-existent hash returns error", func(t *testing.T) {
		_, err := queries.GetRefreshTokenByHash(ctx, "nonexistent-hash")
		require.Error(t, err)
	})

	t.Run("duplicate token_hash fails", func(t *testing.T) {
		hash := uuid.New().String()
		params := CreateRefreshTokenParams{
			TokenHash:       hash,
			TokenFamilyID:   uuid.New(),
			ClientID:        client.ID,
			UserID:          user.ID,
			AccessTokenID:   accessToken.ID,
			PreviousTokenID: nil,
			Scope:           "openid",
			ExpiresAt:       time.Now().Add(time.Hour),
		}

		_, err := queries.CreateRefreshToken(ctx, params)
		require.NoError(t, err)

		_, err = queries.CreateRefreshToken(ctx, params)
		require.Error(t, err)
	})
}

func TestMarkRefreshTokenUsed(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "markused")
	client := createTestClient(t, queries, "markused", user.ID)
	accessToken := createTestAccessToken(t, queries, client.ID, user.ID)

	t.Run("mark used sets is_revoked true used_at and revoke_reason", func(t *testing.T) {
		token := createTestRefreshToken(t, queries, client.ID, user.ID, accessToken.ID, uuid.New())
		assert.False(t, token.IsRevoked)
		assert.Nil(t, token.UsedAt)
		assert.Nil(t, token.RevokeReason)

		beforeMark := time.Now()
		err := queries.MarkRefreshTokenUsed(ctx, token.ID)
		require.NoError(t, err)

		updated, err := queries.GetRefreshTokenByID(ctx, token.ID)
		require.NoError(t, err)

		assert.True(t, updated.IsRevoked)
		assert.NotNil(t, updated.UsedAt)
		assert.WithinDuration(t, beforeMark, *updated.UsedAt, time.Second)
		require.NotNil(t, updated.RevokeReason)
		assert.Equal(t, "used", *updated.RevokeReason)
	})

	t.Run("marking already-used token is idempotent", func(t *testing.T) {
		token := createTestRefreshToken(t, queries, client.ID, user.ID, accessToken.ID, uuid.New())

		err := queries.MarkRefreshTokenUsed(ctx, token.ID)
		require.NoError(t, err)

		err = queries.MarkRefreshTokenUsed(ctx, token.ID)
		require.NoError(t, err)

		updated, err := queries.GetRefreshTokenByID(ctx, token.ID)
		require.NoError(t, err)
		assert.True(t, updated.IsRevoked)
	})
}

func TestRevokeRefreshTokenFamily(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "revokefamily")
	client := createTestClient(t, queries, "revokefamily", user.ID)
	accessToken := createTestAccessToken(t, queries, client.ID, user.ID)

	t.Run("revokes all tokens in the family in one statement", func(t *testing.T) {
		familyID := uuid.New()
		otherFamilyID := uuid.New()

		// Create two tokens in the same family and one in a different family
		token1 := createTestRefreshToken(t, queries, client.ID, user.ID, accessToken.ID, familyID)
		token2 := createTestRefreshToken(t, queries, client.ID, user.ID, accessToken.ID, familyID)
		tokenOther := createTestRefreshToken(t, queries, client.ID, user.ID, accessToken.ID, otherFamilyID)

		reason := "replay_detected"
		err := queries.RevokeRefreshTokenFamily(ctx, RevokeRefreshTokenFamilyParams{
			TokenFamilyID: familyID,
			RevokeReason:  &reason,
		})
		require.NoError(t, err)

		// Both family tokens should be revoked
		r1, err := queries.GetRefreshTokenByID(ctx, token1.ID)
		require.NoError(t, err)
		assert.True(t, r1.IsRevoked)
		require.NotNil(t, r1.RevokeReason)
		assert.Equal(t, reason, *r1.RevokeReason)

		r2, err := queries.GetRefreshTokenByID(ctx, token2.ID)
		require.NoError(t, err)
		assert.True(t, r2.IsRevoked)
		require.NotNil(t, r2.RevokeReason)
		assert.Equal(t, reason, *r2.RevokeReason)

		// Token in different family must remain active
		rOther, err := queries.GetRefreshTokenByID(ctx, tokenOther.ID)
		require.NoError(t, err)
		assert.False(t, rOther.IsRevoked)
	})

	t.Run("subsequent use of any family token still shows revoked", func(t *testing.T) {
		familyID := uuid.New()
		token := createTestRefreshToken(t, queries, client.ID, user.ID, accessToken.ID, familyID)

		reason := "replay_detected"
		err := queries.RevokeRefreshTokenFamily(ctx, RevokeRefreshTokenFamilyParams{
			TokenFamilyID: familyID,
			RevokeReason:  &reason,
		})
		require.NoError(t, err)

		// Looking up the token by hash still shows is_revoked=true
		found, err := queries.GetRefreshTokenByHash(ctx, token.TokenHash)
		require.NoError(t, err)
		assert.True(t, found.IsRevoked)
	})
}

func TestDeleteExpiredRefreshTokens(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "deleteexpired")
	client := createTestClient(t, queries, "deleteexpired", user.ID)
	accessToken := createTestAccessToken(t, queries, client.ID, user.ID)

	t.Run("removes only expired tokens", func(t *testing.T) {
		familyID := uuid.New()

		// Create an expired token
		expiredToken, err := queries.CreateRefreshToken(ctx, CreateRefreshTokenParams{
			TokenHash:       uuid.New().String(),
			TokenFamilyID:   familyID,
			ClientID:        client.ID,
			UserID:          user.ID,
			AccessTokenID:   accessToken.ID,
			PreviousTokenID: nil,
			Scope:           "openid",
			ExpiresAt:       time.Now().Add(-1 * time.Hour), // already expired
		})
		require.NoError(t, err)

		// Create a valid (non-expired) token
		validToken := createTestRefreshToken(t, queries, client.ID, user.ID, accessToken.ID, familyID)

		err = queries.DeleteExpiredRefreshTokens(ctx)
		require.NoError(t, err)

		// Expired token should be gone
		_, err = queries.GetRefreshTokenByID(ctx, expiredToken.ID)
		require.Error(t, err)

		// Valid token should still exist
		found, err := queries.GetRefreshTokenByID(ctx, validToken.ID)
		require.NoError(t, err)
		assert.Equal(t, validToken.ID, found.ID)
	})

	t.Run("no error when no expired tokens exist", func(t *testing.T) {
		err := queries.DeleteExpiredRefreshTokens(ctx)
		require.NoError(t, err)
	})
}
