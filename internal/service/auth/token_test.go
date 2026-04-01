package auth

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSessionSigningKey is a fixed 32-byte (256-bit) hex-encoded key used
// exclusively in challenge token tests.
const testSessionSigningKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// newChallengeTestService creates a Service configured with both ECDSA access
// token keys and an HMAC session signing key so that both GenerateChallengeToken
// and GenerateAccessToken can be exercised in the same test.
func newChallengeTestService(t *testing.T) *Service {
	t.Helper()
	privPEM, pubPEM := generateTestPEMKeys(t)
	cfg := &config.Config{
		App: config.AppConfig{Name: "test-app"},
		AccessToken: config.AccessTokenConfig{
			PrivateKey: privPEM,
			PublicKey:  pubPEM,
			Expiry:     60,
		},
		Security: config.SecurityConfig{
			SessionSigningKey: testSessionSigningKey,
		},
	}
	svc, err := New(nil, cfg, nil, nil)
	require.NoError(t, err)
	return svc
}

// expiredChallengeToken builds a structurally valid challenge token whose
// expiry is set in the past. It uses the same signing key as svc so that the
// signature check passes and only the expiry check fails.
func expiredChallengeToken(t *testing.T, svc *Service, userID uuid.UUID) string {
	t.Helper()
	signingKey, err := hex.DecodeString(svc.cfg.Security.SessionSigningKey)
	require.NoError(t, err)

	past := time.Now().UTC().Add(-2 * time.Minute)
	claims := challengeClaims{
		TokenType: challengeTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(past),
			IssuedAt:  jwt.NewNumericDate(past.Add(-challengeTokenExpiry)),
			Issuer:    svc.cfg.App.Name,
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(signingKey)
	require.NoError(t, err)
	return signed
}

// wrongTypeChallengeToken builds a token signed with the correct key but with
// a TokenType field set to an arbitrary non-"password_change" value.
func wrongTypeChallengeToken(t *testing.T, svc *Service, userID uuid.UUID) string {
	t.Helper()
	signingKey, err := hex.DecodeString(svc.cfg.Security.SessionSigningKey)
	require.NoError(t, err)

	now := time.Now().UTC()
	claims := challengeClaims{
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    svc.cfg.App.Name,
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(signingKey)
	require.NoError(t, err)
	return signed
}

// TestChallengToken_RoundTrip verifies that a token produced by
// GenerateChallengeToken is accepted by ValidateChallengeToken and
// that the extracted user ID matches the one that was embedded.
func TestChallengeToken_RoundTrip(t *testing.T) {
	svc := newChallengeTestService(t)
	userID := uuid.New()

	tokenStr, err := svc.GenerateChallengeToken(userID)
	require.NoError(t, err)
	require.NotEmpty(t, tokenStr)

	got, err := svc.ValidateChallengeToken(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, userID, got)
}

// TestChallengeToken_ExpiredRejected verifies that ValidateChallengeToken
// returns an error for a token whose expiry time is in the past.
func TestChallengeToken_ExpiredRejected(t *testing.T) {
	svc := newChallengeTestService(t)
	userID := uuid.New()

	tokenStr := expiredChallengeToken(t, svc, userID)

	got, err := svc.ValidateChallengeToken(tokenStr)
	assert.ErrorContains(t, err, "invalid challenge token")
	assert.Equal(t, uuid.Nil, got)
}

// TestChallengeToken_WrongTypRejected verifies that ValidateChallengeToken
// rejects a token that carries a typ claim other than "password_change", even
// when the signature and expiry are both valid.
func TestChallengeToken_WrongTypRejected(t *testing.T) {
	svc := newChallengeTestService(t)
	userID := uuid.New()

	tokenStr := wrongTypeChallengeToken(t, svc, userID)

	got, err := svc.ValidateChallengeToken(tokenStr)
	assert.ErrorContains(t, err, "wrong type")
	assert.Equal(t, uuid.Nil, got)
}

// TestChallengeToken_AccessTokenNotAccepted verifies that an access token
// (signed with the ECDSA private key, not the HMAC session key) is rejected
// by ValidateChallengeToken. The two tokens use different signing algorithms
// and different keys, so validation must fail at the signature / algorithm step.
func TestChallengeToken_AccessTokenNotAccepted(t *testing.T) {
	svc := newChallengeTestService(t)
	userID := uuid.New()

	// Generate a normal ECDSA-signed access token.
	accessTok, err := svc.GenerateAccessToken(userID.String(), "user@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, accessTok)

	// ValidateChallengeToken must refuse it: wrong algorithm (ES256 vs HS256)
	// and no valid "password_change" typ claim.
	got, err := svc.ValidateChallengeToken(accessTok)
	assert.Error(t, err)
	assert.Equal(t, uuid.Nil, got)
}
