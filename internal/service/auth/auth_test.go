package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/models"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockProviderService is a testify mock for the providerServicer interface.
type mockProviderService struct {
	mock.Mock
}

func (m *mockProviderService) GetProviderWithSecretByClientAndName(ctx context.Context, clientID uuid.UUID, name string) (*provider.OAuthProviderWithSecret, error) {
	args := m.Called(ctx, clientID, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*provider.OAuthProviderWithSecret), args.Error(1)
}

// generateTestPEMKeys returns PEM-encoded ECDSA P-256 private and public keys.
func generateTestPEMKeys(t *testing.T) (privatePEM, publicPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	privatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	publicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return
}

// newTestService creates a Service with a fresh AccessTokenManager backed by
// generated test keys.  It injects both the mock repo and mock provider service.
func newTestService(t *testing.T, q *mocks.MockQuerier, psvc *mockProviderService) *Service {
	t.Helper()
	privPEM, pubPEM := generateTestPEMKeys(t)
	cfg := &config.Config{
		App: config.AppConfig{Name: "test-app"},
		AccessToken: config.AccessTokenConfig{
			PrivateKey: privPEM,
			PublicKey:  pubPEM,
			Expiry:     60,
		},
	}

	svc, err := New(q, cfg, psvc)
	require.NoError(t, err)
	require.NotNil(t, svc)

	return svc
}

// activeClient builds a repository.Client marked as active with the given SHA-256 secret hash.
func activeClient(t *testing.T, secretHash string) repository.Client {
	t.Helper()
	isActive := true
	return repository.Client{
		ID:               uuid.New(),
		Name:             "test-client",
		ClientSecretHash: secretHash,
		RedirectUris:     []string{"https://app.example.com/callback"},
		GrantTypes:       []string{"authorization_code"},
		IsActive:         &isActive,
		CreatedBy:        uuid.New(),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

// sha256Hash hashes the given plain secret using SHA-256 for use in test fixtures.
func sha256Hash(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}

// tokenHash returns SHA-256 hex of the token string.
func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// activeProviderWithSecret returns a provider.OAuthProviderWithSecret whose
// TokenURL and UserInfoURL point to the supplied httptest.Server base URL.
func activeProviderWithSecret(serverURL string, clientID uuid.UUID) *provider.OAuthProviderWithSecret {
	isEnabled := true
	return &provider.OAuthProviderWithSecret{
		OAuthProvider: provider.OAuthProvider{
			ID:          uuid.New(),
			ClientID:    clientID,
			Name:        "google",
			DisplayName: "Google",
			AuthURL:     serverURL + "/auth",
			TokenURL:    serverURL + "/token",
			UserInfoURL: serverURL + "/userinfo",
			Scopes:      []string{"openid", "email"},
			IsEnabled:   isEnabled,
		},
		ProviderClientID:     "goog-client-id",
		ProviderClientSecret: "goog-client-secret",
	}
}

// sampleUser returns a repository.User used in test expectations.
func sampleUser() repository.User {
	isAdmin := false
	return repository.User{
		ID:            uuid.New(),
		Email:         "user@example.com",
		EmailVerified: true,
		IsActive:      true,
		Locale:        "en-US",
		LastLoginAt:   time.Now(),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		IsAdmin:       &isAdmin,
		ProviderData:  &models.OAuthProviderData{},
	}
}

// ---- InitiateAuthorization ----

func TestInitiateAuthorization_Success(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, sha256Hash("s3cr3t"))
	prov := activeProviderWithSecret("https://fake.provider.example.com", client.ID)

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(prov, nil)

	svc := newTestService(t, q, psvc)
	authURL, err := svc.InitiateAuthorization(
		context.Background(),
		client.ID,
		"google",
		"https://auth.example.com/web/auth/callback",
		"https://app.example.com/callback",
		"random-state",
		nil,
	)
	require.NoError(t, err)
	assert.Contains(t, authURL, "state=random-state")
	q.AssertExpectations(t)
	psvc.AssertExpectations(t)
}

func TestInitiateAuthorization_ClientNotFound(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	clientID := uuid.New()
	q.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, pgx.ErrNoRows)

	svc := newTestService(t, q, psvc)
	_, err := svc.InitiateAuthorization(context.Background(), clientID, "google",
		"https://cb.example.com", "https://app.example.com/callback", "state", nil)
	assert.ErrorIs(t, err, ErrClientNotFound)
	q.AssertExpectations(t)
}

func TestInitiateAuthorization_ClientInactive(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	isActive := false
	inactive := repository.Client{
		ID:       uuid.New(),
		IsActive: &isActive,
	}
	q.On("GetClient", mock.Anything, inactive.ID).Return(inactive, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.InitiateAuthorization(context.Background(), inactive.ID, "google",
		"https://cb.example.com", "https://app.example.com/callback", "state", nil)
	assert.ErrorIs(t, err, ErrClientInactive)
}

func TestInitiateAuthorization_InvalidRedirectURI(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	client := activeClient(t, "hash")
	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.InitiateAuthorization(context.Background(), client.ID, "google",
		"https://cb.example.com", "https://NOTREGISTERED.example.com/callback", "state", nil)
	assert.ErrorIs(t, err, ErrInvalidRedirectURI)
}

func TestInitiateAuthorization_ProviderDisabled(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	client := activeClient(t, "hash")

	disabledProv := &provider.OAuthProviderWithSecret{
		OAuthProvider: provider.OAuthProvider{
			ID:        uuid.New(),
			ClientID:  client.ID,
			Name:      "google",
			IsEnabled: false,
		},
	}

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(disabledProv, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.InitiateAuthorization(context.Background(), client.ID, "google",
		"https://cb.example.com", "https://app.example.com/callback", "state", nil)
	assert.ErrorIs(t, err, ErrProviderDisabled)
}

// ---- ExchangeCodeForToken ----

func TestExchangeCodeForToken_Success(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	const plainSecret = "client-secret-value"
	client := activeClient(t, sha256Hash(plainSecret))
	user := sampleUser()

	isRevoked := false
	notUsed := (*time.Time)(nil)
	codeRow := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "auth-code-123",
		ClientID:    client.ID,
		UserID:      user.ID,
		ProviderID:  uuid.New(),
		RedirectUri: "https://app.example.com/callback",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		UsedAt:      notUsed,
		IsRevoked:   &isRevoked,
	}

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	q.On("GetAuthorizationCode", mock.Anything, "auth-code-123").Return(codeRow, nil)
	q.On("MarkAuthorizationCodeUsed", mock.Anything, codeRow.ID).Return(codeRow, nil)
	q.On("GetUserByID", mock.Anything, user.ID).Return(user, nil)
	q.On("CreateAccessToken", mock.Anything, mock.Anything).Return(repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: "hash",
		ClientID:  client.ID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(60 * time.Minute),
	}, nil)

	svc := newTestService(t, q, psvc)
	resp, err := svc.ExchangeCodeForToken(
		context.Background(),
		"auth-code-123",
		client.ID,
		plainSecret,
		"https://app.example.com/callback",
	)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Greater(t, resp.ExpiresIn, int64(0))
	q.AssertExpectations(t)
}

func TestExchangeCodeForToken_InvalidClientSecret(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	client := activeClient(t, sha256Hash("correct-secret"))
	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "code", client.ID, "wrong-secret", "https://app.example.com/callback")
	assert.ErrorIs(t, err, ErrInvalidClientSecret)
}

func TestExchangeCodeForToken_CodeNotFound(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	const plainSecret = "secret"
	client := activeClient(t, sha256Hash(plainSecret))
	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	q.On("GetAuthorizationCode", mock.Anything, "missing-code").Return(repository.AuthorizationCode{}, pgx.ErrNoRows)

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "missing-code", client.ID, plainSecret, "https://app.example.com/callback")
	assert.ErrorIs(t, err, ErrCodeNotFound)
}

func TestExchangeCodeForToken_CodeExpired(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	const plainSecret = "secret"
	client := activeClient(t, sha256Hash(plainSecret))
	isRevoked := false
	codeRow := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "expired-code",
		ClientID:    client.ID,
		RedirectUri: "https://app.example.com/callback",
		ExpiresAt:   time.Now().Add(-1 * time.Minute), // expired
		UsedAt:      nil,
		IsRevoked:   &isRevoked,
	}
	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	q.On("GetAuthorizationCode", mock.Anything, "expired-code").Return(codeRow, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "expired-code", client.ID, plainSecret, "https://app.example.com/callback")
	assert.ErrorIs(t, err, ErrCodeExpired)
}

func TestExchangeCodeForToken_CodeAlreadyUsed(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	const plainSecret = "secret"
	client := activeClient(t, sha256Hash(plainSecret))
	isRevoked := false
	usedAt := time.Now().Add(-2 * time.Minute)
	codeRow := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "used-code",
		ClientID:    client.ID,
		RedirectUri: "https://app.example.com/callback",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		UsedAt:      &usedAt,
		IsRevoked:   &isRevoked,
	}
	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	q.On("GetAuthorizationCode", mock.Anything, "used-code").Return(codeRow, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "used-code", client.ID, plainSecret, "https://app.example.com/callback")
	assert.ErrorIs(t, err, ErrCodeUsed)
}

func TestExchangeCodeForToken_CodeRevoked(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	const plainSecret = "secret"
	client := activeClient(t, sha256Hash(plainSecret))
	isRevoked := true
	codeRow := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "revoked-code",
		ClientID:    client.ID,
		RedirectUri: "https://app.example.com/callback",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		UsedAt:      nil,
		IsRevoked:   &isRevoked,
	}
	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	q.On("GetAuthorizationCode", mock.Anything, "revoked-code").Return(codeRow, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "revoked-code", client.ID, plainSecret, "https://app.example.com/callback")
	assert.ErrorIs(t, err, ErrCodeRevoked)
}

func TestExchangeCodeForToken_ClientMismatch(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	const plainSecret = "secret"
	client := activeClient(t, sha256Hash(plainSecret))
	isRevoked := false
	codeRow := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "code",
		ClientID:    uuid.New(), // different client
		RedirectUri: "https://app.example.com/callback",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		UsedAt:      nil,
		IsRevoked:   &isRevoked,
	}
	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	q.On("GetAuthorizationCode", mock.Anything, "code").Return(codeRow, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "code", client.ID, plainSecret, "https://app.example.com/callback")
	assert.ErrorIs(t, err, ErrCodeClientMismatch)
}

func TestExchangeCodeForToken_RedirectMismatch(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	const plainSecret = "secret"
	client := activeClient(t, sha256Hash(plainSecret))
	isRevoked := false
	codeRow := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "code",
		ClientID:    client.ID,
		RedirectUri: "https://app.example.com/callback",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		UsedAt:      nil,
		IsRevoked:   &isRevoked,
	}
	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	q.On("GetAuthorizationCode", mock.Anything, "code").Return(codeRow, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "code", client.ID, plainSecret, "https://DIFFERENT.example.com/callback")
	assert.ErrorIs(t, err, ErrCodeRedirectMismatch)
}

// ---- RevokeToken ----

func TestRevokeToken_Success(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	tokenRow := repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: tokenHash("my-token"),
	}
	q.On("GetAccessToken", mock.Anything, tokenHash("my-token")).Return(tokenRow, nil)
	q.On("RevokeAccessToken", mock.Anything, tokenRow.ID).Return(nil)

	svc := newTestService(t, q, psvc)
	err := svc.RevokeToken(context.Background(), tokenHash("my-token"))
	require.NoError(t, err)
	q.AssertExpectations(t)
}

func TestRevokeToken_NotFound(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	q.On("GetAccessToken", mock.Anything, "unknown-hash").Return(repository.AccessToken{}, pgx.ErrNoRows)

	svc := newTestService(t, q, psvc)
	err := svc.RevokeToken(context.Background(), "unknown-hash")
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

// ---- RevokeRawToken ----

func TestRevokeRawToken_Success(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	rawToken := "my-raw-access-token"
	hash := tokenHash(rawToken)
	tokenRow := repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: hash,
	}
	q.On("GetAccessToken", mock.Anything, hash).Return(tokenRow, nil)
	q.On("RevokeAccessToken", mock.Anything, tokenRow.ID).Return(nil)

	svc := newTestService(t, q, psvc)
	err := svc.RevokeRawToken(context.Background(), rawToken)
	require.NoError(t, err)
	q.AssertExpectations(t)
}

func TestRevokeRawToken_NotFound(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	rawToken := "nonexistent-token"
	hash := tokenHash(rawToken)
	q.On("GetAccessToken", mock.Anything, hash).Return(repository.AccessToken{}, pgx.ErrNoRows)

	svc := newTestService(t, q, psvc)
	err := svc.RevokeRawToken(context.Background(), rawToken)
	assert.ErrorIs(t, err, ErrTokenNotFound)
	q.AssertExpectations(t)
}

// ---- IsTokenRevoked ----

func TestIsTokenRevoked_NotInDB_ReturnsRevoked(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	rawToken := "unknown-raw-token"
	hash := tokenHash(rawToken)
	q.On("GetAccessToken", mock.Anything, hash).Return(repository.AccessToken{}, pgx.ErrNoRows)

	svc := newTestService(t, q, psvc)
	revoked, err := svc.IsTokenRevoked(context.Background(), rawToken)
	require.NoError(t, err)
	assert.True(t, revoked, "token not in DB should be treated as revoked")
	q.AssertExpectations(t)
}

func TestIsTokenRevoked_ActiveToken_ReturnsFalse(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	rawToken := "active-raw-token"
	hash := tokenHash(rawToken)
	isRevoked := false
	tokenRow := repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: hash,
		IsRevoked: &isRevoked,
	}
	q.On("GetAccessToken", mock.Anything, hash).Return(tokenRow, nil)

	svc := newTestService(t, q, psvc)
	revoked, err := svc.IsTokenRevoked(context.Background(), rawToken)
	require.NoError(t, err)
	assert.False(t, revoked)
	q.AssertExpectations(t)
}

func TestIsTokenRevoked_RevokedToken_ReturnsTrue(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	rawToken := "revoked-raw-token"
	hash := tokenHash(rawToken)
	isRevoked := true
	tokenRow := repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: hash,
		IsRevoked: &isRevoked,
	}
	q.On("GetAccessToken", mock.Anything, hash).Return(tokenRow, nil)

	svc := newTestService(t, q, psvc)
	revoked, err := svc.IsTokenRevoked(context.Background(), rawToken)
	require.NoError(t, err)
	assert.True(t, revoked)
	q.AssertExpectations(t)
}

func TestIsTokenRevoked_RepoError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	rawToken := "error-token"
	hash := tokenHash(rawToken)
	q.On("GetAccessToken", mock.Anything, hash).Return(repository.AccessToken{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.IsTokenRevoked(context.Background(), rawToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "looking up access token")
	q.AssertExpectations(t)
}

// ---- ValidateAccessToken ----

func TestValidateAccessToken_ValidToken(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	svc := newTestService(t, q, psvc)

	userID := uuid.New().String()
	email := "valid@example.com"
	token, err := svc.GenerateAccessToken(userID, email)
	require.NoError(t, err)

	claims, err := svc.ValidateAccessToken(token)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, email, claims.Email)
}

func TestValidateAccessToken_InvalidToken(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	svc := newTestService(t, q, psvc)

	_, err := svc.ValidateAccessToken("not-a-real-jwt")
	require.Error(t, err)
}

// ---- HandleProviderCallback ----

func TestHandleProviderCallback_Success(t *testing.T) {
	user := sampleUser()
	providerSub := "provider-user-123"
	providerName := "google"

	// httptest.Server implements both the token exchange and user-info endpoints.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			// Respond to the OAuth token exchange.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "provider-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":            providerSub,
				"email":          user.Email,
				"email_verified": true,
				"given_name":     "Test",
				"family_name":    "User",
				"locale":         "en-US",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	isActive := true
	client := repository.Client{
		ID:           uuid.New(),
		Name:         "cb-test-client",
		RedirectUris: []string{"https://app.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		IsActive:     &isActive,
		CreatedBy:    uuid.New(),
	}
	prov := activeProviderWithSecret(srv.URL, client.ID)

	// The user hasn't been seen before — GetUserByProviderID returns not found.
	provPtr := util_strPtr(providerName)
	subPtr := util_strPtr(providerSub)
	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(prov, nil)
	q.On("GetUserByProviderID", mock.Anything, repository.GetUserByProviderIDParams{
		Provider:   provPtr,
		ProviderID: subPtr,
	}).Return(repository.User{}, pgx.ErrNoRows)
	q.On("CreateUser", mock.Anything, mock.Anything).Return(user, nil)
	q.On("CreateAuthorizationCode", mock.Anything, mock.Anything).Return(repository.AuthorizationCode{
		ID:   uuid.New(),
		Code: "generated-auth-code",
	}, nil)

	svc := newTestService(t, q, psvc)
	authCode, err := svc.HandleProviderCallback(
		context.Background(),
		client.ID,
		"google",
		"provider-code",
		srv.URL+"/token",
		"https://app.example.com/callback",
	)
	require.NoError(t, err)
	assert.NotEmpty(t, authCode)
	q.AssertExpectations(t)
	psvc.AssertExpectations(t)
}

func TestHandleProviderCallback_ClientInactive(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	isActive := false
	client := repository.Client{ID: uuid.New(), IsActive: &isActive}
	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", "https://cb.example.com/token", "https://app.example.com/callback")
	assert.ErrorIs(t, err, ErrClientInactive)
}

// util_strPtr is a local helper to get a *string from a string literal in test.
func util_strPtr(s string) *string { return &s }

// --- New constructor ---

func TestNew_Constructor(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	privPEM, pubPEM := generateTestPEMKeys(t)
	cfg := &config.Config{
		App: config.AppConfig{Name: "test"},
		AccessToken: config.AccessTokenConfig{
			PrivateKey: privPEM,
			PublicKey:  pubPEM,
			Expiry:     30,
		},
	}

	svc, err := New(q, cfg, psvc)
	require.NoError(t, err)
	require.NotNil(t, svc)
}

// --- upsertUser: existing user path ---

func TestHandleProviderCallback_ExistingUser(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	// Build httptest server that handles token exchange + user info
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"sub":"user-sub-123","email":"user@example.com","email_verified":true}`)
		}
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)

	existingUser := sampleUser()
	provPtr := util_strPtr("google")
	subPtr := util_strPtr("user-sub-123")

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)
	q.On("GetUserByProviderID", mock.Anything, repository.GetUserByProviderIDParams{
		Provider:   provPtr,
		ProviderID: subPtr,
	}).Return(existingUser, nil) // user exists
	q.On("UpdateLastLogin", mock.Anything, mock.Anything).Return(existingUser, nil)
	q.On("CreateAuthorizationCode", mock.Anything, mock.Anything).Return(repository.AuthorizationCode{
		ID:   uuid.New(),
		Code: "auth-code-existing",
	}, nil)

	svc := newTestService(t, q, psvc)
	authCode, err := svc.HandleProviderCallback(
		context.Background(),
		client.ID,
		"google",
		"provider-code",
		srv.URL+"/token",
		"https://app.example.com/callback",
	)
	require.NoError(t, err)
	assert.NotEmpty(t, authCode)
	q.AssertExpectations(t)
	psvc.AssertExpectations(t)
}

// --- upsertUser: lookup error path ---

func TestHandleProviderCallback_UserLookupError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"sub":"user-sub-456","email":"user@example.com","email_verified":true}`)
		}
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)
	provPtr := util_strPtr("google")
	subPtr := util_strPtr("user-sub-456")

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)
	q.On("GetUserByProviderID", mock.Anything, repository.GetUserByProviderIDParams{
		Provider:   provPtr,
		ProviderID: subPtr,
	}).Return(repository.User{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(
		context.Background(),
		client.ID,
		"google",
		"provider-code",
		srv.URL+"/token",
		"https://app.example.com/callback",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "looking up user")
	q.AssertExpectations(t)
}

// --- InitiateAuthorization additional error paths ---

func TestInitiateAuthorization_GetClientRepoError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	clientID := uuid.New()

	q.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.InitiateAuthorization(context.Background(), clientID, "google",
		"https://cb.example.com/callback", "https://app.example.com/callback", "state", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting client")
}

func TestInitiateAuthorization_GetProviderRepoError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive
	client.RedirectUris = []string{"https://app.example.com/callback"}

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").
		Return(nil, errors.New("unexpected db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.InitiateAuthorization(context.Background(), client.ID, "google",
		"https://cb.example.com/callback", "https://app.example.com/callback", "state", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting provider")
}

func TestInitiateAuthorization_WithScope(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive
	client.RedirectUris = []string{"https://app.example.com/callback"}

	p := activeProviderWithSecret("https://provider.example.com", client.ID)

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)

	scope := "openid email"
	svc := newTestService(t, q, psvc)
	url, err := svc.InitiateAuthorization(context.Background(), client.ID, "google",
		"https://cb.example.com/callback", "https://app.example.com/callback", "state", &scope)
	require.NoError(t, err)
	assert.NotEmpty(t, url)
}

// --- HandleProviderCallback additional error paths ---

func TestHandleProviderCallback_ClientNotFound(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	clientID := uuid.New()

	q.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, pgx.ErrNoRows)

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), clientID, "google",
		"code", "https://cb.example.com/token", "https://app.example.com/callback")
	require.ErrorIs(t, err, ErrClientNotFound)
}

func TestHandleProviderCallback_GetClientRepoError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	clientID := uuid.New()

	q.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), clientID, "google",
		"code", "https://cb.example.com/token", "https://app.example.com/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting client")
}

func TestHandleProviderCallback_GetProviderError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").
		Return(nil, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", "https://cb.example.com/token", "https://app.example.com/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting provider")
}

func TestHandleProviderCallback_ProviderDisabled(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	p := activeProviderWithSecret("https://provider.example.com", client.ID)
	p.IsEnabled = false

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", "https://cb.example.com/token", "https://app.example.com/callback")
	require.ErrorIs(t, err, ErrProviderDisabled)
}

func TestHandleProviderCallback_ExchangeCodeError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	// Server returns 400 on token exchange.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"bad-code", srv.URL+"/token", "https://app.example.com/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exchanging provider code")
}

func TestHandleProviderCallback_FetchUserInfoError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", srv.URL+"/token", "https://app.example.com/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetching user info")
}

func TestHandleProviderCallback_CreateAuthCodeError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"sub":"user-sub-789","email":"user@example.com","email_verified":true}`)
		}
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)
	provPtr := util_strPtr("google")
	subPtr := util_strPtr("user-sub-789")
	user := sampleUser()

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)
	q.On("GetUserByProviderID", mock.Anything, repository.GetUserByProviderIDParams{
		Provider:   provPtr,
		ProviderID: subPtr,
	}).Return(repository.User{}, pgx.ErrNoRows)
	q.On("CreateUser", mock.Anything, mock.Anything).Return(user, nil)
	q.On("CreateAuthorizationCode", mock.Anything, mock.Anything).
		Return(repository.AuthorizationCode{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", srv.URL+"/token", "https://app.example.com/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storing authorization code")
}

func TestHandleProviderCallback_EmptyLocale(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			// No locale and no given_name/family_name to test nonEmptyStrPtr("") → nil
			fmt.Fprint(w, `{"sub":"user-sub-locale","email":"user@example.com","email_verified":true}`)
		}
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)
	provPtr := util_strPtr("google")
	subPtr := util_strPtr("user-sub-locale")
	user := sampleUser()

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)
	q.On("GetUserByProviderID", mock.Anything, repository.GetUserByProviderIDParams{
		Provider:   provPtr,
		ProviderID: subPtr,
	}).Return(repository.User{}, pgx.ErrNoRows)
	q.On("CreateUser", mock.Anything, mock.Anything).Return(user, nil)
	q.On("CreateAuthorizationCode", mock.Anything, mock.Anything).Return(repository.AuthorizationCode{
		ID:   uuid.New(),
		Code: "auth-code-locale",
	}, nil)

	svc := newTestService(t, q, psvc)
	authCode, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", srv.URL+"/token", "https://app.example.com/callback")
	require.NoError(t, err)
	assert.NotEmpty(t, authCode)
}

// --- ExchangeCodeForToken additional error paths ---

func TestExchangeCodeForToken_ClientRepoError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	clientID := uuid.New()

	q.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "code", clientID, "secret", "https://app.example.com/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting client")
}

func TestExchangeCodeForToken_ClientInactive(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	isActive := false
	client := repository.Client{ID: uuid.New(), IsActive: &isActive}

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "code", client.ID, "secret", "https://app.example.com/callback")
	require.ErrorIs(t, err, ErrClientInactive)
}

func TestExchangeCodeForToken_AuthCodeRepoError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	secretHash := sha256Hash("test-secret")
	client := activeClient(t, secretHash)

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	q.On("GetAuthorizationCode", mock.Anything, "code").Return(repository.AuthorizationCode{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "code", client.ID, "test-secret", "https://app.example.com/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting authorization code")
}

func TestExchangeCodeForToken_MarkUsedError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	secretHash := sha256Hash("test-secret")
	client := activeClient(t, secretHash)

	code := repository.AuthorizationCode{
		ID:          uuid.New(),
		ClientID:    client.ID,
		UserID:      uuid.New(),
		RedirectUri: "https://app.example.com/callback",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	q.On("GetAuthorizationCode", mock.Anything, "code").Return(code, nil)
	q.On("MarkAuthorizationCodeUsed", mock.Anything, code.ID).Return(repository.AuthorizationCode{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "code", client.ID, "test-secret", "https://app.example.com/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marking authorization code as used")
}

func TestExchangeCodeForToken_GetUserError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	secretHash := sha256Hash("test-secret")
	client := activeClient(t, secretHash)
	userID := uuid.New()

	code := repository.AuthorizationCode{
		ID:          uuid.New(),
		ClientID:    client.ID,
		UserID:      userID,
		RedirectUri: "https://app.example.com/callback",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	q.On("GetAuthorizationCode", mock.Anything, "code").Return(code, nil)
	q.On("MarkAuthorizationCodeUsed", mock.Anything, code.ID).Return(code, nil)
	q.On("GetUserByID", mock.Anything, userID).Return(repository.User{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "code", client.ID, "test-secret", "https://app.example.com/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting user")
}

func TestExchangeCodeForToken_CreateAccessTokenError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	secretHash := sha256Hash("test-secret")
	client := activeClient(t, secretHash)
	user := sampleUser()

	code := repository.AuthorizationCode{
		ID:          uuid.New(),
		ClientID:    client.ID,
		UserID:      user.ID,
		RedirectUri: "https://app.example.com/callback",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	q.On("GetAuthorizationCode", mock.Anything, "code").Return(code, nil)
	q.On("MarkAuthorizationCodeUsed", mock.Anything, code.ID).Return(code, nil)
	q.On("GetUserByID", mock.Anything, user.ID).Return(user, nil)
	q.On("CreateAccessToken", mock.Anything, mock.Anything).Return(repository.AccessToken{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "code", client.ID, "test-secret", "https://app.example.com/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storing access token record")
}

// --- RevokeToken additional error paths ---

func TestRevokeToken_RepoError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	q.On("GetAccessToken", mock.Anything, "hash123").Return(repository.AccessToken{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	err := svc.RevokeToken(context.Background(), "hash123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting access token")
}

func TestRevokeToken_RevokeError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	token := repository.AccessToken{ID: uuid.New()}
	q.On("GetAccessToken", mock.Anything, "hash123").Return(token, nil)
	q.On("RevokeAccessToken", mock.Anything, token.ID).Return(errors.New("db error"))

	svc := newTestService(t, q, psvc)
	err := svc.RevokeToken(context.Background(), "hash123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoking access token")
}

// --- upsertUser: UpdateLastLogin error ---

func TestHandleProviderCallback_UpdateLastLoginError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"sub":"user-sub-ullerr","email":"user@example.com","email_verified":true}`)
		}
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)
	provPtr := util_strPtr("google")
	subPtr := util_strPtr("user-sub-ullerr")
	existingUser := sampleUser()

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)
	q.On("GetUserByProviderID", mock.Anything, repository.GetUserByProviderIDParams{
		Provider:   provPtr,
		ProviderID: subPtr,
	}).Return(existingUser, nil) // user exists
	q.On("UpdateLastLogin", mock.Anything, mock.Anything).Return(repository.User{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", srv.URL+"/token", "https://app.example.com/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "updating last login")
}

// --- fetchUserInfo missing required fields ---

func TestHandleProviderCallback_MissingSubInUserInfo(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			// missing "sub" field
			fmt.Fprint(w, `{"email":"user@example.com","email_verified":true}`)
		}
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", srv.URL+"/token", "https://app.example.com/callback")
	require.Error(t, err)
}

func TestHandleProviderCallback_MissingEmailInUserInfo(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			// missing "email" field
			fmt.Fprint(w, `{"sub":"user-sub-noemail"}`)
		}
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", srv.URL+"/token", "https://app.example.com/callback")
	require.Error(t, err)
}

func TestHandleProviderCallback_NonBoolEmailVerified(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			// email_verified is a string instead of bool (boolField returns false)
			fmt.Fprint(w, `{"sub":"user-sub-strbool","email":"user@example.com","email_verified":"yes"}`)
		}
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)
	provPtr := util_strPtr("google")
	subPtr := util_strPtr("user-sub-strbool")
	user := sampleUser()

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)
	q.On("GetUserByProviderID", mock.Anything, repository.GetUserByProviderIDParams{
		Provider:   provPtr,
		ProviderID: subPtr,
	}).Return(repository.User{}, pgx.ErrNoRows)
	q.On("CreateUser", mock.Anything, mock.Anything).Return(user, nil)
	q.On("CreateAuthorizationCode", mock.Anything, mock.Anything).Return(repository.AuthorizationCode{
		ID:   uuid.New(),
		Code: "auth-code-strbool",
	}, nil)

	svc := newTestService(t, q, psvc)
	authCode, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", srv.URL+"/token", "https://app.example.com/callback")
	require.NoError(t, err)
	assert.NotEmpty(t, authCode)
}

// --- upsertUser: CreateUser error path ---

func TestHandleProviderCallback_CreateUserError(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"sub":"new-user-error","email":"new@example.com","email_verified":true}`)
		}
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)
	provPtr := util_strPtr("google")
	subPtr := util_strPtr("new-user-error")

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)
	q.On("GetUserByProviderID", mock.Anything, repository.GetUserByProviderIDParams{
		Provider:   provPtr,
		ProviderID: subPtr,
	}).Return(repository.User{}, pgx.ErrNoRows)
	q.On("CreateUser", mock.Anything, mock.Anything).Return(repository.User{}, errors.New("db error"))

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", srv.URL+"/token", "https://app.example.com/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating user")
}

// --- fetchUserInfo: first_name/last_name fields and invalid JSON ---

func TestHandleProviderCallback_UseFirstNameLastName(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			// Use first_name/last_name (non-standard) instead of given_name/family_name
			fmt.Fprint(w, `{"sub":"user-firstname","email":"user@example.com","first_name":"John","last_name":"Doe"}`)
		}
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)
	provPtr := util_strPtr("google")
	subPtr := util_strPtr("user-firstname")
	user := sampleUser()

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)
	q.On("GetUserByProviderID", mock.Anything, repository.GetUserByProviderIDParams{
		Provider:   provPtr,
		ProviderID: subPtr,
	}).Return(repository.User{}, pgx.ErrNoRows)
	q.On("CreateUser", mock.Anything, mock.Anything).Return(user, nil)
	q.On("CreateAuthorizationCode", mock.Anything, mock.Anything).Return(repository.AuthorizationCode{
		ID:   uuid.New(),
		Code: "auth-code-firstname",
	}, nil)

	svc := newTestService(t, q, psvc)
	authCode, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", srv.URL+"/token", "https://app.example.com/callback")
	require.NoError(t, err)
	assert.NotEmpty(t, authCode)
}

func TestHandleProviderCallback_InvalidJSONUserInfo(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{invalid json}`)
		}
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", srv.URL+"/token", "https://app.example.com/callback")
	require.Error(t, err)
}

// TestHandleProviderCallback_InvalidUserInfoURL covers the http.NewRequestWithContext error path
func TestHandleProviderCallback_InvalidUserInfoURL(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
	}))
	defer srv.Close()

	p := activeProviderWithSecret(srv.URL, client.ID)
	p.UserInfoURL = "http://example.com/\x00invalid"

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", srv.URL, "https://app.example.com/callback")
	require.Error(t, err)
}

// TestHandleProviderCallback_UserInfoConnRefused covers the httpClient.Do error path
func TestHandleProviderCallback_UserInfoConnRefused(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive

	// Token server stays up for the code exchange
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
	}))
	defer tokenSrv.Close()

	// UserInfo server is closed immediately so Do() returns connection refused
	userInfoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	userInfoSrv.Close()

	p := activeProviderWithSecret(tokenSrv.URL, client.ID)
	p.UserInfoURL = userInfoSrv.URL + "/userinfo"

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").Return(p, nil)

	svc := newTestService(t, q, psvc)
	_, err := svc.HandleProviderCallback(context.Background(), client.ID, "google",
		"code", tokenSrv.URL, "https://app.example.com/callback")
	require.Error(t, err)
}

// --- Missing "not found" error path tests ---

func TestInitiateAuthorization_ProviderNotFound(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}

	client := activeClient(t, "")
	isActive := true
	client.IsActive = &isActive
	client.RedirectUris = []string{"https://app.example.com/callback"}

	q.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	psvc.On("GetProviderWithSecretByClientAndName", mock.Anything, client.ID, "google").
		Return(nil, provider.ErrProviderNotFound)

	svc := newTestService(t, q, psvc)
	_, err := svc.InitiateAuthorization(context.Background(), client.ID, "google",
		"https://cb.example.com/callback", "https://app.example.com/callback", "state", nil)
	require.ErrorIs(t, err, provider.ErrProviderNotFound)
}

func TestExchangeCodeForToken_ClientNotFoundInDB(t *testing.T) {
	q := &mocks.MockQuerier{}
	psvc := &mockProviderService{}
	clientID := uuid.New()

	q.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, pgx.ErrNoRows)

	svc := newTestService(t, q, psvc)
	_, err := svc.ExchangeCodeForToken(context.Background(), "code", clientID, "secret", "https://app.example.com/callback")
	require.ErrorIs(t, err, ErrClientNotFound)
}
