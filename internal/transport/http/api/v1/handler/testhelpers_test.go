package handler_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/service/client"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/SamuelWang/goauth-server/internal/service/session"
	"github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	v1 "github.com/SamuelWang/goauth-server/internal/transport/http/api/v1"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// testEnv holds all mocked dependencies and services for handler tests.
type testEnv struct {
	mockQ       *mocks.MockQuerier
	authSvc     *auth.Service
	userSvc     *user.Service
	providerSvc *provider.Service
	clientSvc   *client.Service
	sessionSvc  *session.Service
	privKey     *ecdsa.PrivateKey
	router      *gin.Engine
}

// newTestEnv constructs a full handler test environment with a fresh encryption key
// and a mock querier. The router has all v1 API routes registered.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	// Generate ECDSA keys for JWT
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privDER, err := x509.MarshalECPrivateKey(privKey)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	cfg := &config.Config{
		App:    config.AppConfig{Name: "test-app"},
		Server: config.ServerConfig{Env: "development", Scheme: "http", HostName: "localhost", Port: "8080"},
		AccessToken: config.AccessTokenConfig{
			PrivateKey: privPEM,
			PublicKey:  pubPEM,
			Expiry:     60,
		},
	}

	mockQ := &mocks.MockQuerier{}

	authSvc, err := auth.New(mockQ, cfg, nil)
	require.NoError(t, err)

	userSvc := user.New(mockQ)

	// 32-byte encryption key for provider secrets
	encKey := make([]byte, 32)
	_, err = rand.Read(encKey)
	require.NoError(t, err)

	providerSvc, err := provider.New(mockQ, encKey, cfg.Server.Env)
	require.NoError(t, err)

	clientSvc := client.New(mockQ, cfg.Server.Env)
	sessionSvc := session.New(mockQ)

	router := gin.New()
	apiV1 := router.Group("/api/v1")
	apiV1.Use(middleware.ContextMiddleware(cfg))
	v1.RegisterRoutes(apiV1, authSvc, userSvc, providerSvc, clientSvc, sessionSvc)

	return &testEnv{
		mockQ:       mockQ,
		authSvc:     authSvc,
		userSvc:     userSvc,
		providerSvc: providerSvc,
		clientSvc:   clientSvc,
		sessionSvc:  sessionSvc,
		privKey:     privKey,
		router:      router,
	}
}

// generateToken mints a valid JWT for the given userID and email.
func (e *testEnv) generateToken(t *testing.T, userID, email string) string {
	t.Helper()
	token, err := e.authSvc.GenerateAccessToken(userID, email)
	require.NoError(t, err)
	return token
}

// hashToken returns the hex SHA-256 hash used as the token_hash in the DB.
func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// activeTokenRow builds a non-revoked AccessToken repository row for the given raw token.
func activeTokenRow(rawToken string, userID uuid.UUID) repository.AccessToken {
	notRevoked := false
	return repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: hashToken(rawToken),
		ClientID:  uuid.New(),
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour),
		IsRevoked: &notRevoked,
	}
}

// revokedTokenRow builds a revoked AccessToken repository row.
func revokedTokenRow(rawToken string) repository.AccessToken {
	revoked := true
	return repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: hashToken(rawToken),
		ClientID:  uuid.New(),
		UserID:    uuid.New(),
		ExpiresAt: time.Now().Add(time.Hour),
		IsRevoked: &revoked,
	}
}

// buildAdminUser returns a repository.User row with is_admin = true.
func buildAdminUser(id uuid.UUID) repository.User {
	isAdmin := true
	isActive := true
	return repository.User{
		ID:            id,
		Email:         "admin@example.com",
		EmailVerified: true,
		IsActive:      isActive,
		IsAdmin:       &isAdmin,
		Locale:        "en-US",
		LastLoginAt:   time.Now(),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

// buildRegularUser returns a repository.User row with is_admin = false.
func buildRegularUser(id uuid.UUID) repository.User {
	isAdmin := false
	isActive := true
	return repository.User{
		ID:            id,
		Email:         "user@example.com",
		EmailVerified: true,
		IsActive:      isActive,
		IsAdmin:       &isAdmin,
		Locale:        "en-US",
		LastLoginAt:   time.Now(),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

// buildActiveClient returns a repository.Client row marked as active.
func buildActiveClient(id uuid.UUID, name string, createdBy uuid.UUID) repository.Client {
	isActive := true
	return repository.Client{
		ID:               id,
		Name:             name,
		ClientSecretHash: "some-hash",
		RedirectUris:     []string{"https://app.example.com/callback"},
		GrantTypes:       []string{"authorization_code"},
		IsActive:         &isActive,
		CreatedBy:        createdBy,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

// buildOAuthProvider returns a repository.OauthProvider row.
func buildOAuthProvider(id, clientID uuid.UUID, name string) repository.OauthProvider {
	isEnabled := true
	return repository.OauthProvider{
		ID:                   id,
		ClientID:             clientID,
		Name:                 name,
		DisplayName:          name + " Display",
		ProviderClientID:     "provider-client-id",
		ProviderClientSecret: "encrypted-secret",
		AuthUrl:              "https://provider.example.com/auth",
		TokenUrl:             "https://provider.example.com/token",
		UserInfoUrl:          "https://provider.example.com/userinfo",
		Scopes:               []string{"openid", "email"},
		IsEnabled:            &isEnabled,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
}

// doRequest performs an HTTP request against the test router.
func (e *testEnv) doRequest(method, path string, body interface{}) *httptest.ResponseRecorder {
	var reqBody *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, reqBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

// testCSRFToken is a fixed valid CSRF token used in tests for state-changing
// requests.  Both the csrf_token cookie and the X-CSRF-Token header are set
// to this value so the double-submit check passes.
const testCSRFToken = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

// doAuthRequest performs an HTTP request with a Bearer token.
// For state-changing methods (POST, PATCH, DELETE) it also adds the CSRF
// cookie and X-CSRF-Token header so that the CSRFMiddleware is satisfied.
func (e *testEnv) doAuthRequest(method, path string, body interface{}, token string) *httptest.ResponseRecorder {
	var reqBody *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// State-changing requests require a valid CSRF double-submit token.
	switch method {
	case "POST", "PATCH", "PUT", "DELETE":
		req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: testCSRFToken})
		req.Header.Set(middleware.CSRFHeaderName, testCSRFToken)
	}

	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

// parseJSON unmarshals JSON from a recorder's body into target.
func parseJSON(t *testing.T, w *httptest.ResponseRecorder, target interface{}) {
	t.Helper()
	require.NoError(t, json.NewDecoder(w.Body).Decode(target))
}
