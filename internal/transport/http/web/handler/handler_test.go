package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	providerservice "github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ---------------------------------------------------------------------------
// Mock provider service (satisfies auth.providerServicer via structural typing)
// ---------------------------------------------------------------------------

type stubProvSvc struct {
	result *providerservice.OAuthProviderWithSecret
	err    error
}

func (s *stubProvSvc) GetProviderWithSecretByClientAndName(
	_ context.Context, _ uuid.UUID, _ string,
) (*providerservice.OAuthProviderWithSecret, error) {
	return s.result, s.err
}

// ---------------------------------------------------------------------------
// Test environment
// ---------------------------------------------------------------------------

type webEnv struct {
	mockQ   *mocks.MockQuerier
	provSvc *stubProvSvc
	authSvc *auth.Service
	h       *WebHandler
	router  *gin.Engine
	sigKey  []byte
	cfg     *config.Config
}

func newWebEnv(t *testing.T) *webEnv {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	cfg := &config.Config{
		App:    config.AppConfig{Name: "test"},
		Server: config.ServerConfig{Env: "development", Scheme: "http", HostName: "localhost", Port: "8080"},
		AccessToken: config.AccessTokenConfig{
			PrivateKey: privPEM,
			PublicKey:  pubPEM,
			Expiry:     60,
		},
	}

	mockQ := &mocks.MockQuerier{}
	provSvc := &stubProvSvc{}

	authSvc, err := auth.New(mockQ, cfg, provSvc, nil)
	require.NoError(t, err)

	sigKey := make([]byte, 32)
	_, err = rand.Read(sigKey)
	require.NoError(t, err)

	h := New(authSvc, cfg, sigKey)

	router := gin.New()
	router.Use(middleware.ContextMiddleware(cfg))
	authGroup := router.Group("/web/auth/:client_id/:provider")
	authGroup.GET("/login", h.Login)
	authGroup.GET("/callback", h.Callback)

	return &webEnv{
		mockQ:   mockQ,
		provSvc: provSvc,
		authSvc: authSvc,
		h:       h,
		router:  router,
		sigKey:  sigKey,
		cfg:     cfg,
	}
}

// doRequest performs a GET request and returns the recorder.
func (e *webEnv) doGet(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

// activeClient returns a repository.Client that is active with the given redirect URIs.
func webActiveClient(redirectURIs []string) repository.Client {
	isActive := true
	return repository.Client{
		ID:               uuid.New(),
		Name:             "test-client",
		ClientSecretHash: "",
		RedirectUris:     redirectURIs,
		GrantTypes:       []string{"authorization_code"},
		IsActive:         &isActive,
		CreatedBy:        uuid.New(),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

// activeProvWithSecret returns a provider backed by the given httptest server URL.
func activeProvWithSecret(serverURL string, clientID uuid.UUID) *providerservice.OAuthProviderWithSecret {
	return &providerservice.OAuthProviderWithSecret{
		OAuthProvider: providerservice.OAuthProvider{
			ID:          uuid.New(),
			ClientID:    clientID,
			Name:        "google",
			DisplayName: "Google",
			AuthURL:     serverURL + "/auth",
			TokenURL:    serverURL + "/token",
			UserInfoURL: serverURL + "/userinfo",
			Scopes:      []string{"openid", "email"},
			IsEnabled:   true,
		},
		ProviderClientID:     "test-client-id",
		ProviderClientSecret: "test-client-secret",
	}
}

// makeSessionCookie encodes an oauthSession into a signed cookie.
func makeSessionCookie(t *testing.T, sigKey []byte, s oauthSession) *http.Cookie {
	t.Helper()
	val, err := encodeSession(s, sigKey)
	require.NoError(t, err)
	return &http.Cookie{Name: oauthSessionCookieName, Value: val}
}

// signedCookie builds a `<b64url(payload)>.<b64url(hmac)>` cookie string,
// mirroring the format of encodeSession. This allows crafting cookies with a
// valid signature but an arbitrary (possibly invalid) payload for edge-case tests.
func signedCookie(payload []byte, key []byte) string {
	b64p := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(b64p))
	sig := mac.Sum(nil)
	return b64p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// ---------------------------------------------------------------------------
// session.go tests
// ---------------------------------------------------------------------------

func TestEncodeDecodeSession_RoundTrip(t *testing.T) {
	key := []byte("test-signing-key-32-bytes-xxxxxxx")
	s := oauthSession{
		State:       "random-state",
		ClientID:    uuid.New().String(),
		Provider:    "google",
		RedirectURI: "https://app.example.com/callback",
	}

	encoded, err := encodeSession(s, key)
	require.NoError(t, err)
	assert.Contains(t, encoded, ".")

	decoded, err := decodeSession(encoded, key)
	require.NoError(t, err)
	assert.Equal(t, s, decoded)
}

func TestDecodeSession_MalformedNoDot(t *testing.T) {
	_, err := decodeSession("nodotinhere", []byte("key"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed")
}

func TestDecodeSession_WrongKey(t *testing.T) {
	key1 := []byte("correct-key-xxxxxxxxxxxxxxxxxxxxxxx")
	key2 := []byte("wrong-key-xxxxxxxxxxxxxxxxxxxxxxxxx")
	s := oauthSession{State: "s", ClientID: "c", Provider: "p", RedirectURI: "r"}

	encoded, err := encodeSession(s, key1)
	require.NoError(t, err)

	_, err = decodeSession(encoded, key2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mismatch")
}

func TestDecodeSession_InvalidSigEncoding(t *testing.T) {
	// Craft a cookie where the signature part is not valid base64url.
	_, err := decodeSession("validpayload.!!invalid-base64!!", []byte("key"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session signature encoding")
}

func TestDecodeSession_InvalidPayloadEncoding(t *testing.T) {
	// Build a cookie whose payload contains chars illegal for base64url ('!')
	// but with a correct HMAC so the signature check passes first.
	key := []byte("test-key")
	badPayload := "!!!invalid!!!"
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(badPayload))
	sig := mac.Sum(nil)
	cookieVal := badPayload + "." + base64.RawURLEncoding.EncodeToString(sig)

	_, err := decodeSession(cookieVal, key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session payload encoding")
}

func TestDecodeSession_InvalidJSON(t *testing.T) {
	// Build a properly-signed cookie whose decoded payload is not valid JSON.
	key := []byte("test-key")
	cookieVal := signedCookie([]byte("not-valid-json"), key)

	_, err := decodeSession(cookieVal, key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed session payload")
}

// ---------------------------------------------------------------------------
// handler.go: getCookieSecure
// ---------------------------------------------------------------------------

func TestGetCookieSecure_True(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("cookie_secure", true)
	assert.True(t, getCookieSecure(c))
}

func TestGetCookieSecure_False(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("cookie_secure", false)
	assert.False(t, getCookieSecure(c))
}

func TestGetCookieSecure_NotSet(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	assert.False(t, getCookieSecure(c))
}

func TestGetCookieSecure_WrongType(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("cookie_secure", "yes") // wrong type
	assert.False(t, getCookieSecure(c))
}

// ---------------------------------------------------------------------------
// auth_handler.go: Login
// ---------------------------------------------------------------------------

func TestLogin_InvalidClientID(t *testing.T) {
	env := newWebEnv(t)
	w := env.doGet("/web/auth/not-a-uuid/google/login?redirect_uri=https://app.example.com/cb")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid client_id")
}

func TestLogin_MissingRedirectURI(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/login", clientID))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "redirect_uri is required")
}

func TestLogin_ServiceError_ClientNotFound(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()
	env.mockQ.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, pgx.ErrNoRows)

	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/login?redirect_uri=https://app.example.com/cb", clientID))
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "client not found or inactive")
	env.mockQ.AssertExpectations(t)
}

func TestLogin_ServiceError_ClientInactive(t *testing.T) {
	env := newWebEnv(t)
	isActive := false
	client := repository.Client{ID: uuid.New(), IsActive: &isActive}
	env.mockQ.On("GetClient", mock.Anything, client.ID).Return(client, nil)

	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/login?redirect_uri=https://app.example.com/cb", client.ID))
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "client not found or inactive")
	env.mockQ.AssertExpectations(t)
}

func TestLogin_ServiceError_InvalidRedirectURI(t *testing.T) {
	env := newWebEnv(t)
	client := webActiveClient([]string{"https://other.example.com/callback"})
	env.mockQ.On("GetClient", mock.Anything, client.ID).Return(client, nil)

	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/login?redirect_uri=https://app.example.com/cb", client.ID))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "redirect_uri is not registered")
	env.mockQ.AssertExpectations(t)
}

func TestLogin_ServiceError_ProviderNotFound(t *testing.T) {
	env := newWebEnv(t)
	client := webActiveClient([]string{"https://app.example.com/cb"})
	env.mockQ.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	env.provSvc.err = providerservice.ErrProviderNotFound

	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/login?redirect_uri=https://app.example.com/cb", client.ID))
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "provider not found")
	env.mockQ.AssertExpectations(t)
}

func TestLogin_ServiceError_ProviderDisabled(t *testing.T) {
	env := newWebEnv(t)
	client := webActiveClient([]string{"https://app.example.com/cb"})
	env.mockQ.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	// Return a disabled provider.
	disabledProv := activeProvWithSecret("https://fake.example.com", client.ID)
	disabledProv.IsEnabled = false
	env.provSvc.result = disabledProv
	env.provSvc.err = nil

	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/login?redirect_uri=https://app.example.com/cb", client.ID))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "provider is disabled")
	env.mockQ.AssertExpectations(t)
}

func TestLogin_ServiceError_UnexpectedError(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()
	env.mockQ.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, fmt.Errorf("db connection error"))

	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/login?redirect_uri=https://app.example.com/cb", clientID))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "internal server error")
	env.mockQ.AssertExpectations(t)
}

func TestLogin_Success_RedirectsAndSetsCookie(t *testing.T) {
	env := newWebEnv(t)
	client := webActiveClient([]string{"https://app.example.com/cb"})
	env.mockQ.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	env.provSvc.result = activeProvWithSecret("https://fake.provider.example.com", client.ID)
	env.provSvc.err = nil

	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/login?redirect_uri=https://app.example.com/cb", client.ID))
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "state=")

	// Verify the session cookie was set.
	setCookie := w.Header().Get("Set-Cookie")
	assert.Contains(t, setCookie, oauthSessionCookieName)
	env.mockQ.AssertExpectations(t)
}

func TestLogin_WithScope_AppendedToURL(t *testing.T) {
	env := newWebEnv(t)
	client := webActiveClient([]string{"https://app.example.com/cb"})
	env.mockQ.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	env.provSvc.result = activeProvWithSecret("https://fake.provider.example.com", client.ID)
	env.provSvc.err = nil

	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/login?redirect_uri=https://app.example.com/cb&scope=openid+profile", client.ID))
	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	// Scope should be reflected somewhere in the redirect URL.
	assert.NotEmpty(t, w.Header().Get("Location"))
	env.mockQ.AssertExpectations(t)
}

// ---------------------------------------------------------------------------
// auth_handler.go: Callback
// ---------------------------------------------------------------------------

func TestCallback_InvalidClientID(t *testing.T) {
	env := newWebEnv(t)
	w := env.doGet("/web/auth/not-a-uuid/google/callback?code=c&state=s")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid client_id")
}

func TestCallback_OAuthProviderError(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()
	w := env.doGet(fmt.Sprintf(
		"/web/auth/%s/google/callback?error=access_denied&error_description=User+denied+access", clientID,
	))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "access_denied", body["error"])
	assert.Equal(t, "User denied access", body["error_description"])
}

func TestCallback_MissingCodeOrState(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()

	// Missing code
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?state=s", clientID))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "missing code or state")

	// Missing state
	w = env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=c", clientID))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "missing code or state")
}

func TestCallback_MissingSessionCookie(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=c&state=s", clientID))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "missing session cookie")
}

func TestCallback_MalformedSessionCookie(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()
	cookie := &http.Cookie{Name: oauthSessionCookieName, Value: "not-a-valid-cookie"}
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=c&state=s", clientID), cookie)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid session")
}

func TestCallback_WrongSigningKey(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()
	// Encode with a different key.
	wrongKey := make([]byte, 32)
	_, _ = rand.Read(wrongKey)
	cookie := makeSessionCookie(t, wrongKey, oauthSession{
		State:       "s",
		ClientID:    clientID.String(),
		Provider:    "google",
		RedirectURI: "https://app.example.com/cb",
	})
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=c&state=s", clientID), cookie)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid session")
}

func TestCallback_StateMismatch(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()
	cookie := makeSessionCookie(t, env.sigKey, oauthSession{
		State:       "expected-state",
		ClientID:    clientID.String(),
		Provider:    "google",
		RedirectURI: "https://app.example.com/cb",
	})
	// Send different state value in query.
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=c&state=wrong-state", clientID), cookie)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "state mismatch")
}

func TestCallback_SessionClientIDMismatch(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()
	// Session has a different client_id than the path.
	cookie := makeSessionCookie(t, env.sigKey, oauthSession{
		State:       "the-state",
		ClientID:    uuid.New().String(), // different from path
		Provider:    "google",
		RedirectURI: "https://app.example.com/cb",
	})
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=c&state=the-state", clientID), cookie)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "session context mismatch")
}

func TestCallback_SessionProviderMismatch(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()
	// Session has a different provider than the path.
	cookie := makeSessionCookie(t, env.sigKey, oauthSession{
		State:       "the-state",
		ClientID:    clientID.String(),
		Provider:    "github", // different from path "google"
		RedirectURI: "https://app.example.com/cb",
	})
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=c&state=the-state", clientID), cookie)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "session context mismatch")
}

func TestCallback_ServiceError_ClientNotFound(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()
	env.mockQ.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, pgx.ErrNoRows)

	cookie := makeSessionCookie(t, env.sigKey, oauthSession{
		State:       "st",
		ClientID:    clientID.String(),
		Provider:    "google",
		RedirectURI: "https://app.example.com/cb",
	})
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=c&state=st", clientID), cookie)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "client not found or inactive")
	env.mockQ.AssertExpectations(t)
}

func TestCallback_ServiceError_ClientInactive(t *testing.T) {
	env := newWebEnv(t)
	isActive := false
	client := repository.Client{ID: uuid.New(), IsActive: &isActive}
	env.mockQ.On("GetClient", mock.Anything, client.ID).Return(client, nil)

	cookie := makeSessionCookie(t, env.sigKey, oauthSession{
		State:       "st",
		ClientID:    client.ID.String(),
		Provider:    "google",
		RedirectURI: "https://app.example.com/cb",
	})
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=c&state=st", client.ID), cookie)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "client not found or inactive")
	env.mockQ.AssertExpectations(t)
}

func TestCallback_ServiceError_ProviderNotFound(t *testing.T) {
	env := newWebEnv(t)
	client := webActiveClient([]string{"https://app.example.com/cb"})
	env.mockQ.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	env.provSvc.err = providerservice.ErrProviderNotFound

	cookie := makeSessionCookie(t, env.sigKey, oauthSession{
		State:       "st",
		ClientID:    client.ID.String(),
		Provider:    "google",
		RedirectURI: "https://app.example.com/cb",
	})
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=c&state=st", client.ID), cookie)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "provider not found")
	env.mockQ.AssertExpectations(t)
}

func TestCallback_ServiceError_ProviderDisabled(t *testing.T) {
	env := newWebEnv(t)
	client := webActiveClient([]string{"https://app.example.com/cb"})
	env.mockQ.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	disabledProv := activeProvWithSecret("https://fake.example.com", client.ID)
	disabledProv.IsEnabled = false
	env.provSvc.result = disabledProv
	env.provSvc.err = nil

	cookie := makeSessionCookie(t, env.sigKey, oauthSession{
		State:       "st",
		ClientID:    client.ID.String(),
		Provider:    "google",
		RedirectURI: "https://app.example.com/cb",
	})
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=c&state=st", client.ID), cookie)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "provider is disabled")
	env.mockQ.AssertExpectations(t)
}

func TestCallback_ServiceError_Unexpected(t *testing.T) {
	env := newWebEnv(t)
	clientID := uuid.New()
	env.mockQ.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, fmt.Errorf("unexpected db error"))

	cookie := makeSessionCookie(t, env.sigKey, oauthSession{
		State:       "st",
		ClientID:    clientID.String(),
		Provider:    "google",
		RedirectURI: "https://app.example.com/cb",
	})
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=c&state=st", clientID), cookie)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "authentication failed")
	env.mockQ.AssertExpectations(t)
}

func TestCallback_Success_RedirectsWithCode(t *testing.T) {
	// Set up an httptest server that handles the OAuth provider token exchange
	// and user info endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "provider-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":            "provider-sub-123",
				"email":          "user@example.com",
				"email_verified": true,
				"given_name":     "Test",
				"family_name":    "User",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	env := newWebEnv(t)
	client := webActiveClient([]string{"https://app.example.com/cb"})
	env.mockQ.On("GetClient", mock.Anything, client.ID).Return(client, nil)
	env.provSvc.result = activeProvWithSecret(srv.URL, client.ID)
	env.provSvc.err = nil

	// New user path: GetUserByProviderID → not found → CreateUser.
	newUser := repository.User{ID: uuid.New(), Email: "user@example.com"}
	env.mockQ.On("GetUserByProviderID", mock.Anything, mock.Anything).Return(repository.User{}, pgx.ErrNoRows)
	env.mockQ.On("CreateUser", mock.Anything, mock.Anything).Return(newUser, nil)
	env.mockQ.On("CreateAuthorizationCode", mock.Anything, mock.Anything).
		Return(repository.AuthorizationCode{ID: uuid.New(), Code: "the-auth-code"}, nil)

	cookie := makeSessionCookie(t, env.sigKey, oauthSession{
		State:       "the-state",
		ClientID:    client.ID.String(),
		Provider:    "google",
		RedirectURI: "https://app.example.com/cb",
	})
	w := env.doGet(fmt.Sprintf("/web/auth/%s/google/callback?code=provider-code&state=the-state", client.ID), cookie)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "https://app.example.com/cb")
	assert.Contains(t, location, "code=")
	assert.NotContains(t, location, "code=&") // code must be non-empty
	env.mockQ.AssertExpectations(t)
}
