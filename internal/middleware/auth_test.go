package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

// testAuthHelper holds a real auth.Service backed by a mock querier, along with
// the private key used to sign tokens.  Keeping the private key here allows tests
// to mint arbitrary JWTs (including expired ones) without touching package-private
// functions.
type testAuthHelper struct {
	service *auth.Service
	privKey *ecdsa.PrivateKey
}

// newTestAuthHelper creates an auth.Service initialised with a freshly-generated
// ECDSA P-256 key pair and the supplied mock querier.
func newTestAuthHelper(t *testing.T, q *mocks.MockQuerier) *testAuthHelper {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privDER, err := x509.MarshalECPrivateKey(privKey)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	cfg := &config.Config{
		App: config.AppConfig{Name: "test-app"},
		AccessToken: config.AccessTokenConfig{
			PrivateKey: privPEM,
			PublicKey:  pubPEM,
			Expiry:     60,
		},
	}

	svc, err := auth.New(q, cfg, nil, nil)
	require.NoError(t, err)

	return &testAuthHelper{service: svc, privKey: privKey}
}

// generateValidToken mints a valid JWT via the service's GenerateAccessToken method.
func (h *testAuthHelper) generateValidToken(t *testing.T) string {
	t.Helper()
	token, err := h.service.GenerateAccessToken("user-id-123", "test@example.com")
	require.NoError(t, err)
	return token
}

// generateExpiredToken creates a JWT whose expiry is set in the past but signed
// with the same private key as the service, so only the time check fails.
func (h *testAuthHelper) generateExpiredToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id": "user-id-123",
		"email":   "test@example.com",
		"exp":     now.Add(-1 * time.Minute).Unix(),
		"iat":     now.Add(-2 * time.Minute).Unix(),
		"nbf":     now.Add(-2 * time.Minute).Unix(),
		"iss":     "test-app",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := token.SignedString(h.privKey)
	require.NoError(t, err)
	return signed
}

// activeTokenRecord returns a non-revoked AccessToken row for the given raw token.
func activeTokenRecord(rawToken string) repository.AccessToken {
	notRevoked := false
	return repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: util.SHA256Hex(rawToken),
		ClientID:  uuid.New(),
		UserID:    uuid.New(),
		ExpiresAt: time.Now().Add(time.Hour),
		IsRevoked: &notRevoked,
	}
}

// revokedTokenRecord returns an IsRevoked=true AccessToken row for the given raw token.
func revokedTokenRecord(rawToken string) repository.AccessToken {
	revoked := true
	return repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: util.SHA256Hex(rawToken),
		ClientID:  uuid.New(),
		UserID:    uuid.New(),
		ExpiresAt: time.Now().Add(time.Hour),
		IsRevoked: &revoked,
	}
}

// ---------------------------------------------------------------------------
// AuthMiddleware tests
// ---------------------------------------------------------------------------

func TestAuthMiddleware_MissingToken_NoCookieOrHeader(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	h := newTestAuthHelper(t, mockQ)
	router := setupTestRouter()

	var handlerCalled bool
	router.GET("/protected", AuthMiddleware(h.service), func(c *gin.Context) {
		handlerCalled = true
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "no token")
	assert.False(t, handlerCalled)
	mockQ.AssertNotCalled(t, "GetAccessToken")
}

func TestAuthMiddleware_MalformedAuthHeader(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	h := newTestAuthHelper(t, mockQ)
	router := setupTestRouter()

	var handlerCalled bool
	router.GET("/protected", AuthMiddleware(h.service), func(c *gin.Context) {
		handlerCalled = true
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearertoken-without-space")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "malformed")
	assert.False(t, handlerCalled)
	mockQ.AssertNotCalled(t, "GetAccessToken")
}

func TestAuthMiddleware_InvalidJWT(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	h := newTestAuthHelper(t, mockQ)
	router := setupTestRouter()

	var handlerCalled bool
	router.GET("/protected", AuthMiddleware(h.service), func(c *gin.Context) {
		handlerCalled = true
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "not.a.valid.jwt"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid token")
	assert.False(t, handlerCalled)
	mockQ.AssertNotCalled(t, "GetAccessToken")
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	h := newTestAuthHelper(t, mockQ)
	router := setupTestRouter()

	var handlerCalled bool
	router.GET("/protected", AuthMiddleware(h.service), func(c *gin.Context) {
		handlerCalled = true
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	expiredToken := h.generateExpiredToken(t)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: expiredToken})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid token")
	assert.False(t, handlerCalled)
	// Expiry check happens in JWT validation; DB is never consulted.
	mockQ.AssertNotCalled(t, "GetAccessToken")
}

func TestAuthMiddleware_TokenNotFoundInDB(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	h := newTestAuthHelper(t, mockQ)
	router := setupTestRouter()

	validToken := h.generateValidToken(t)
	// Token not present in DB → treated as NOT revoked.
	// Direct-login tokens (v0.3.0+) are not persisted in access_tokens;
	// their validity is enforced solely by the JWT signature and expiry claim.
	mockQ.On("GetAccessToken", mock.Anything, util.SHA256Hex(validToken)).
		Return(repository.AccessToken{}, pgx.ErrNoRows)

	var handlerCalled bool
	router.GET("/protected", AuthMiddleware(h.service), func(c *gin.Context) {
		handlerCalled = true
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: validToken})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, handlerCalled)
	mockQ.AssertExpectations(t)
}

func TestAuthMiddleware_RevokedToken(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	h := newTestAuthHelper(t, mockQ)
	router := setupTestRouter()

	validToken := h.generateValidToken(t)
	mockQ.On("GetAccessToken", mock.Anything, util.SHA256Hex(validToken)).
		Return(revokedTokenRecord(validToken), nil)

	var handlerCalled bool
	router.GET("/protected", AuthMiddleware(h.service), func(c *gin.Context) {
		handlerCalled = true
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: validToken})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "revoked")
	assert.False(t, handlerCalled)
	mockQ.AssertExpectations(t)
}

func TestAuthMiddleware_RevocationDBError(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	h := newTestAuthHelper(t, mockQ)
	router := setupTestRouter()

	validToken := h.generateValidToken(t)
	mockQ.On("GetAccessToken", mock.Anything, util.SHA256Hex(validToken)).
		Return(repository.AccessToken{}, assert.AnError)

	var handlerCalled bool
	router.GET("/protected", AuthMiddleware(h.service), func(c *gin.Context) {
		handlerCalled = true
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: validToken})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.False(t, handlerCalled)
	mockQ.AssertExpectations(t)
}

func TestAuthMiddleware_ValidToken_Cookie(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	h := newTestAuthHelper(t, mockQ)
	router := setupTestRouter()

	validToken := h.generateValidToken(t)
	mockQ.On("GetAccessToken", mock.Anything, util.SHA256Hex(validToken)).
		Return(activeTokenRecord(validToken), nil)

	var capturedUserID, capturedEmail, capturedRawToken string
	router.GET("/protected", AuthMiddleware(h.service), func(c *gin.Context) {
		uid, _ := c.Get("user_id")
		capturedUserID = uid.(string)
		email, _ := c.Get("email")
		capturedEmail = email.(string)
		raw, _ := c.Get("raw_token")
		capturedRawToken = raw.(string)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: validToken})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "user-id-123", capturedUserID)
	assert.Equal(t, "test@example.com", capturedEmail)
	assert.Equal(t, validToken, capturedRawToken)
	mockQ.AssertExpectations(t)
}

func TestAuthMiddleware_ValidToken_BearerHeader(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	h := newTestAuthHelper(t, mockQ)
	router := setupTestRouter()

	validToken := h.generateValidToken(t)
	mockQ.On("GetAccessToken", mock.Anything, util.SHA256Hex(validToken)).
		Return(activeTokenRecord(validToken), nil)

	var capturedUserID string
	router.GET("/protected", AuthMiddleware(h.service), func(c *gin.Context) {
		uid, _ := c.Get("user_id")
		capturedUserID = uid.(string)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "user-id-123", capturedUserID)
	mockQ.AssertExpectations(t)
}

func TestAuthMiddleware_HeaderTakesPrecedenceOverCookie(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	h := newTestAuthHelper(t, mockQ)
	router := setupTestRouter()

	// Only the header token is active; the cookie token is not set up on the mock,
	// which means the middleware must prefer the header.
	headerToken := h.generateValidToken(t)
	mockQ.On("GetAccessToken", mock.Anything, util.SHA256Hex(headerToken)).
		Return(activeTokenRecord(headerToken), nil)

	router.GET("/protected", AuthMiddleware(h.service), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+headerToken)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "some-other-token"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockQ.AssertExpectations(t)
}

func TestAuthMiddleware_HandlerAbortedOnUnauthorized(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	h := newTestAuthHelper(t, mockQ)
	router := setupTestRouter()

	var nextHandlerCalled bool
	router.GET("/protected",
		AuthMiddleware(h.service),
		func(c *gin.Context) {
			nextHandlerCalled = true
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, nextHandlerCalled, "next handler should not be called when unauthorized")
}
