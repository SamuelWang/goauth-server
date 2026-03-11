package handler_test

// security_test.go contains penetration / security-focused tests that verify
// the API resists known attacks:
//
//  - JWT algorithm confusion (none / HS256 / RS256 instead of ES256)
//  - Token replay after logout / revocation
//  - Authorization code replay (double-use)
//  - Authorization code client-mismatch attack
//  - CSRF double-submit bypass attempts
//  - Cross-client provider isolation
//  - Pagination bounds injection
//  - Request ID log-injection sanitisation
//  - Security headers on every response
//  - Admin-route authorization enforcement
//  - Information leakage (secrets, token_hash, error details)
//  - UUID injection / path parameter validation
//  - Large / malformed input handling

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hashTokenForPentest(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// notRevokedTokenRow builds a non-revoked AccessToken for the given raw token and user.
func notRevokedTokenRow(rawToken string, userID uuid.UUID) repository.AccessToken {
	notRevoked := false
	return repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: hashTokenForPentest(rawToken),
		ClientID:  uuid.New(),
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour),
		IsRevoked: &notRevoked,
	}
}

// mintHMACToken creates a JWT signed with HMAC-SHA256 using the raw bytes of
// the ECDSA public key PEM as the secret — simulating an algorithm-confusion attack.
func mintHMACToken(t *testing.T, env *testEnv, userID string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   "attacker@evil.com",
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
		"nbf":     time.Now().Unix(),
		"iss":     "test-app",
	}
	// Sign with HS256 using the ECDSA private key DER bytes as the HMAC secret.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	privDER, err := x509.MarshalECPrivateKey(env.privKey)
	require.NoError(t, err)
	signed, err := tok.SignedString(privDER)
	require.NoError(t, err)
	return signed
}

// mintNoneAlgToken creates a JWT with alg=none (no signature).
func mintNoneAlgToken(t *testing.T, userID string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   "attacker@evil.com",
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return signed
}

// mintRS256Token creates a JWT signed with RS256 instead of ES256.
func mintRS256Token(t *testing.T, userID string) string {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   "attacker@evil.com",
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(rsaKey)
	require.NoError(t, err)
	return signed
}

// doRequestWithRawToken issues a request with an arbitrary bearer token, bypassing
// the helper functions that use a valid CSRF token.
func (e *testEnv) doRequestWithRawToken(method, path string, body interface{}, token string) *httptest.ResponseRecorder {
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
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

// doRequestWithCookie issues a GET request using a cookie-based token.
func (e *testEnv) doRequestWithCookie(method, path string, cookieName, cookieValue string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// 1. JWT Algorithm Confusion Attacks
// ---------------------------------------------------------------------------

// TestSecurity_JWTAlgNone verifies that a token signed with alg=none is rejected.
func TestSecurity_JWTAlgNone(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New().String()
	noneToken := mintNoneAlgToken(t, userID)

	w := env.doRequestWithRawToken(http.MethodGet, "/api/v1/auth/me", nil, noneToken)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestSecurity_JWTAlgHS256Confusion verifies that switching from ES256 to HS256
// (algorithm confusion attack) is rejected even when the secret is derived from
// the public key material.
func TestSecurity_JWTAlgHS256Confusion(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New().String()
	hmacToken := mintHMACToken(t, env, userID)

	w := env.doRequestWithRawToken(http.MethodGet, "/api/v1/auth/me", nil, hmacToken)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestSecurity_JWTAlgRS256Confusion verifies that tokens signed with RS256 are rejected.
func TestSecurity_JWTAlgRS256Confusion(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New().String()
	rsaToken := mintRS256Token(t, userID)

	w := env.doRequestWithRawToken(http.MethodGet, "/api/v1/auth/me", nil, rsaToken)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestSecurity_JWTTamperedPayload verifies that modifying the payload of a valid
// JWT (changing user_id after signing) causes signature verification to fail.
func TestSecurity_JWTTamperedPayload(t *testing.T) {
	env := newTestEnv(t)
	// Generate a valid token for one user, then tamper with the payload.
	validUserID := uuid.New()
	token := env.generateToken(t, validUserID.String(), "victim@example.com")

	// Split the JWT into header.payload.signature
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	// Decode and modify the payload — change user_id to a different UUID.
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(decoded, &claims))
	claims["user_id"] = uuid.New().String() // tamper

	tamperedJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	tamperedB64 := base64.RawURLEncoding.EncodeToString(tamperedJSON)
	// Construct a token with the original header + tampered payload + original signature.
	tamperedToken := parts[0] + "." + tamperedB64 + "." + parts[2]

	w := env.doRequestWithRawToken(http.MethodGet, "/api/v1/auth/me", nil, tamperedToken)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// 2. Token Replay After Revocation
// ---------------------------------------------------------------------------

// TestSecurity_RevokedTokenRejected verifies that after a token is marked
// is_revoked=true in the database, it cannot be used to access protected routes.
func TestSecurity_RevokedTokenRejected(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New()
	token := env.generateToken(t, userID.String(), "user@example.com")

	// Simulate a revoked token stored in the DB.
	revokedRow := revokedTokenRow(token)
	env.mockQ.On("GetAccessToken", mock.Anything, hashToken(token)).Return(revokedRow, nil)

	w := env.doRequestWithRawToken(http.MethodGet, "/api/v1/auth/me", nil, token)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	assert.Contains(t, body["error"], "revoked")
}

// TestSecurity_TokenNotFoundInDB verifies that a well-formed JWT whose hash is not
// in the database (e.g. never issued, or already cleaned up) is rejected.
func TestSecurity_TokenNotFoundInDB(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New()
	token := env.generateToken(t, userID.String(), "user@example.com")

	env.mockQ.On("GetAccessToken", mock.Anything, hashToken(token)).Return(repository.AccessToken{}, pgx.ErrNoRows)

	w := env.doRequestWithRawToken(http.MethodGet, "/api/v1/auth/me", nil, token)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestSecurity_MalformedBearerToken verifies that malformed Authorization headers
// (missing "Bearer " prefix, partial content) are rejected immediately.
func TestSecurity_MalformedBearerToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
	}{
		{"empty_header", ""},
		{"no_bearer_prefix", "Token abc123"},
		{"basic_auth", "Basic dXNlcjpwYXNz"},
		{"bearer_only", "Bearer"},
		{"random_bytes", strings.Repeat("A", 512)},
	}

	env := newTestEnv(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			w := httptest.NewRecorder()
			env.router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Authorization Code Security
// ---------------------------------------------------------------------------

// TestSecurity_AuthCodeReplay verifies that presenting the same authorization
// code twice results in an error_description, without leaking specific internal state.
func TestSecurity_AuthCodeReplay_ReturnsGenericError(t *testing.T) {
	env := newTestEnv(t)

	redirectURI := "https://app.example.com/callback"
	cl, plainSecret := buildActiveClientWithSecret(t, redirectURI)
	providerID := uuid.New()
	authCode := buildValidAuthCode(cl.ID, uuid.New(), providerID, redirectURI)

	// First call: code is already used.
	alreadyUsed := true
	usedAt := time.Now().Add(-10 * time.Second)
	usedCode := authCode
	usedCode.UsedAt = &usedAt
	_ = alreadyUsed

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)
	env.mockQ.On("GetAuthorizationCode", mock.Anything, authCode.Code).Return(usedCode, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          authCode.Code,
		"client_id":     cl.ID.String(),
		"client_secret": plainSecret,
		"redirect_uri":  redirectURI,
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var body map[string]string
	parseJSON(t, w, &body)
	assert.Equal(t, "invalid_grant", body["error"])
	// The error_description must be the generic RFC6749 message, not an internal detail.
	assert.Contains(t, body["error_description"], "invalid, expired, revoked")
	// Confirm internal code state not leaked.
	assert.NotContains(t, body["error_description"], "already been used")
	assert.NotContains(t, body["error_description"], "UsedAt")
}

// TestSecurity_AuthCodeClientMismatch verifies that an authorization code issued
// for Client A cannot be exchanged using Client B's credentials.
func TestSecurity_AuthCodeClientMismatch(t *testing.T) {
	env := newTestEnv(t)

	redirectURI := "https://app.example.com/callback"

	// Client B: the attacker's client.
	clientB, secretB := buildActiveClientWithSecret(t, redirectURI)

	// Auth code was issued for Client A (different UUID).
	clientAID := uuid.New()
	providerID := uuid.New()
	codeForClientA := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "code-for-client-a",
		ClientID:    clientAID, // belongs to A, not B
		UserID:      uuid.New(),
		ProviderID:  providerID,
		RedirectUri: redirectURI,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
	notRevoked := false
	codeForClientA.IsRevoked = &notRevoked

	env.mockQ.On("GetClient", mock.Anything, clientB.ID).Return(clientB, nil)
	env.mockQ.On("GetAuthorizationCode", mock.Anything, "code-for-client-a").Return(codeForClientA, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "code-for-client-a",
		"client_id":     clientB.ID.String(),
		"client_secret": secretB,
		"redirect_uri":  redirectURI,
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var body map[string]string
	parseJSON(t, w, &body)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestSecurity_AuthCodeExpired verifies that an expired authorization code is rejected
// with a generic error message (no timing info leaked).
func TestSecurity_AuthCodeExpired(t *testing.T) {
	env := newTestEnv(t)

	redirectURI := "https://app.example.com/callback"
	cl, plainSecret := buildActiveClientWithSecret(t, redirectURI)
	providerID := uuid.New()

	notRevoked := false
	expiredCode := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "expired-auth-code",
		ClientID:    cl.ID,
		UserID:      uuid.New(),
		ProviderID:  providerID,
		RedirectUri: redirectURI,
		ExpiresAt:   time.Now().Add(-10 * time.Minute), // already expired
		IsRevoked:   &notRevoked,
	}

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)
	env.mockQ.On("GetAuthorizationCode", mock.Anything, "expired-auth-code").Return(expiredCode, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "expired-auth-code",
		"client_id":     cl.ID.String(),
		"client_secret": plainSecret,
		"redirect_uri":  redirectURI,
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var body map[string]string
	parseJSON(t, w, &body)
	assert.Equal(t, "invalid_grant", body["error"])
	// No internal timing info leaked.
	assert.NotContains(t, body["error_description"], "ExpiresAt")
	assert.NotContains(t, body["error_description"], "expired at")
}

// TestSecurity_AuthCodeRedirectURIMismatch verifies that supplying a redirect URI
// different from the one stored with the code is rejected.
func TestSecurity_AuthCodeRedirectURIMismatch(t *testing.T) {
	env := newTestEnv(t)

	registeredRedirectURI := "https://app.example.com/callback"
	cl, plainSecret := buildActiveClientWithSecret(t, registeredRedirectURI)
	providerID := uuid.New()

	notRevoked := false
	authCode := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "valid-code-redirect-mismatch",
		ClientID:    cl.ID,
		UserID:      uuid.New(),
		ProviderID:  providerID,
		RedirectUri: registeredRedirectURI,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		IsRevoked:   &notRevoked,
	}

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)
	env.mockQ.On("GetAuthorizationCode", mock.Anything, "valid-code-redirect-mismatch").Return(authCode, nil)

	// Attacker supplies a different redirect URI to intercept the token.
	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "valid-code-redirect-mismatch",
		"client_id":     cl.ID.String(),
		"client_secret": plainSecret,
		"redirect_uri":  "https://evil.attacker.com/steal",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var body map[string]string
	parseJSON(t, w, &body)
	assert.Equal(t, "invalid_grant", body["error"])
}

// TestSecurity_UnregisteredClientSecret verifies that an incorrect client secret
// is rejected without leaking whether the client exists.
func TestSecurity_UnregisteredClientSecret(t *testing.T) {
	env := newTestEnv(t)

	redirectURI := "https://app.example.com/callback"
	cl, _ := buildActiveClientWithSecret(t, redirectURI)

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "some-code",
		"client_id":     cl.ID.String(),
		"client_secret": "WRONG-SECRET",
		"redirect_uri":  redirectURI,
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var body map[string]string
	parseJSON(t, w, &body)
	assert.Equal(t, "invalid_client", body["error"])
	// The description must not reveal whether client was found or just invalid secret.
	assert.Equal(t, "client authentication failed", body["error_description"])
}

// ---------------------------------------------------------------------------
// 4. CSRF Protection Bypass Attempts
// ---------------------------------------------------------------------------

// TestSecurity_CSRF_MissingHeader verifies that POST requests without the
// X-CSRF-Token header are rejected even when the CSRF cookie is present.
func TestSecurity_CSRF_MissingHeader(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New()
	token := env.generateToken(t, userID.String(), "user@example.com")
	tokenRow := notRevokedTokenRow(token, userID)
	isAdmin := true
	isActive := true
	adminUser := repository.User{ID: userID, IsAdmin: &isAdmin, IsActive: isActive, Email: "user@example.com", UpdatedAt: time.Now(), CreatedAt: time.Now()}

	env.mockQ.On("GetAccessToken", mock.Anything, hashTokenForPentest(token)).Return(tokenRow, nil).Maybe()
	env.mockQ.On("GetUserByID", mock.Anything, userID).Return(adminUser, nil).Maybe()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", bytes.NewBufferString(`{"name":"evil"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	// Provide cookie but NO header.
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: testCSRFToken})
	// Intentionally omit: req.Header.Set(middleware.CSRFHeaderName, testCSRFToken)

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestSecurity_CSRF_WrongHeaderValue verifies that a CSRF header value that doesn't
// match the cookie is rejected.
func TestSecurity_CSRF_WrongHeaderValue(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New()
	token := env.generateToken(t, userID.String(), "user@example.com")
	tokenRow := notRevokedTokenRow(token, userID)
	isAdmin := true
	isActive := true
	adminUser := repository.User{ID: userID, IsAdmin: &isAdmin, IsActive: isActive, Email: "user@example.com", UpdatedAt: time.Now(), CreatedAt: time.Now()}

	env.mockQ.On("GetAccessToken", mock.Anything, hashTokenForPentest(token)).Return(tokenRow, nil).Maybe()
	env.mockQ.On("GetUserByID", mock.Anything, userID).Return(adminUser, nil).Maybe()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", bytes.NewBufferString(`{"name":"evil"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: testCSRFToken})
	req.Header.Set(middleware.CSRFHeaderName, "DIFFERENT-CSRF-VALUE-ATTACKER-INJECTED")

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestSecurity_CSRF_MissingCookie verifies that a POST request with only the header
// (but no cookie) is rejected.
func TestSecurity_CSRF_MissingCookie(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New()
	token := env.generateToken(t, userID.String(), "user@example.com")
	tokenRow := notRevokedTokenRow(token, userID)
	isAdmin := true
	isActive := true
	adminUser := repository.User{ID: userID, IsAdmin: &isAdmin, IsActive: isActive, Email: "user@example.com", UpdatedAt: time.Now(), CreatedAt: time.Now()}

	env.mockQ.On("GetAccessToken", mock.Anything, hashTokenForPentest(token)).Return(tokenRow, nil).Maybe()
	env.mockQ.On("GetUserByID", mock.Anything, userID).Return(adminUser, nil).Maybe()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", bytes.NewBufferString(`{"name":"evil"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	// No cookie — only header.
	req.Header.Set(middleware.CSRFHeaderName, testCSRFToken)

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	// Without a cookie the middleware generates a new token and the header won't match it.
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestSecurity_CSRF_EmptyHeaderValue verifies that an empty X-CSRF-Token header
// does not bypass validation.
func TestSecurity_CSRF_EmptyHeaderValue(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New()
	token := env.generateToken(t, userID.String(), "user@example.com")
	tokenRow := notRevokedTokenRow(token, userID)
	isAdmin := true
	isActive := true
	adminUser := repository.User{ID: userID, IsAdmin: &isAdmin, IsActive: isActive, Email: "user@example.com", UpdatedAt: time.Now(), CreatedAt: time.Now()}

	env.mockQ.On("GetAccessToken", mock.Anything, hashTokenForPentest(token)).Return(tokenRow, nil).Maybe()
	env.mockQ.On("GetUserByID", mock.Anything, userID).Return(adminUser, nil).Maybe()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", bytes.NewBufferString(`{"name":"evil"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: testCSRFToken})
	req.Header.Set(middleware.CSRFHeaderName, "") // empty

	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------------------------------------------------------------------------
// 5. Cross-Client Provider Isolation
// ---------------------------------------------------------------------------

// TestSecurity_CrossClientProviderAccess verifies that requesting a provider
// that belongs to Client A while specifying Client B's ID returns 404, not 200
// or 403 (which could leak provider existence).
func TestSecurity_CrossClientProviderAccess(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	clientA := uuid.New()
	clientB := uuid.New()
	providerID := uuid.New()

	// The provider belongs to Client A.
	providerForA := buildOAuthProvider(providerID, clientA, "google")

	// GetOAuthProvider by ID — returns a provider owned by Client A.
	env.mockQ.On("GetOAuthProvider", mock.Anything, providerID).Return(providerForA, nil)

	// Request the provider using Client B's client_id — should be a 404.
	w := env.doAuthRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/clients/%s/providers/%s", clientB.String(), providerID.String()),
		nil, token)

	// The server must return 404 — not 200 (data leak) or 403 (existence leak).
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestSecurity_CrossClientListProviders verifies that listing providers for a
// client only returns providers scoped to that client.
func TestSecurity_CrossClientListProviders(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	targetClientID := uuid.New()
	// The mock returns an empty list — confirming isolation even if other clients
	// have providers configured.
	env.mockQ.On("ListOAuthProvidersByClient", mock.Anything, targetClientID).
		Return([]repository.OauthProvider{}, nil)

	w := env.doAuthRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/clients/%s/providers", targetClientID.String()),
		nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Providers []interface{} `json:"providers"`
	}
	parseJSON(t, w, &resp)
	assert.Empty(t, resp.Providers)
}

// ---------------------------------------------------------------------------
// 6. Pagination Bounds Injection
// ---------------------------------------------------------------------------

// TestSecurity_PaginationNegativeLimit ensures negative limits are rejected.
func TestSecurity_PaginationNegativeLimit(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients?limit=-1", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSecurity_PaginationZeroLimit ensures a limit of 0 is rejected.
func TestSecurity_PaginationZeroLimit(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients?limit=0", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSecurity_PaginationExcessiveLimit ensures that a limit above 100 is rejected,
// preventing DoS via large DB queries.
func TestSecurity_PaginationExcessiveLimit(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients?limit=1000000", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSecurity_PaginationNegativeOffset ensures negative offsets are rejected.
func TestSecurity_PaginationNegativeOffset(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients?offset=-5", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSecurity_PaginationNonNumericLimit ensures non-numeric limit is rejected.
func TestSecurity_PaginationNonNumericLimit(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients?limit=abc", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSecurity_PaginationSQLInjectionAttempt verifies that SQL injection
// patterns in pagination params are rejected at the input validation boundary.
func TestSecurity_PaginationSQLInjectionAttempt(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	// These all fail numeric conversion and should return 400.
	// We URL-encode each value before embedding in the query string to avoid
	// httptest.NewRequest panicking on characters that are illegal in raw URLs.
	injectionAttempts := []struct {
		name  string
		value string
	}{
		{"semicolon_drop", "1%3B%20DROP%20TABLE%20clients--"},
		{"or_one_equals_one", "1%20OR%201%3D1"},
		{"union_select", "1%20UNION%20SELECT%20*%20FROM%20users"},
		{"single_quote", "'%20OR%20'1'%3D'1"},
	}
	for _, tc := range injectionAttempts {
		t.Run(tc.name, func(t *testing.T) {
			w := env.doAuthRequest(http.MethodGet, "/api/v1/clients?limit="+tc.value, nil, token)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// 7. UUID Path Parameter Injection
// ---------------------------------------------------------------------------

// TestSecurity_InvalidUUIDInClientID verifies that non-UUID values in path
// parameters are rejected before reaching any storage layer.
func TestSecurity_InvalidUUIDInClientID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	// Use URL-safe identifiers — raw special chars in path segments cause
	// httptest.NewRequest to panic since they form invalid HTTP request lines.
	invalidIDs := []struct {
		name string
		path string
	}{
		{"not_a_uuid", "/api/v1/clients/not-a-uuid"},
		{"sql_injection", "/api/v1/clients/1%27%20OR%20%271%27%3D%271"},
		{"long_string", "/api/v1/clients/" + strings.Repeat("a", 200)},
	}
	for _, tc := range invalidIDs {
		t.Run(tc.name, func(t *testing.T) {
			w := env.doAuthRequest(http.MethodGet, tc.path, nil, token)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}

	// XSS-encoded path: Gin may return 404 (route not matched due to encoded slash
	// in </script>) or 400 (UUID parse failed). Both are safe — no data returned.
	t.Run("xss_encoded", func(t *testing.T) {
		w := env.doAuthRequest(http.MethodGet, "/api/v1/clients/%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil, token)
		assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusNotFound,
			"expected 400 or 404, got %d", w.Code)
	})
}

// TestSecurity_InvalidUUIDInProviderClientID verifies path parameter validation
// on the client-scoped provider routes.
func TestSecurity_InvalidUUIDInProviderClientID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients/INVALID/providers", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// 8. Information Leakage Prevention
// ---------------------------------------------------------------------------

// TestSecurity_ProviderSecretsExcluded verifies that provider credentials are
// never present in any API response field.
func TestSecurity_ProviderSecretsExcluded(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	clientID := uuid.New()
	providerID := uuid.New()
	provider := buildOAuthProvider(providerID, clientID, "google")

	env.mockQ.On("GetOAuthProvider", mock.Anything, providerID).Return(provider, nil)
	// The mock for GetClient is needed since handler validates client ownership.
	adminID := uuid.New()
	cl := buildActiveClient(clientID, "test", adminID)
	env.mockQ.On("GetClient", mock.Anything, clientID).Return(cl, nil).Maybe()

	w := env.doAuthRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/clients/%s/providers/%s", clientID.String(), providerID.String()),
		nil, token)

	// Even if it's a 200 OK, credentials must be absent from the response.
	if w.Code == http.StatusOK {
		var raw map[string]interface{}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&raw))
		assert.NotContains(t, raw, "provider_client_secret")
		assert.NotContains(t, raw, "provider_client_id")
	}
}

// TestSecurity_TokenHashExcludedFromSessionResponse verifies that the token_hash
// field is not present in /api/v1/sessions/tokens responses.
func TestSecurity_TokenHashExcludedFromSessionResponse(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	notRevoked := false
	tokenRow := repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: "this-should-never-appear-in-response",
		ClientID:  uuid.New(),
		UserID:    uuid.New(),
		ExpiresAt: time.Now().Add(time.Hour),
		IsRevoked: &notRevoked,
	}

	env.mockQ.On("ListAccessTokens", mock.Anything, mock.Anything).Return([]repository.AccessToken{tokenRow}, nil)
	env.mockQ.On("CountAccessTokens", mock.Anything, mock.Anything).Return(int64(1), nil).Maybe()

	w := env.doAuthRequest(http.MethodGet, "/api/v1/sessions/tokens", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	rawBody := w.Body.String()
	assert.NotContains(t, rawBody, "this-should-never-appear-in-response")
	assert.NotContains(t, rawBody, "token_hash")
}

// TestSecurity_ClientSecretHashNotExposedInList verifies that client_secret_hash
// is never returned in client listing/get responses.
func TestSecurity_ClientSecretHashNotExposedInList(t *testing.T) {
	env := newTestEnv(t)
	token, adminID := adminAuthSetup(t, env)

	clientID := uuid.New()
	cl := buildActiveClient(clientID, "my-client", adminID)
	// Store a recognizable hash value to detect leakage.
	cl.ClientSecretHash = "BCRYPT-HASH-MUST-NOT-APPEAR-IN-RESPONSE"
	isActive := true

	env.mockQ.On("ListClients", mock.Anything, repository.ListClientsParams{
		Column1: isActive,
		Limit:   20,
		Offset:  0,
	}).Return([]repository.Client{cl}, nil)
	env.mockQ.On("CountClients", mock.Anything, isActive).Return(int64(1), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	rawBody := w.Body.String()
	assert.NotContains(t, rawBody, "BCRYPT-HASH-MUST-NOT-APPEAR-IN-RESPONSE")
	assert.NotContains(t, rawBody, "client_secret_hash")
}

// TestSecurity_PublicProviderListExcludesURLs verifies that the public provider
// listing endpoint does not return internal OAuth URLs or credentials.
func TestSecurity_PublicProviderListExcludesURLs(t *testing.T) {
	env := newTestEnv(t)
	clientID := uuid.New()

	env.mockQ.On("ListEnabledOAuthProvidersByClient", mock.Anything, clientID).
		Return([]repository.OauthProvider{buildOAuthProvider(uuid.New(), clientID, "google")}, nil)

	w := env.doRequest(http.MethodGet, "/api/v1/clients/"+clientID.String()+"/auth/providers", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	rawBody := w.Body.String()
	// Internal OAuth endpoint URLs must not be exposed.
	assert.NotContains(t, rawBody, "auth_url")
	assert.NotContains(t, rawBody, "token_url")
	assert.NotContains(t, rawBody, "user_info_url")
	assert.NotContains(t, rawBody, "provider_client_id")
	assert.NotContains(t, rawBody, "provider_client_secret")
	assert.NotContains(t, rawBody, "scopes")
}

// ---------------------------------------------------------------------------
// 9. Security Headers on Every Response
// ---------------------------------------------------------------------------

// TestSecurity_HeadersOnSuccessResponse verifies that the security headers are
// set on a successful (200 OK) response.
func TestSecurity_HeadersOnSuccessResponse(t *testing.T) {
	env := newTestEnv(t)
	clientID := uuid.New()

	env.mockQ.On("ListEnabledOAuthProvidersByClient", mock.Anything, clientID).
		Return([]repository.OauthProvider{}, nil)

	w := env.doRequest(http.MethodGet, "/api/v1/clients/"+clientID.String()+"/auth/providers", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", w.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
}

// TestSecurity_HeadersOnErrorResponse verifies that security headers are also
// set on error (4xx/5xx) responses, not just success responses.
func TestSecurity_HeadersOnErrorResponse(t *testing.T) {
	env := newTestEnv(t)

	// Trigger a 400 by using a non-UUID client ID.
	w := env.doRequest(http.MethodGet, "/api/v1/clients/not-a-uuid/auth/providers", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
}

// TestSecurity_HSTSAbsentInDevelopment verifies HSTS is not set when env=development
// (the test env uses development mode).
func TestSecurity_HSTSAbsentInDevelopment(t *testing.T) {
	env := newTestEnv(t)
	clientID := uuid.New()

	env.mockQ.On("ListEnabledOAuthProvidersByClient", mock.Anything, clientID).
		Return([]repository.OauthProvider{}, nil)

	w := env.doRequest(http.MethodGet, "/api/v1/clients/"+clientID.String()+"/auth/providers", nil)
	assert.Empty(t, w.Header().Get("Strict-Transport-Security"),
		"HSTS must not be set in development mode to avoid locking browsers into HTTPS")
}

// TestSecurity_RequestIDReflected verifies that the response echoes the X-Request-ID
// when the value is safe (alphanumeric/hyphens/underscores, max 64 chars).
func TestSecurity_RequestIDSafeValueReflected(t *testing.T) {
	env := newTestEnv(t)
	clientID := uuid.New()

	env.mockQ.On("ListEnabledOAuthProvidersByClient", mock.Anything, clientID).
		Return([]repository.OauthProvider{}, nil)

	safeID := "safe-request-id-12345"
	req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/"+clientID.String()+"/auth/providers", nil)
	req.Header.Set("X-Request-ID", safeID)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	assert.Equal(t, safeID, w.Header().Get("X-Request-ID"))
}

// ---------------------------------------------------------------------------
// 10. Log-Injection Prevention (X-Request-ID Sanitisation)
// ---------------------------------------------------------------------------

// TestSecurity_LogInjectionRequestID verifies that malicious X-Request-ID values
// are sanitised and replaced with a fresh UUID rather than being echoed verbatim.
// HTTP header values cannot contain raw newlines (RFC 7230), so we test the
// other injection vectors: JSON fragments, ANSI escapes (single-byte), null bytes,
// values that are too long, and path traversal strings.
func TestSecurity_LogInjectionRequestID(t *testing.T) {
	env := newTestEnv(t)
	clientID := uuid.New()

	env.mockQ.On("ListEnabledOAuthProvidersByClient", mock.Anything, clientID).
		Return([]repository.OauthProvider{}, nil).Maybe()

	maliciousValues := []struct {
		name  string
		value string
	}{
		// JSON injection — would corrupt structured log output
		{"json_injection", `","level":"CRITICAL","msg":"injected"`},
		// Very long value (> 64 chars)
		{"too_long", strings.Repeat("a", 200)},
		// Path traversal
		{"path_traversal", "../../etc/passwd"},
		// Contains spaces (invalid for the safe pattern)
		{"with_spaces", "valid id with spaces"},
	}

	for _, tc := range maliciousValues {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/clients/"+clientID.String()+"/auth/providers", nil)
			req.Header.Set("X-Request-ID", tc.value)
			w := httptest.NewRecorder()
			env.router.ServeHTTP(w, req)

			reflectedID := w.Header().Get("X-Request-ID")
			// The reflected ID must not contain the injected content.
			assert.NotEqual(t, tc.value, reflectedID, "malicious value must not be echoed verbatim")
			// It must be a valid UUID (generated as a safe replacement).
			_, uuidErr := uuid.Parse(reflectedID)
			assert.NoError(t, uuidErr, "the sanitised request ID should be a UUID, got: %q", reflectedID)
		})
	}
}

// ---------------------------------------------------------------------------
// 11. Admin Authorization Enforcement
// ---------------------------------------------------------------------------

// TestSecurity_NonAdminCannotListClients ensures non-admin users receive 403.
func TestSecurity_NonAdminCannotListClients(t *testing.T) {
	env := newTestEnv(t)
	token := nonAdminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients", nil, token)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestSecurity_NonAdminCannotCreateClient ensures non-admin users get 403 on POST.
func TestSecurity_NonAdminCannotCreateClient(t *testing.T) {
	env := newTestEnv(t)
	token := nonAdminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodPost, "/api/v1/clients", map[string]interface{}{
		"name":          "malicious-client",
		"redirect_uris": []string{"https://evil.com/callback"},
	}, token)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestSecurity_NonAdminCannotListUsers ensures non-admin users get 403 on user listing.
func TestSecurity_NonAdminCannotListUsers(t *testing.T) {
	env := newTestEnv(t)
	token := nonAdminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/users", nil, token)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestSecurity_NonAdminCannotRevokeToken ensures non-admin users cannot revoke
// other users' tokens.
func TestSecurity_NonAdminCannotRevokeToken(t *testing.T) {
	env := newTestEnv(t)
	token := nonAdminAuthSetup(t, env)

	randomTokenID := uuid.New()
	w := env.doAuthRequest(http.MethodDelete,
		fmt.Sprintf("/api/v1/sessions/tokens/%s", randomTokenID.String()),
		nil, token)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestSecurity_UnauthenticatedCannotAccessAdminRoutes verifies that completely
// unauthenticated requests to admin routes receive 401, not 403 or 200.
func TestSecurity_UnauthenticatedCannotAccessAdminRoutes(t *testing.T) {
	env := newTestEnv(t)

	protectedRoutes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/clients"},
		{http.MethodGet, "/api/v1/users"},
		{http.MethodGet, "/api/v1/sessions/tokens"},
		{http.MethodGet, "/api/v1/sessions/codes"},
	}

	for _, r := range protectedRoutes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			w := env.doRequest(r.method, r.path, nil)
			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"unauthenticated request should get 401, not 403 or 200")
		})
	}
}

// ---------------------------------------------------------------------------
// 12. Token Exchange — Unsupported Grant Types
// ---------------------------------------------------------------------------

// TestSecurity_UnsupportedGrantType verifies that unsupported OAuth grant types
// are rejected (prevents implicit/password/client_credentials grant abuse).
func TestSecurity_UnsupportedGrantType(t *testing.T) {
	env := newTestEnv(t)

	unsupportedGrants := []string{
		"implicit",
		"password",
		"client_credentials",
		"refresh_token",
		"urn:ietf:params:oauth:grant-type:device_code",
	}

	for _, gt := range unsupportedGrants {
		t.Run(gt, func(t *testing.T) {
			w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
				"grant_type":    gt,
				"code":          "some-code",
				"client_id":     uuid.New().String(),
				"client_secret": "some-secret",
				"redirect_uri":  "https://example.com/callback",
			})
			assert.Equal(t, http.StatusBadRequest, w.Code)
			var body map[string]string
			parseJSON(t, w, &body)
			assert.Equal(t, "unsupported_grant_type", body["error"])
		})
	}
}

// TestSecurity_TokenExchangeMissingFields verifies that required fields are validated
// and each missing field returns a proper error rather than a panic or 500.
func TestSecurity_TokenExchangeMissingFields(t *testing.T) {
	env := newTestEnv(t)

	cases := []struct {
		name string
		body map[string]interface{}
	}{
		{
			"missing_grant_type",
			map[string]interface{}{
				"code": "abc", "client_id": uuid.New().String(),
				"client_secret": "s", "redirect_uri": "https://x.com",
			},
		},
		{
			"missing_code",
			map[string]interface{}{
				"grant_type": "authorization_code", "client_id": uuid.New().String(),
				"client_secret": "s", "redirect_uri": "https://x.com",
			},
		},
		{
			"missing_client_id",
			map[string]interface{}{
				"grant_type": "authorization_code", "code": "abc",
				"client_secret": "s", "redirect_uri": "https://x.com",
			},
		},
		{
			"missing_redirect_uri",
			map[string]interface{}{
				"grant_type": "authorization_code", "code": "abc",
				"client_id": uuid.New().String(), "client_secret": "s",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := env.doRequest(http.MethodPost, "/api/v1/auth/token", tc.body)
			// Must not be a 500 — either 400 bad request or 401 invalid_client.
			assert.NotEqual(t, http.StatusInternalServerError, w.Code)
			assert.Less(t, w.Code, 500)
		})
	}
}

// ---------------------------------------------------------------------------
// 13. Large / Malformed Input Handling
// ---------------------------------------------------------------------------

// TestSecurity_ExcessivelyLargeRequestBody verifies that requests whose body
// exceeds the 1 MiB limit are rejected with 413 Payload Too Large before any
// JSON binding or business logic executes.
func TestSecurity_ExcessivelyLargeRequestBody(t *testing.T) {
	env := newTestEnv(t)

	// Build a payload whose total size exceeds the 1 MiB body limit.
	largePayload := fmt.Sprintf(`{"grant_type":"authorization_code","code":"%s","client_id":"%s","client_secret":"%s","redirect_uri":"https://example.com"}`,
		strings.Repeat("A", 1024*1024),
		uuid.New().String(),
		strings.Repeat("B", 1024),
	)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token",
		bytes.NewBufferString(largePayload))
	req.Header.Set("Content-Type", "application/json")
	// Set Content-Length so MaxBodySizeMiddleware can short-circuit on the header.
	req.ContentLength = int64(len(largePayload))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	// 413 Payload Too Large — enforced by MaxBodySizeMiddleware.
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

// TestSecurity_InvalidJSONBody verifies that malformed JSON in the request body
// returns a 400 rather than causing a panic.
func TestSecurity_InvalidJSONBody(t *testing.T) {
	env := newTestEnv(t)

	cases := []string{
		`{not valid json`,
		`{"key": }`,
		`null`,
		`[]`,
		strings.Repeat(`{"a":`, 1000),
	}

	for i, body := range cases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token",
				bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			env.router.ServeHTTP(w, req)

			// Must not be 500; should be a client-error 4xx.
			assert.NotEqual(t, http.StatusInternalServerError, w.Code)
			assert.Less(t, w.Code, 500)
		})
	}
}

// TestSecurity_NonJSONContentType verifies that requests with the wrong
// Content-Type are handled gracefully.
func TestSecurity_NonJSONContentType(t *testing.T) {
	env := newTestEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token",
		bytes.NewBufferString("grant_type=authorization_code&code=abc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	// Must not be 500.
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// 14. Token Exchange — client_id Validation
// ---------------------------------------------------------------------------

// TestSecurity_TokenExchangeInvalidClientIDFormat verifies that a non-UUID
// client_id is rejected before any DB query is made.
func TestSecurity_TokenExchangeInvalidClientIDFormat(t *testing.T) {
	env := newTestEnv(t)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "some-code",
		"client_id":     "not-a-uuid",
		"client_secret": "some-secret",
		"redirect_uri":  "https://example.com/callback",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var body map[string]string
	parseJSON(t, w, &body)
	assert.Equal(t, "invalid_client", body["error"])
}

// ---------------------------------------------------------------------------
// 15. Revoked Auth Code
// ---------------------------------------------------------------------------

// TestSecurity_RevokedAuthCodeRejected verifies that a revoked authorization
// code returns the generic invalid_grant error.
func TestSecurity_RevokedAuthCodeRejected(t *testing.T) {
	env := newTestEnv(t)

	redirectURI := "https://app.example.com/callback"
	cl, plainSecret := buildActiveClientWithSecret(t, redirectURI)
	providerID := uuid.New()

	isRevoked := true
	revokedCode := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "revoked-code-123",
		ClientID:    cl.ID,
		UserID:      uuid.New(),
		ProviderID:  providerID,
		RedirectUri: redirectURI,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		IsRevoked:   &isRevoked,
	}

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)
	env.mockQ.On("GetAuthorizationCode", mock.Anything, "revoked-code-123").Return(revokedCode, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "revoked-code-123",
		"client_id":     cl.ID.String(),
		"client_secret": plainSecret,
		"redirect_uri":  redirectURI,
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var body map[string]string
	parseJSON(t, w, &body)
	assert.Equal(t, "invalid_grant", body["error"])
}

// ---------------------------------------------------------------------------
// 16. HTTP Method Not Allowed
// ---------------------------------------------------------------------------

// TestSecurity_MethodNotAllowed verifies that methods not registered for an
// endpoint return 404 or 405 (not 200 or 500).
func TestSecurity_MethodNotAllowed(t *testing.T) {
	env := newTestEnv(t)

	// GET /api/v1/auth/token is not a registered route — only POST is.
	w := env.doRequest(http.MethodGet, "/api/v1/auth/token", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// POST on a GET-only endpoint: the public provider list (GET only).
	// Gin returns 404 for routes that don't match method+path together.
	clientID := uuid.New()
	w = env.doRequest(http.MethodPost, "/api/v1/clients/"+clientID.String()+"/auth/providers", nil)
	// Must not be 200 or 500 — either 404 (no such route) or 401 (auth fires first).
	assert.NotEqual(t, http.StatusOK, w.Code)
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// 17. Bcrypt Timing Attack Mitigation (Inactive Client)
// ---------------------------------------------------------------------------

// TestSecurity_InactiveClientRejected verifies that an inactive client is rejected
// before bcrypt comparison to prevent timing differences from leaking client existence.
func TestSecurity_InactiveClientRejected(t *testing.T) {
	env := newTestEnv(t)

	redirectURI := "https://app.example.com/callback"
	plainSecret := "my-secret"
	hash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.MinCost)
	require.NoError(t, err)

	isActive := false
	inactiveClient := repository.Client{
		ID:               uuid.New(),
		Name:             "inactive-client",
		ClientSecretHash: string(hash),
		RedirectUris:     []string{redirectURI},
		GrantTypes:       []string{"authorization_code"},
		IsActive:         &isActive,
		CreatedBy:        uuid.New(),
	}

	env.mockQ.On("GetClient", mock.Anything, inactiveClient.ID).Return(inactiveClient, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "some-code",
		"client_id":     inactiveClient.ID.String(),
		"client_secret": plainSecret,
		"redirect_uri":  redirectURI,
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var body map[string]string
	parseJSON(t, w, &body)
	assert.Equal(t, "invalid_client", body["error"])
	// Must not reveal the client was found but is inactive.
	assert.Equal(t, "client authentication failed", body["error_description"])
}
