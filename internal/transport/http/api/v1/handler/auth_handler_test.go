package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
// GET /api/v1/clients/:client_id/auth/providers
// ---------------------------------------------------------------------------

func TestListEnabledProviders_Success(t *testing.T) {
	env := newTestEnv(t)
	clientID := uuid.New()

	isEnabled := true
	env.mockQ.On("ListEnabledOAuthProvidersByClient", mock.Anything, clientID).
		Return([]repository.OauthProvider{
			buildOAuthProvider(uuid.New(), clientID, "google"),
			{
				ID:          uuid.New(),
				ClientID:    clientID,
				Name:        "github",
				DisplayName: "GitHub",
				IsEnabled:   &isEnabled,
				Scopes:      []string{"user"},
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
		}, nil)

	w := env.doRequest(http.MethodGet, "/api/v1/clients/"+clientID.String()+"/auth/providers", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Providers []struct {
			Name        string `json:"name"`
			DisplayName string `json:"display_name"`
		} `json:"providers"`
	}
	parseJSON(t, w, &resp)
	assert.Len(t, resp.Providers, 2)
	assert.Equal(t, "google", resp.Providers[0].Name)
	assert.Equal(t, "github", resp.Providers[1].Name)
	env.mockQ.AssertExpectations(t)
}

func TestListEnabledProviders_InvalidClientID(t *testing.T) {
	env := newTestEnv(t)

	w := env.doRequest(http.MethodGet, "/api/v1/clients/not-a-uuid/auth/providers", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListEnabledProviders_EmptyList(t *testing.T) {
	env := newTestEnv(t)
	clientID := uuid.New()

	env.mockQ.On("ListEnabledOAuthProvidersByClient", mock.Anything, clientID).
		Return([]repository.OauthProvider{}, nil)

	w := env.doRequest(http.MethodGet, "/api/v1/clients/"+clientID.String()+"/auth/providers", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Providers []interface{} `json:"providers"`
	}
	parseJSON(t, w, &resp)
	assert.Empty(t, resp.Providers)
}

// TestListEnabledProviders_ExcludesSensitiveData verifies that only name and
// display_name are present in the public provider response — no credentials or URLs.
func TestListEnabledProviders_ExcludesSensitiveData(t *testing.T) {
	env := newTestEnv(t)
	clientID := uuid.New()

	env.mockQ.On("ListEnabledOAuthProvidersByClient", mock.Anything, clientID).
		Return([]repository.OauthProvider{
			buildOAuthProvider(uuid.New(), clientID, "google"),
		}, nil)

	w := env.doRequest(http.MethodGet, "/api/v1/clients/"+clientID.String()+"/auth/providers", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	providers := raw["providers"].([]interface{})
	require.Len(t, providers, 1)

	p := providers[0].(map[string]interface{})
	assert.Contains(t, p, "name")
	assert.Contains(t, p, "display_name")
	assert.NotContains(t, p, "provider_client_id")
	assert.NotContains(t, p, "provider_client_secret")
	assert.NotContains(t, p, "auth_url")
	assert.NotContains(t, p, "token_url")
	assert.NotContains(t, p, "user_info_url")
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/token
// ---------------------------------------------------------------------------

func buildActiveClientWithSecret(t *testing.T, redirectURI string) (repository.Client, string) {
	t.Helper()
	plainSecret := "my-plain-secret"
	hash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.MinCost)
	require.NoError(t, err)

	isActive := true
	cl := repository.Client{
		ID:               uuid.New(),
		Name:             "test-client",
		ClientSecretHash: string(hash),
		RedirectUris:     []string{redirectURI},
		GrantTypes:       []string{"authorization_code"},
		IsActive:         &isActive,
		CreatedBy:        uuid.New(),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	return cl, plainSecret
}

func buildValidAuthCode(clientID, userID, providerID uuid.UUID, redirectURI string) repository.AuthorizationCode {
	notRevoked := false
	return repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "valid-auth-code-xyz",
		ClientID:    clientID,
		UserID:      userID,
		ProviderID:  providerID,
		RedirectUri: redirectURI,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		IsRevoked:   &notRevoked,
	}
}

func TestTokenExchange_Success(t *testing.T) {
	env := newTestEnv(t)
	redirectURI := "https://app.example.com/callback"
	cl, plainSecret := buildActiveClientWithSecret(t, redirectURI)
	userID := uuid.New()
	providerID := uuid.New()
	code := buildValidAuthCode(cl.ID, userID, providerID, redirectURI)

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)
	env.mockQ.On("GetAuthorizationCode", mock.Anything, "valid-auth-code-xyz").Return(code, nil)
	env.mockQ.On("MarkAuthorizationCodeUsed", mock.Anything, code.ID).Return(code, nil)
	env.mockQ.On("GetUserByID", mock.Anything, userID).Return(buildAdminUser(userID), nil)
	env.mockQ.On("CreateAccessToken", mock.Anything, mock.AnythingOfType("repository.CreateAccessTokenParams")).
		Return(repository.AccessToken{
			ID:        uuid.New(),
			TokenHash: "some-hash",
			ClientID:  cl.ID,
			UserID:    userID,
			ExpiresAt: time.Now().Add(time.Hour),
		}, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "valid-auth-code-xyz",
		"client_id":     cl.ID.String(),
		"client_secret": plainSecret,
		"redirect_uri":  redirectURI,
	})

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	parseJSON(t, w, &resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Greater(t, resp.ExpiresIn, int64(0))
	env.mockQ.AssertExpectations(t)
}

func TestTokenExchange_MissingFields(t *testing.T) {
	env := newTestEnv(t)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"client_id":     uuid.New().String(),
		"client_secret": "secret",
		"redirect_uri":  "https://app.example.com/callback",
		// missing "code"
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTokenExchange_UnsupportedGrantType(t *testing.T) {
	env := newTestEnv(t)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "client_credentials",
		"code":          "some-code",
		"client_id":     uuid.New().String(),
		"client_secret": "secret",
		"redirect_uri":  "https://app.example.com/callback",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "unsupported_grant_type", resp["error"])
}

func TestTokenExchange_InvalidClientID(t *testing.T) {
	env := newTestEnv(t)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "some-code",
		"client_id":     "not-a-uuid",
		"client_secret": "secret",
		"redirect_uri":  "https://app.example.com/callback",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "invalid_client", resp["error"])
}

func TestTokenExchange_ClientNotFound(t *testing.T) {
	env := newTestEnv(t)
	clientID := uuid.New()

	env.mockQ.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, pgx.ErrNoRows)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "some-code",
		"client_id":     clientID.String(),
		"client_secret": "secret",
		"redirect_uri":  "https://app.example.com/callback",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "invalid_client", resp["error"])
}

func TestTokenExchange_InvalidClientSecret(t *testing.T) {
	env := newTestEnv(t)
	redirectURI := "https://app.example.com/callback"
	cl, _ := buildActiveClientWithSecret(t, redirectURI)

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "some-code",
		"client_id":     cl.ID.String(),
		"client_secret": "wrong-secret",
		"redirect_uri":  redirectURI,
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "invalid_client", resp["error"])
}

func TestTokenExchange_CodeNotFound(t *testing.T) {
	env := newTestEnv(t)
	redirectURI := "https://app.example.com/callback"
	cl, plainSecret := buildActiveClientWithSecret(t, redirectURI)

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)
	env.mockQ.On("GetAuthorizationCode", mock.Anything, "bad-code").
		Return(repository.AuthorizationCode{}, pgx.ErrNoRows)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "bad-code",
		"client_id":     cl.ID.String(),
		"client_secret": plainSecret,
		"redirect_uri":  redirectURI,
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "invalid_grant", resp["error"])
}

func TestTokenExchange_ExpiredCode(t *testing.T) {
	env := newTestEnv(t)
	redirectURI := "https://app.example.com/callback"
	cl, plainSecret := buildActiveClientWithSecret(t, redirectURI)
	notRevoked := false
	expiredCode := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "expired-code",
		ClientID:    cl.ID,
		UserID:      uuid.New(),
		ProviderID:  uuid.New(),
		RedirectUri: redirectURI,
		ExpiresAt:   time.Now().Add(-1 * time.Minute),
		IsRevoked:   &notRevoked,
	}

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)
	env.mockQ.On("GetAuthorizationCode", mock.Anything, "expired-code").Return(expiredCode, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "expired-code",
		"client_id":     cl.ID.String(),
		"client_secret": plainSecret,
		"redirect_uri":  redirectURI,
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "invalid_grant", resp["error"])
}

func TestTokenExchange_CodeClientMismatch(t *testing.T) {
	env := newTestEnv(t)
	redirectURI := "https://app.example.com/callback"
	cl, plainSecret := buildActiveClientWithSecret(t, redirectURI)
	notRevoked := false
	codeForOtherClient := repository.AuthorizationCode{
		ID:          uuid.New(),
		Code:        "other-client-code",
		ClientID:    uuid.New(), // different client
		UserID:      uuid.New(),
		ProviderID:  uuid.New(),
		RedirectUri: redirectURI,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		IsRevoked:   &notRevoked,
	}

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)
	env.mockQ.On("GetAuthorizationCode", mock.Anything, "other-client-code").Return(codeForOtherClient, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "other-client-code",
		"client_id":     cl.ID.String(),
		"client_secret": plainSecret,
		"redirect_uri":  redirectURI,
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "invalid_grant", resp["error"])
}

func TestTokenExchange_RedirectURIMismatch(t *testing.T) {
	env := newTestEnv(t)
	redirectURI := "https://app.example.com/callback"
	cl, plainSecret := buildActiveClientWithSecret(t, redirectURI)
	code := buildValidAuthCode(cl.ID, uuid.New(), uuid.New(), redirectURI)

	env.mockQ.On("GetClient", mock.Anything, cl.ID).Return(cl, nil)
	env.mockQ.On("GetAuthorizationCode", mock.Anything, code.Code).Return(code, nil)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/token", map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          code.Code,
		"client_id":     cl.ID.String(),
		"client_secret": plainSecret,
		"redirect_uri":  "https://attacker.example.com/callback",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "invalid_grant", resp["error"])
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/logout
// ---------------------------------------------------------------------------

func TestLogout_Success(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New()
	token := env.generateToken(t, userID.String(), "user@example.com")
	tokenRow := activeTokenRow(token, userID)

	env.mockQ.On("GetAccessToken", mock.Anything, hashToken(token)).Return(tokenRow, nil).Once()
	env.mockQ.On("GetAccessToken", mock.Anything, hashToken(token)).Return(tokenRow, nil).Once()
	env.mockQ.On("RevokeAccessToken", mock.Anything, tokenRow.ID).Return(nil)

	w := env.doAuthRequest(http.MethodPost, "/api/v1/auth/logout", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)
	env.mockQ.AssertExpectations(t)
}

func TestLogout_Unauthorized_NoToken(t *testing.T) {
	env := newTestEnv(t)

	w := env.doRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogout_Unauthorized_RevokedToken(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New()
	token := env.generateToken(t, userID.String(), "user@example.com")

	env.mockQ.On("GetAccessToken", mock.Anything, hashToken(token)).
		Return(revokedTokenRow(token), nil)

	w := env.doAuthRequest(http.MethodPost, "/api/v1/auth/logout", nil, token)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// GET /api/v1/auth/me
// ---------------------------------------------------------------------------

func TestGetCurrentUser_Success(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New()
	token := env.generateToken(t, userID.String(), "user@example.com")
	tokenRow := activeTokenRow(token, userID)
	userRow := buildRegularUser(userID)

	env.mockQ.On("GetAccessToken", mock.Anything, hashToken(token)).Return(tokenRow, nil)
	env.mockQ.On("GetUserByID", mock.Anything, userID).Return(userRow, nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/auth/me", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	parseJSON(t, w, &resp)
	assert.Equal(t, userID.String(), resp.User.ID)
	assert.Equal(t, "user@example.com", resp.User.Email)
	env.mockQ.AssertExpectations(t)
}

func TestGetCurrentUser_Unauthorized(t *testing.T) {
	env := newTestEnv(t)

	w := env.doRequest(http.MethodGet, "/api/v1/auth/me", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ---------------------------------------------------------------------------
// Auth middleware edge cases
// ---------------------------------------------------------------------------

func TestProtectedRoute_MalformedAuthHeader(t *testing.T) {
	env := newTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "NotBearer sometoken")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProtectedRoute_ExpiredToken(t *testing.T) {
	env := newTestEnv(t)
	expiredToken := buildExpiredJWT(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/auth/me", nil, expiredToken)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// buildExpiredJWT signs a JWT with a past expiration using the test env's private key.
func buildExpiredJWT(t *testing.T, env *testEnv) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id": uuid.New().String(),
		"email":   "user@example.com",
		"exp":     now.Add(-1 * time.Minute).Unix(),
		"iat":     now.Add(-2 * time.Minute).Unix(),
		"nbf":     now.Add(-2 * time.Minute).Unix(),
		"iss":     "test-app",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := tok.SignedString(env.privKey)
	require.NoError(t, err)
	return signed
}
