package handler_test

import (
	"net/http"
	"testing"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// ---------------------------------------------------------------------------
// GET /api/v1/clients/:client_id/providers
// ---------------------------------------------------------------------------

func TestListProviders_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	clientID := uuid.New()

	env.mockQ.On("ListOAuthProvidersByClient", mock.Anything, clientID).
		Return([]repository.OauthProvider{
			buildOAuthProvider(uuid.New(), clientID, "google"),
			buildOAuthProvider(uuid.New(), clientID, "github"),
		}, nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients/"+clientID.String()+"/providers", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Providers []struct {
			Name string `json:"name"`
		} `json:"providers"`
	}
	parseJSON(t, w, &resp)
	assert.Len(t, resp.Providers, 2)
	env.mockQ.AssertExpectations(t)
}

func TestListProviders_Unauthenticated(t *testing.T) {
	env := newTestEnv(t)
	clientID := uuid.New()

	w := env.doRequest(http.MethodGet, "/api/v1/clients/"+clientID.String()+"/providers", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListProviders_NonAdmin(t *testing.T) {
	env := newTestEnv(t)
	token := nonAdminAuthSetup(t, env)
	clientID := uuid.New()

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients/"+clientID.String()+"/providers", nil, token)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestListProviders_InvalidClientID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients/not-a-uuid/providers", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListProviders_ExcludesCredentials verifies provider credentials are not
// present in list responses.
func TestListProviders_ExcludesCredentials(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	clientID := uuid.New()

	env.mockQ.On("ListOAuthProvidersByClient", mock.Anything, clientID).
		Return([]repository.OauthProvider{
			buildOAuthProvider(uuid.New(), clientID, "google"),
		}, nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients/"+clientID.String()+"/providers", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	parseJSON(t, w, &resp)
	providers := resp["providers"].([]interface{})
	p := providers[0].(map[string]interface{})
	assert.NotContains(t, p, "provider_client_id")
	assert.NotContains(t, p, "provider_client_secret")
}

// ---------------------------------------------------------------------------
// GET /api/v1/clients/:client_id/providers/:id
// ---------------------------------------------------------------------------

func TestGetProvider_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	clientID := uuid.New()
	providerID := uuid.New()
	pRow := buildOAuthProvider(providerID, clientID, "google")

	env.mockQ.On("GetOAuthProvider", mock.Anything, providerID).Return(pRow, nil)

	w := env.doAuthRequest(http.MethodGet,
		"/api/v1/clients/"+clientID.String()+"/providers/"+providerID.String(),
		nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		ID       string `json:"id"`
		ClientID string `json:"client_id"`
		Name     string `json:"name"`
	}
	parseJSON(t, w, &resp)
	assert.Equal(t, providerID.String(), resp.ID)
	assert.Equal(t, clientID.String(), resp.ClientID)
	assert.Equal(t, "google", resp.Name)
	env.mockQ.AssertExpectations(t)
}

func TestGetProvider_NotFound(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	clientID := uuid.New()
	providerID := uuid.New()

	env.mockQ.On("GetOAuthProvider", mock.Anything, providerID).Return(repository.OauthProvider{}, pgx.ErrNoRows)

	w := env.doAuthRequest(http.MethodGet,
		"/api/v1/clients/"+clientID.String()+"/providers/"+providerID.String(),
		nil, token)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetProvider_WrongClient verifies that a provider belonging to a different client
// returns 404 to prevent cross-client information leakage.
func TestGetProvider_WrongClient(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	correctClientID := uuid.New()
	requestedClientID := uuid.New() // different client
	providerID := uuid.New()
	pRow := buildOAuthProvider(providerID, correctClientID, "google")

	env.mockQ.On("GetOAuthProvider", mock.Anything, providerID).Return(pRow, nil)

	w := env.doAuthRequest(http.MethodGet,
		"/api/v1/clients/"+requestedClientID.String()+"/providers/"+providerID.String(),
		nil, token)
	// The handler validates client ownership and returns 404 to avoid information leakage.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// POST /api/v1/clients/:client_id/providers
// ---------------------------------------------------------------------------

func TestCreateProvider_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	clientID := uuid.New()
	providerID := uuid.New()
	pRow := buildOAuthProvider(providerID, clientID, "google")

	env.mockQ.On("CreateOAuthProvider", mock.Anything, mock.AnythingOfType("repository.CreateOAuthProviderParams")).
		Return(pRow, nil)

	w := env.doAuthRequest(http.MethodPost,
		"/api/v1/clients/"+clientID.String()+"/providers",
		map[string]interface{}{
			"name":                   "google",
			"display_name":           "Google",
			"provider_client_id":     "client-123",
			"provider_client_secret": "secret-abc",
			"auth_url":               "https://accounts.google.com/o/oauth2/auth",
			"token_url":              "https://oauth2.googleapis.com/token",
			"user_info_url":          "https://openidconnect.googleapis.com/v1/userinfo",
			"scopes":                 []string{"openid", "email"},
			"is_enabled":             true,
		}, token)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		ClientID string `json:"client_id"`
	}
	parseJSON(t, w, &resp)
	assert.Equal(t, providerID.String(), resp.ID)
	assert.Equal(t, "google", resp.Name)
	env.mockQ.AssertExpectations(t)
}

func TestCreateProvider_MissingRequiredFields(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	clientID := uuid.New()

	w := env.doAuthRequest(http.MethodPost,
		"/api/v1/clients/"+clientID.String()+"/providers",
		map[string]interface{}{
			"name": "google",
			// missing required fields
		}, token)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateProvider_ResponseExcludesCredentials(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	clientID := uuid.New()
	pRow := buildOAuthProvider(uuid.New(), clientID, "google")

	env.mockQ.On("CreateOAuthProvider", mock.Anything, mock.AnythingOfType("repository.CreateOAuthProviderParams")).
		Return(pRow, nil)

	w := env.doAuthRequest(http.MethodPost,
		"/api/v1/clients/"+clientID.String()+"/providers",
		map[string]interface{}{
			"name":                   "google",
			"display_name":           "Google",
			"provider_client_id":     "client-123",
			"provider_client_secret": "secret-abc",
			"auth_url":               "https://accounts.google.com/o/oauth2/auth",
			"token_url":              "https://oauth2.googleapis.com/token",
			"user_info_url":          "https://openidconnect.googleapis.com/v1/userinfo",
			"scopes":                 []string{"openid", "email"},
		}, token)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	parseJSON(t, w, &resp)
	assert.NotContains(t, resp, "provider_client_id")
	assert.NotContains(t, resp, "provider_client_secret")
}

// ---------------------------------------------------------------------------
// PATCH /api/v1/clients/:client_id/providers/:id
// ---------------------------------------------------------------------------

func TestUpdateProvider_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	clientID := uuid.New()
	providerID := uuid.New()
	pRow := buildOAuthProvider(providerID, clientID, "google")

	// UpdateProvider fetches existing first, then updates
	env.mockQ.On("GetOAuthProvider", mock.Anything, providerID).Return(pRow, nil)
	env.mockQ.On("UpdateOAuthProvider", mock.Anything, mock.AnythingOfType("repository.UpdateOAuthProviderParams")).
		Return(pRow, nil)

	w := env.doAuthRequest(http.MethodPatch,
		"/api/v1/clients/"+clientID.String()+"/providers/"+providerID.String(),
		map[string]interface{}{
			"display_name":           "Google Updated",
			"provider_client_id":     "client-123",
			"provider_client_secret": "",
			"auth_url":               "https://accounts.google.com/o/oauth2/auth",
			"token_url":              "https://oauth2.googleapis.com/token",
			"user_info_url":          "https://openidconnect.googleapis.com/v1/userinfo",
			"scopes":                 []string{"openid", "email"},
			"is_enabled":             true,
		}, token)

	assert.Equal(t, http.StatusOK, w.Code)
	env.mockQ.AssertExpectations(t)
}

func TestUpdateProvider_WrongClient(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	correctClientID := uuid.New()
	wrongClientID := uuid.New()
	providerID := uuid.New()
	pRow := buildOAuthProvider(providerID, correctClientID, "google")

	env.mockQ.On("GetOAuthProvider", mock.Anything, providerID).Return(pRow, nil)

	w := env.doAuthRequest(http.MethodPatch,
		"/api/v1/clients/"+wrongClientID.String()+"/providers/"+providerID.String(),
		map[string]interface{}{
			"display_name":       "Google Updated",
			"provider_client_id": "client-123",
			"auth_url":           "https://accounts.google.com/o/oauth2/auth",
			"token_url":          "https://oauth2.googleapis.com/token",
			"user_info_url":      "https://openidconnect.googleapis.com/v1/userinfo",
			"scopes":             []string{"openid"},
			"is_enabled":         true,
		}, token)

	// Provider client mismatch is surfaced as 404 to prevent info leakage
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/clients/:client_id/providers/:id
// ---------------------------------------------------------------------------

func TestDeleteProvider_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	clientID := uuid.New()
	providerID := uuid.New()
	pRow := buildOAuthProvider(providerID, clientID, "google")

	// DeleteProvider calls validateOwnership (GetOAuthProvider) then DeleteOAuthProvider
	env.mockQ.On("GetOAuthProvider", mock.Anything, providerID).Return(pRow, nil)
	env.mockQ.On("DeleteOAuthProvider", mock.Anything, providerID).Return(nil)

	w := env.doAuthRequest(http.MethodDelete,
		"/api/v1/clients/"+clientID.String()+"/providers/"+providerID.String(),
		nil, token)
	assert.Equal(t, http.StatusNoContent, w.Code)
	env.mockQ.AssertExpectations(t)
}

func TestDeleteProvider_NotFound(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	clientID := uuid.New()
	providerID := uuid.New()

	env.mockQ.On("GetOAuthProvider", mock.Anything, providerID).Return(repository.OauthProvider{}, pgx.ErrNoRows)

	w := env.doAuthRequest(http.MethodDelete,
		"/api/v1/clients/"+clientID.String()+"/providers/"+providerID.String(),
		nil, token)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDeleteProvider_CrossClientIsolation verifies that providers cannot be
// deleted using a different client's ID.
func TestDeleteProvider_CrossClientIsolation(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	ownerClientID := uuid.New()
	attackerClientID := uuid.New()
	providerID := uuid.New()
	pRow := buildOAuthProvider(providerID, ownerClientID, "google")

	env.mockQ.On("GetOAuthProvider", mock.Anything, providerID).Return(pRow, nil)

	w := env.doAuthRequest(http.MethodDelete,
		"/api/v1/clients/"+attackerClientID.String()+"/providers/"+providerID.String(),
		nil, token)
	// ErrProviderClientMismatch is surfaced as 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteProvider_InvalidProviderID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	clientID := uuid.New()

	w := env.doAuthRequest(http.MethodDelete,
		"/api/v1/clients/"+clientID.String()+"/providers/not-a-uuid",
		nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
