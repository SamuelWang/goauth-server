package handler_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// adminAuthSetup mocks the middleware calls required for an admin-authenticated request:
// AuthMiddleware (GetAccessToken) and AdminMiddleware (GetUserByID).
// Returns the token string and the admin user ID.
func adminAuthSetup(t *testing.T, env *testEnv) (string, uuid.UUID) {
	t.Helper()
	adminID := uuid.New()
	token := env.generateToken(t, adminID.String(), "admin@example.com")
	tokenRow := activeTokenRow(token, adminID)
	adminRow := buildAdminUser(adminID)

	env.mockQ.On("GetAccessToken", mock.Anything, hashToken(token)).Return(tokenRow, nil)
	env.mockQ.On("GetUserByID", mock.Anything, adminID).Return(adminRow, nil)

	return token, adminID
}

// nonAdminAuthSetup mocks middleware calls for a non-admin user.
func nonAdminAuthSetup(t *testing.T, env *testEnv) string {
	t.Helper()
	userID := uuid.New()
	token := env.generateToken(t, userID.String(), "user@example.com")
	tokenRow := activeTokenRow(token, userID)
	userRow := buildRegularUser(userID)

	env.mockQ.On("GetAccessToken", mock.Anything, hashToken(token)).Return(tokenRow, nil)
	env.mockQ.On("GetUserByID", mock.Anything, userID).Return(userRow, nil)

	return token
}

// ---------------------------------------------------------------------------
// GET /api/v1/clients
// ---------------------------------------------------------------------------

func TestListClients_Success(t *testing.T) {
	env := newTestEnv(t)
	token, adminID := adminAuthSetup(t, env)

	clientID := uuid.New()
	cl := buildActiveClient(clientID, "my-client", adminID)
	isActive := true

	env.mockQ.On("ListClients", mock.Anything, repository.ListClientsParams{
		Column1: isActive,
		Limit:   20,
		Offset:  0,
	}).Return([]repository.Client{cl}, nil)
	env.mockQ.On("CountClients", mock.Anything, isActive).Return(int64(1), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Clients []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"clients"`
		Total int64 `json:"total"`
	}
	parseJSON(t, w, &resp)
	assert.Len(t, resp.Clients, 1)
	assert.Equal(t, clientID.String(), resp.Clients[0].ID)
	assert.Equal(t, int64(1), resp.Total)
	env.mockQ.AssertExpectations(t)
}

func TestListClients_Unauthenticated(t *testing.T) {
	env := newTestEnv(t)

	w := env.doRequest(http.MethodGet, "/api/v1/clients", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListClients_NonAdmin_Forbidden(t *testing.T) {
	env := newTestEnv(t)
	token := nonAdminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients", nil, token)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestListClients_WithIsActiveFilter(t *testing.T) {
	env := newTestEnv(t)
	token, adminID := adminAuthSetup(t, env)

	isActive := false
	env.mockQ.On("ListClients", mock.Anything, repository.ListClientsParams{
		Column1: isActive,
		Limit:   20,
		Offset:  0,
	}).Return([]repository.Client{}, nil)
	env.mockQ.On("CountClients", mock.Anything, isActive).Return(int64(0), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients?is_active=false", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)
	_ = adminID
	env.mockQ.AssertExpectations(t)
}

func TestListClients_InvalidIsActiveFilter(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients?is_active=notbool", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// GET /api/v1/clients/:id
// ---------------------------------------------------------------------------

func TestGetClient_Success(t *testing.T) {
	env := newTestEnv(t)
	token, adminID := adminAuthSetup(t, env)

	clientID := uuid.New()
	cl := buildActiveClient(clientID, "my-client", adminID)

	env.mockQ.On("GetClient", mock.Anything, clientID).Return(cl, nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients/"+clientID.String(), nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	parseJSON(t, w, &resp)
	assert.Equal(t, clientID.String(), resp.ID)
	assert.Equal(t, "my-client", resp.Name)
	env.mockQ.AssertExpectations(t)
}

func TestGetClient_NotFound(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	clientID := uuid.New()
	env.mockQ.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, pgx.ErrNoRows)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients/"+clientID.String(), nil, token)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetClient_InvalidID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients/not-a-uuid", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// POST /api/v1/clients
// ---------------------------------------------------------------------------

func TestCreateClient_Success(t *testing.T) {
	env := newTestEnv(t)
	token, adminID := adminAuthSetup(t, env)

	createdClientID := uuid.New()
	isActive := true
	createdClient := repository.Client{
		ID:               createdClientID,
		Name:             "new-client",
		ClientSecretHash: "hashed-secret",
		RedirectUris:     []string{"https://app.example.com/callback"},
		GrantTypes:       []string{"authorization_code"},
		IsActive:         &isActive,
		CreatedBy:        adminID,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	env.mockQ.On("CreateClient", mock.Anything, mock.AnythingOfType("repository.CreateClientParams")).
		Return(createdClient, nil)

	w := env.doAuthRequest(http.MethodPost, "/api/v1/clients", map[string]interface{}{
		"name":          "new-client",
		"redirect_uris": []string{"https://app.example.com/callback"},
		"grant_types":   []string{"authorization_code"},
		"is_active":     true,
	}, token)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		ClientSecret string `json:"client_secret"`
	}
	parseJSON(t, w, &resp)
	assert.Equal(t, createdClientID.String(), resp.ID)
	assert.Equal(t, "new-client", resp.Name)
	assert.NotEmpty(t, resp.ClientSecret)
	env.mockQ.AssertExpectations(t)
}

func TestCreateClient_MissingRequiredFields(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodPost, "/api/v1/clients", map[string]interface{}{
		// missing name
		"redirect_uris": []string{"https://app.example.com/callback"},
		"grant_types":   []string{"authorization_code"},
	}, token)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateClient_GetDoesNotExposeSecret verifies that the regular GET /clients/:id
// response does not include client_secret (it must only be returned at creation).
func TestCreateClient_GetDoesNotExposeSecret(t *testing.T) {
	env := newTestEnv(t)
	token, adminID := adminAuthSetup(t, env)

	clientID := uuid.New()
	cl := buildActiveClient(clientID, "my-client", adminID)

	env.mockQ.On("GetClient", mock.Anything, clientID).Return(cl, nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/clients/"+clientID.String(), nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	parseJSON(t, w, &resp)
	assert.NotContains(t, resp, "client_secret")
	assert.NotContains(t, resp, "client_secret_hash")
}

// ---------------------------------------------------------------------------
// PATCH /api/v1/clients/:id
// ---------------------------------------------------------------------------

func TestUpdateClient_Success(t *testing.T) {
	env := newTestEnv(t)
	token, adminID := adminAuthSetup(t, env)

	clientID := uuid.New()
	isActive := true
	updatedClient := repository.Client{
		ID:               clientID,
		Name:             "updated-client",
		ClientSecretHash: "hash",
		RedirectUris:     []string{"https://app.example.com/callback"},
		GrantTypes:       []string{"authorization_code"},
		IsActive:         &isActive,
		CreatedBy:        adminID,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	env.mockQ.On("UpdateClient", mock.Anything, mock.AnythingOfType("repository.UpdateClientParams")).
		Return(updatedClient, nil)

	w := env.doAuthRequest(http.MethodPatch, "/api/v1/clients/"+clientID.String(), map[string]interface{}{
		"name":          "updated-client",
		"redirect_uris": []string{"https://app.example.com/callback"},
		"grant_types":   []string{"authorization_code"},
	}, token)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Name string `json:"name"`
	}
	parseJSON(t, w, &resp)
	assert.Equal(t, "updated-client", resp.Name)
	env.mockQ.AssertExpectations(t)
}

func TestUpdateClient_NotFound(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	env.mockQ.On("UpdateClient", mock.Anything, mock.AnythingOfType("repository.UpdateClientParams")).
		Return(repository.Client{}, pgx.ErrNoRows)

	w := env.doAuthRequest(http.MethodPatch, "/api/v1/clients/"+uuid.New().String(), map[string]interface{}{
		"name":          "name",
		"redirect_uris": []string{"https://app.example.com/callback"},
		"grant_types":   []string{"authorization_code"},
	}, token)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// POST /api/v1/clients/:id/regenerate-secret
// ---------------------------------------------------------------------------

func TestRegenerateClientSecret_Success(t *testing.T) {
	env := newTestEnv(t)
	token, adminID := adminAuthSetup(t, env)

	clientID := uuid.New()
	isActive := true
	updatedClient := repository.Client{
		ID:               clientID,
		Name:             "my-client",
		ClientSecretHash: "new-hash",
		RedirectUris:     []string{"https://app.example.com/callback"},
		GrantTypes:       []string{"authorization_code"},
		IsActive:         &isActive,
		CreatedBy:        adminID,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// service: GetClient then RegenerateClientSecret
	env.mockQ.On("GetClient", mock.Anything, clientID).Return(buildActiveClient(clientID, "my-client", adminID), nil)
	env.mockQ.On("RegenerateClientSecret", mock.Anything, mock.AnythingOfType("repository.RegenerateClientSecretParams")).
		Return(updatedClient, nil)

	w := env.doAuthRequest(http.MethodPost, "/api/v1/clients/"+clientID.String()+"/regenerate-secret", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		ClientSecret string `json:"client_secret"`
	}
	parseJSON(t, w, &resp)
	assert.NotEmpty(t, resp.ClientSecret)
	env.mockQ.AssertExpectations(t)
}

func TestRegenerateClientSecret_InvalidID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodPost, "/api/v1/clients/not-a-uuid/regenerate-secret", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/clients/:id
// ---------------------------------------------------------------------------

func TestDeleteClient_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	clientID := uuid.New()
	// service: GetClient then DeleteClient
	env.mockQ.On("GetClient", mock.Anything, clientID).Return(buildActiveClient(clientID, "my-client", uuid.New()), nil)
	env.mockQ.On("DeleteClient", mock.Anything, clientID).Return(nil)

	w := env.doAuthRequest(http.MethodDelete, "/api/v1/clients/"+clientID.String(), nil, token)
	assert.Equal(t, http.StatusNoContent, w.Code)
	env.mockQ.AssertExpectations(t)
}

func TestDeleteClient_NotFound(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	clientID := uuid.New()
	env.mockQ.On("GetClient", mock.Anything, clientID).Return(repository.Client{}, pgx.ErrNoRows)

	w := env.doAuthRequest(http.MethodDelete, "/api/v1/clients/"+clientID.String(), nil, token)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteClient_Unauthenticated(t *testing.T) {
	env := newTestEnv(t)

	w := env.doRequest(http.MethodDelete, "/api/v1/clients/"+uuid.New().String(), nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteClient_NonAdmin(t *testing.T) {
	env := newTestEnv(t)
	token := nonAdminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodDelete, "/api/v1/clients/"+uuid.New().String(), nil, token)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
