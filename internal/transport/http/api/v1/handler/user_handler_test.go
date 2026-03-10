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

// buildUserRow creates a repository.User suitable for mock returns.
func buildUserRow(id uuid.UUID, email string, isAdmin bool) repository.User {
	admin := isAdmin
	isActive := true
	return repository.User{
		ID:            id,
		Email:         email,
		EmailVerified: true,
		IsActive:      isActive,
		IsAdmin:       &admin,
		Locale:        "en-US",
		LastLoginAt:   time.Now(),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

// ---------------------------------------------------------------------------
// GET /api/v1/users
// ---------------------------------------------------------------------------

func TestListUsers_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	userID1 := uuid.New()
	userID2 := uuid.New()

	env.mockQ.On("ListUsers", mock.Anything, repository.ListUsersParams{
		Column1: true,
		Column2: false,
		Limit:   20,
		Offset:  0,
	}).Return([]repository.User{
		buildUserRow(userID1, "user1@example.com", false),
		buildUserRow(userID2, "user2@example.com", false),
	}, nil)
	env.mockQ.On("CountUsers", mock.Anything, repository.CountUsersParams{
		Column1: true,
		Column2: false,
	}).Return(int64(2), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/users", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Users []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"users"`
		Total int64 `json:"total"`
	}
	parseJSON(t, w, &resp)
	assert.Len(t, resp.Users, 2)
	assert.Equal(t, int64(2), resp.Total)
	env.mockQ.AssertExpectations(t)
}

func TestListUsers_Unauthenticated(t *testing.T) {
	env := newTestEnv(t)

	w := env.doRequest(http.MethodGet, "/api/v1/users", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListUsers_NonAdmin(t *testing.T) {
	env := newTestEnv(t)
	token := nonAdminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/users", nil, token)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestListUsers_FilterIsActive(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	env.mockQ.On("ListUsers", mock.Anything, repository.ListUsersParams{
		Column1: false,
		Column2: false,
		Limit:   20,
		Offset:  0,
	}).Return([]repository.User{}, nil)
	env.mockQ.On("CountUsers", mock.Anything, repository.CountUsersParams{
		Column1: false,
		Column2: false,
	}).Return(int64(0), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/users?is_active=false", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)
	env.mockQ.AssertExpectations(t)
}

func TestListUsers_FilterIsAdmin(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	adminUserID := uuid.New()

	env.mockQ.On("ListUsers", mock.Anything, repository.ListUsersParams{
		Column1: true,
		Column2: true,
		Limit:   20,
		Offset:  0,
	}).Return([]repository.User{buildUserRow(adminUserID, "admin@example.com", true)}, nil)
	env.mockQ.On("CountUsers", mock.Anything, repository.CountUsersParams{
		Column1: true,
		Column2: true,
	}).Return(int64(1), nil)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/users?is_admin=true", nil, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Users []struct {
			IsAdmin bool `json:"is_admin"`
		} `json:"users"`
	}
	parseJSON(t, w, &resp)
	assert.True(t, resp.Users[0].IsAdmin)
	env.mockQ.AssertExpectations(t)
}

func TestListUsers_InvalidIsActiveFilter(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodGet, "/api/v1/users?is_active=notabool", nil, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// PATCH /api/v1/users/:id
// ---------------------------------------------------------------------------

func TestUpdateUserStatus_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	userID := uuid.New()

	isActive := false
	updatedUser := buildUserRow(userID, "user@example.com", false)
	updatedUser.IsActive = isActive

	env.mockQ.On("UpdateUserActiveStatus", mock.Anything, repository.UpdateUserActiveStatusParams{
		ID:       userID,
		IsActive: false,
	}).Return(updatedUser, nil)

	w := env.doAuthRequest(http.MethodPatch, "/api/v1/users/"+userID.String(),
		map[string]interface{}{"is_active": false}, token)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		ID       string `json:"id"`
		IsActive bool   `json:"is_active"`
	}
	parseJSON(t, w, &resp)
	assert.Equal(t, userID.String(), resp.ID)
	assert.False(t, resp.IsActive)
	env.mockQ.AssertExpectations(t)
}

func TestUpdateUserStatus_Enable(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	userID := uuid.New()

	updatedUser := buildUserRow(userID, "user@example.com", false)

	env.mockQ.On("UpdateUserActiveStatus", mock.Anything, repository.UpdateUserActiveStatusParams{
		ID:       userID,
		IsActive: true,
	}).Return(updatedUser, nil)

	w := env.doAuthRequest(http.MethodPatch, "/api/v1/users/"+userID.String(),
		map[string]interface{}{"is_active": true}, token)
	assert.Equal(t, http.StatusOK, w.Code)
	env.mockQ.AssertExpectations(t)
}

func TestUpdateUserStatus_UserNotFound(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)
	userID := uuid.New()

	env.mockQ.On("UpdateUserActiveStatus", mock.Anything, repository.UpdateUserActiveStatusParams{
		ID:       userID,
		IsActive: false,
	}).Return(repository.User{}, pgx.ErrNoRows)

	w := env.doAuthRequest(http.MethodPatch, "/api/v1/users/"+userID.String(),
		map[string]interface{}{"is_active": false}, token)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateUserStatus_InvalidID(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	w := env.doAuthRequest(http.MethodPatch, "/api/v1/users/not-a-uuid",
		map[string]interface{}{"is_active": false}, token)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateUserStatus_Unauthenticated(t *testing.T) {
	env := newTestEnv(t)
	userID := uuid.New()

	w := env.doRequest(http.MethodPatch, "/api/v1/users/"+userID.String(),
		map[string]interface{}{"is_active": false})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUpdateUserStatus_NonAdmin(t *testing.T) {
	env := newTestEnv(t)
	token := nonAdminAuthSetup(t, env)
	userID := uuid.New()

	w := env.doAuthRequest(http.MethodPatch, "/api/v1/users/"+userID.String(),
		map[string]interface{}{"is_active": false}, token)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
