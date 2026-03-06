package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestUserService() (*Service, *mocks.MockQuerier) {
	m := &mocks.MockQuerier{}
	return New(m), m
}

func sampleRepoUser(isAdmin *bool) repository.User {
	b := true
	return repository.User{
		ID:            uuid.New(),
		Email:         "test@example.com",
		EmailVerified: true,
		IsActive:      b,
		Locale:        "en",
		LastLoginAt:   time.Now(),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		IsAdmin:       isAdmin,
	}
}

// ListUsers tests

func TestListUsers_NilFiltersDefaultToActiveNonAdmin(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	isAdminFalse := false
	rows := []repository.User{sampleRepoUser(&isAdminFalse)}

	repoParams := repository.ListUsersParams{Column1: true, Column2: false, Limit: 20, Offset: 0}
	countParams := repository.CountUsersParams{Column1: true, Column2: false}

	m.On("ListUsers", ctx, repoParams).Return(rows, nil)
	m.On("CountUsers", ctx, countParams).Return(int64(1), nil)

	result, err := svc.ListUsers(ctx, ListUsersParams{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	assert.Len(t, result.Users, 1)
	assert.False(t, result.Users[0].IsAdmin)
	m.AssertExpectations(t)
}

func TestListUsers_ExplicitFilters(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	isActive := false
	isAdmin := true
	rows := []repository.User{sampleRepoUser(&isAdmin)}

	repoParams := repository.ListUsersParams{Column1: false, Column2: true, Limit: 5, Offset: 10}
	countParams := repository.CountUsersParams{Column1: false, Column2: true}

	m.On("ListUsers", ctx, repoParams).Return(rows, nil)
	m.On("CountUsers", ctx, countParams).Return(int64(1), nil)

	result, err := svc.ListUsers(ctx, ListUsersParams{IsActive: &isActive, IsAdmin: &isAdmin, Limit: 5, Offset: 10})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	m.AssertExpectations(t)
}

func TestListUsers_DefaultLimit(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	repoParams := repository.ListUsersParams{Column1: true, Column2: false, Limit: 20}
	countParams := repository.CountUsersParams{Column1: true, Column2: false}

	m.On("ListUsers", ctx, repoParams).Return([]repository.User{}, nil)
	m.On("CountUsers", ctx, countParams).Return(int64(0), nil)

	result, err := svc.ListUsers(ctx, ListUsersParams{Limit: 0})
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.Total)
	m.AssertExpectations(t)
}

func TestListUsers_RepoErrorOnList(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	repoParams := repository.ListUsersParams{Column1: true, Column2: false, Limit: 20}
	m.On("ListUsers", ctx, repoParams).Return(nil, errors.New("db error"))

	_, err := svc.ListUsers(ctx, ListUsersParams{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listing users")
	m.AssertExpectations(t)
}

func TestListUsers_RepoErrorOnCount(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	repoParams := repository.ListUsersParams{Column1: true, Column2: false, Limit: 20}
	countParams := repository.CountUsersParams{Column1: true, Column2: false}

	m.On("ListUsers", ctx, repoParams).Return([]repository.User{}, nil)
	m.On("CountUsers", ctx, countParams).Return(int64(0), errors.New("db error"))

	_, err := svc.ListUsers(ctx, ListUsersParams{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "counting users")
	m.AssertExpectations(t)
}

// GetUser tests

func TestGetUser_Found(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	isAdmin := true
	row := sampleRepoUser(&isAdmin)
	m.On("GetUserByID", ctx, row.ID).Return(row, nil)

	u, err := svc.GetUser(ctx, row.ID)
	require.NoError(t, err)
	assert.Equal(t, row.ID, u.ID)
	assert.Equal(t, row.Email, u.Email)
	assert.True(t, u.IsAdmin)
	m.AssertExpectations(t)
}

func TestGetUser_NotFound(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	id := uuid.New()
	m.On("GetUserByID", ctx, id).Return(repository.User{}, pgx.ErrNoRows)

	_, err := svc.GetUser(ctx, id)
	require.ErrorIs(t, err, ErrUserNotFound)
	m.AssertExpectations(t)
}

func TestGetUser_RepoError(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	id := uuid.New()
	m.On("GetUserByID", ctx, id).Return(repository.User{}, errors.New("db error"))

	_, err := svc.GetUser(ctx, id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting user")
	m.AssertExpectations(t)
}

// UpdateUserStatus tests

func TestUpdateUserStatus_Enable(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	id := uuid.New()
	updated := sampleRepoUser(nil)
	updated.ID = id
	updated.IsActive = true

	repoParams := repository.UpdateUserActiveStatusParams{ID: id, IsActive: true}
	m.On("UpdateUserActiveStatus", ctx, repoParams).Return(updated, nil)

	u, err := svc.UpdateUserStatus(ctx, id, true)
	require.NoError(t, err)
	assert.True(t, u.IsActive)
	m.AssertExpectations(t)
}

func TestUpdateUserStatus_Disable(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	id := uuid.New()
	updated := sampleRepoUser(nil)
	updated.ID = id
	updated.IsActive = false

	repoParams := repository.UpdateUserActiveStatusParams{ID: id, IsActive: false}
	m.On("UpdateUserActiveStatus", ctx, repoParams).Return(updated, nil)

	u, err := svc.UpdateUserStatus(ctx, id, false)
	require.NoError(t, err)
	assert.False(t, u.IsActive)
	m.AssertExpectations(t)
}

func TestUpdateUserStatus_NotFound(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	id := uuid.New()
	repoParams := repository.UpdateUserActiveStatusParams{ID: id, IsActive: true}
	m.On("UpdateUserActiveStatus", ctx, repoParams).Return(repository.User{}, pgx.ErrNoRows)

	_, err := svc.UpdateUserStatus(ctx, id, true)
	require.ErrorIs(t, err, ErrUserNotFound)
	m.AssertExpectations(t)
}

// IsAdmin tests

func TestIsAdmin_True(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	isAdmin := true
	row := sampleRepoUser(&isAdmin)
	m.On("GetUserByID", ctx, row.ID).Return(row, nil)

	result, err := svc.IsAdmin(ctx, row.ID)
	require.NoError(t, err)
	assert.True(t, result)
	m.AssertExpectations(t)
}

func TestIsAdmin_False(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	isAdmin := false
	row := sampleRepoUser(&isAdmin)
	m.On("GetUserByID", ctx, row.ID).Return(row, nil)

	result, err := svc.IsAdmin(ctx, row.ID)
	require.NoError(t, err)
	assert.False(t, result)
	m.AssertExpectations(t)
}

func TestIsAdmin_NilIsAdminField(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	row := sampleRepoUser(nil) // IsAdmin == nil
	m.On("GetUserByID", ctx, row.ID).Return(row, nil)

	result, err := svc.IsAdmin(ctx, row.ID)
	require.NoError(t, err)
	assert.False(t, result)
	m.AssertExpectations(t)
}

func TestIsAdmin_UserNotFound(t *testing.T) {
	svc, m := newTestUserService()
	ctx := context.Background()

	id := uuid.New()
	m.On("GetUserByID", ctx, id).Return(repository.User{}, pgx.ErrNoRows)

	_, err := svc.IsAdmin(ctx, id)
	require.ErrorIs(t, err, ErrUserNotFound)
	m.AssertExpectations(t)
}
