package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// buildUserRecord returns a minimal repository.User row with the given admin flag.
func buildUserRecord(id uuid.UUID, isAdmin bool) repository.User {
	active := true
	return repository.User{
		ID:            id,
		Email:         "user@example.com",
		EmailVerified: true,
		IsActive:      active,
		IsAdmin:       &isAdmin,
		Locale:        "en-US",
		LastLoginAt:   time.Now(),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

// ---------------------------------------------------------------------------
// AdminMiddleware tests
// ---------------------------------------------------------------------------

// TestAdminMiddleware_NoUserIDInContext verifies that requests which bypass
// AuthMiddleware (so "user_id" is absent from the Gin context) receive 401.
func TestAdminMiddleware_NoUserIDInContext(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	userSvc := user.New(mockQ)
	router := setupTestRouter()

	var handlerCalled bool
	router.GET("/admin", AdminMiddleware(userSvc), func(c *gin.Context) {
		handlerCalled = true
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, handlerCalled)
	mockQ.AssertNotCalled(t, "GetUserByID")
}

// TestAdminMiddleware_InvalidUserID verifies that a non-UUID user_id in context
// (e.g. due to a bug in AuthMiddleware) results in a 401.
func TestAdminMiddleware_InvalidUserID(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	userSvc := user.New(mockQ)
	router := setupTestRouter()

	var handlerCalled bool
	router.GET("/admin",
		func(c *gin.Context) { c.Set("user_id", "not-a-uuid"); c.Next() },
		AdminMiddleware(userSvc),
		func(c *gin.Context) {
			handlerCalled = true
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, handlerCalled)
	mockQ.AssertNotCalled(t, "GetUserByID")
}

// TestAdminMiddleware_NotAdmin verifies that non-admin users receive 403.
func TestAdminMiddleware_NotAdmin(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	userSvc := user.New(mockQ)
	router := setupTestRouter()

	userID := uuid.New()
	mockQ.On("GetUserByID", mock.Anything, userID).
		Return(buildUserRecord(userID, false), nil)

	var handlerCalled bool
	router.GET("/admin",
		func(c *gin.Context) { c.Set("user_id", userID.String()); c.Next() },
		AdminMiddleware(userSvc),
		func(c *gin.Context) {
			handlerCalled = true
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, handlerCalled)
	mockQ.AssertExpectations(t)
}

// TestAdminMiddleware_IsAdmin verifies that admin users can pass through.
func TestAdminMiddleware_IsAdmin(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	userSvc := user.New(mockQ)
	router := setupTestRouter()

	userID := uuid.New()
	mockQ.On("GetUserByID", mock.Anything, userID).
		Return(buildUserRecord(userID, true), nil)

	var handlerCalled bool
	router.GET("/admin",
		func(c *gin.Context) { c.Set("user_id", userID.String()); c.Next() },
		AdminMiddleware(userSvc),
		func(c *gin.Context) {
			handlerCalled = true
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, handlerCalled)
	mockQ.AssertExpectations(t)
}

// TestAdminMiddleware_UserNotFound verifies that a 500 is returned when the
// user record cannot be found (IsAdmin returns ErrUserNotFound which the
// middleware treats as an internal error).
func TestAdminMiddleware_UserNotFound(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	userSvc := user.New(mockQ)
	router := setupTestRouter()

	userID := uuid.New()
	mockQ.On("GetUserByID", mock.Anything, userID).
		Return(repository.User{}, pgx.ErrNoRows)

	var handlerCalled bool
	router.GET("/admin",
		func(c *gin.Context) { c.Set("user_id", userID.String()); c.Next() },
		AdminMiddleware(userSvc),
		func(c *gin.Context) {
			handlerCalled = true
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.False(t, handlerCalled)
	mockQ.AssertExpectations(t)
}

// TestAdminMiddleware_DBError verifies that a database error when checking admin
// status results in a 500 Internal Server Error.
func TestAdminMiddleware_DBError(t *testing.T) {
	mockQ := &mocks.MockQuerier{}
	userSvc := user.New(mockQ)
	router := setupTestRouter()

	userID := uuid.New()
	mockQ.On("GetUserByID", mock.Anything, userID).
		Return(repository.User{}, errors.New("connection refused"))

	var handlerCalled bool
	router.GET("/admin",
		func(c *gin.Context) { c.Set("user_id", userID.String()); c.Next() },
		AdminMiddleware(userSvc),
		func(c *gin.Context) {
			handlerCalled = true
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.False(t, handlerCalled)
	mockQ.AssertExpectations(t)
}
