package handler_test

import (
	"net/http"
	"testing"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// DELETE /api/v1/admin/users/:id/lockout — handler integration tests (9.12)
// ---------------------------------------------------------------------------

// TestUnlockUser_Success verifies that an admin JWT + valid locked-user ID
// returns HTTP 204 and clears the locked_until field via UnlockUserAccount.
func TestUnlockUser_Success(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	targetUserID := uuid.New()
	unlockedUser := buildUserRow(targetUserID, "locked@example.com", false)

	env.mockQ.On("UnlockUserAccount", mock.Anything, targetUserID).Return(unlockedUser, nil)

	w := env.doAuthRequest(http.MethodDelete, "/api/v1/users/"+targetUserID.String()+"/lockout", nil, token)

	require.Equal(t, http.StatusNoContent, w.Code)
	env.mockQ.AssertExpectations(t)
}

// TestUnlockUser_UnknownUser verifies that an admin JWT with a user ID that
// does not exist in the database returns HTTP 404.
func TestUnlockUser_UnknownUser(t *testing.T) {
	env := newTestEnv(t)
	token, _ := adminAuthSetup(t, env)

	unknownUserID := uuid.New()

	env.mockQ.On("UnlockUserAccount", mock.Anything, unknownUserID).Return(repository.User{}, pgx.ErrNoRows)

	w := env.doAuthRequest(http.MethodDelete, "/api/v1/users/"+unknownUserID.String()+"/lockout", nil, token)

	require.Equal(t, http.StatusNotFound, w.Code)

	var resp map[string]string
	parseJSON(t, w, &resp)
	assert.Equal(t, "user not found", resp["error"])

	env.mockQ.AssertExpectations(t)
}

// TestUnlockUser_NonAdmin verifies that a non-admin JWT returns HTTP 403.
func TestUnlockUser_NonAdmin(t *testing.T) {
	env := newTestEnv(t)
	// nonAdminAuthSetup sets up a non-admin user token with GetUserByID returning
	// a user with IsAdmin=false, causing AdminMiddleware to reject with 403.
	token := nonAdminAuthSetup(t, env)

	targetUserID := uuid.New()

	w := env.doAuthRequest(http.MethodDelete, "/api/v1/users/"+targetUserID.String()+"/lockout", nil, token)

	require.Equal(t, http.StatusForbidden, w.Code)
	env.mockQ.AssertExpectations(t)
}
