package handler

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// toUserResponse converts a service-layer User to the API response DTO.
func toUserResponse(u user.User) UserResponse {
	return UserResponse{
		ID:            u.ID.String(),
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		IsActive:      u.IsActive,
		IsAdmin:       u.IsAdmin,
		Locale:        u.Locale,
		LastLoginAt:   u.LastLoginAt.UTC(),
		CreatedAt:     u.CreatedAt.UTC(),
		UpdatedAt:     u.UpdatedAt.UTC(),
	}
}

// handleUserError maps user service errors to appropriate HTTP responses.
func handleUserError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, user.ErrUserNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
	default:
		log.Printf("user handler: unexpected error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}

// ListUsers handles GET /api/v1/users
//
// @Summary     List users
// @Description Returns a paginated list of users. Admin only.
// @Tags        Users
// @Produce     json
// @Param       limit     query     int   false  "Items per page (1-100)"  default(20)
// @Param       offset    query     int   false  "Zero-based offset"       default(0)
// @Param       is_active query     bool  false  "Filter by active status"
// @Param       is_admin  query     bool  false  "Filter by admin status"
// @Success     200  {object}  handler.ListUsersResponse
// @Failure     400  {object}  handler.ErrorResponse
// @Failure     401  {object}  handler.ErrorResponse
// @Failure     403  {object}  handler.ErrorResponse
// @Failure     500  {object}  handler.ErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/users [get]
func (h *ApiV1Handler) ListUsers(c *gin.Context) {
	limit, offset, ok := parsePaginationParams(c)
	if !ok {
		return
	}

	var isActive *bool
	if v := c.Query("is_active"); v != "" {
		val, err := strconv.ParseBool(v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "is_active must be true or false"})
			return
		}
		isActive = &val
	}

	var isAdmin *bool
	if v := c.Query("is_admin"); v != "" {
		val, err := strconv.ParseBool(v)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "is_admin must be true or false"})
			return
		}
		isAdmin = &val
	}

	result, err := h.userService.ListUsers(c.Request.Context(), user.ListUsersParams{
		IsActive: isActive,
		IsAdmin:  isAdmin,
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		log.Printf("ListUsers: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	resp := make([]UserResponse, 0, len(result.Users))
	for _, u := range result.Users {
		resp = append(resp, toUserResponse(u))
	}

	c.JSON(http.StatusOK, ListUsersResponse{Users: resp, Total: result.Total})
}

// UpdateUserStatus handles PATCH /api/v1/users/:id
//
// @Summary     Update user status
// @Description Updates a user's active status. Admin only.
// @Tags        Users
// @Accept      json
// @Produce     json
// @Param       id    path      string                            true  "User UUID"
// @Param       body  body      handler.UpdateUserStatusRequest   true  "Update user status request"
// @Success     200  {object}  handler.UserResponse
// @Failure     400  {object}  handler.ErrorResponse
// @Failure     401  {object}  handler.ErrorResponse
// @Failure     403  {object}  handler.ErrorResponse
// @Failure     404  {object}  handler.ErrorResponse
// @Failure     500  {object}  handler.ErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/users/{id} [patch]
func (h *ApiV1Handler) UpdateUserStatus(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	var req UpdateUserStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	u, err := h.userService.UpdateUserStatus(c.Request.Context(), id, req.IsActive)
	if err != nil {
		handleUserError(c, err)
		return
	}

	c.JSON(http.StatusOK, toUserResponse(*u))
}
