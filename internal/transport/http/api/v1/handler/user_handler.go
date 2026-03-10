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
// Returns a paginated list of users (admin only).
func (h *ApiV1Handler) ListUsers(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

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
		Limit:    int32(limit),
		Offset:   int32(offset),
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
// Updates a user's active status (admin only).
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
