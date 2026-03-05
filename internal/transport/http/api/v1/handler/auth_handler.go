package handler

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Logout invalidates the user's session
func (h *ApiV1Handler) Logout(c *gin.Context) {
	// Clear the auth token cookie
	c.SetCookie(
		"access_token",
		"",
		-1, // Expire immediately
		"/",
		"",
		getCookieSecure(c), // Secure
		true,               // HttpOnly
	)

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// GetCurrentUser returns the current authenticated user's information
func (h *ApiV1Handler) GetCurrentUser(c *gin.Context) {
	// Get user from context (set by auth middleware)
	userID, exists := getUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		log.Printf("Invalid user ID format: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	user, err := h.userService.GetUser(c.Request.Context(), userUUID)
	if err != nil {
		log.Printf("Failed to get user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	resp := GetCurrentUserResponse{
		User: UserDTO{
			ID:            user.ID.String(),
			Email:         user.Email,
			EmailVerified: user.EmailVerified,
			FirstName:     user.FirstName,
			LastName:      user.LastName,
			Locale:        user.Locale,
			CreatedAt:     user.CreatedAt.UTC(),
		},
	}

	c.JSON(http.StatusOK, resp)
}
