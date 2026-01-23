package handler

import "time"

// UserDTO represents the user object returned by API responses.
type UserDTO struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	FirstName     *string   `json:"first_name"`
	LastName      *string   `json:"last_name"`
	Locale        string    `json:"locale"`
	CreatedAt     time.Time `json:"created_at"`
}

// GetCurrentUserResponse is the response envelope for the GetCurrentUser endpoint.
type GetCurrentUserResponse struct {
	User UserDTO `json:"user"`
}
