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

// ProviderResponse is the provider object returned in API responses.
// Provider secrets (provider_client_id, provider_client_secret) are intentionally excluded.
type ProviderResponse struct {
	ID          string    `json:"id"`
	ClientID    string    `json:"client_id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name"`
	AuthURL     string    `json:"auth_url"`
	TokenURL    string    `json:"token_url"`
	UserInfoURL string    `json:"user_info_url"`
	Scopes      []string  `json:"scopes"`
	IsEnabled   bool      `json:"is_enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ListProvidersResponse wraps a list of providers for API responses.
type ListProvidersResponse struct {
	Providers []ProviderResponse `json:"providers"`
}

// CreateProviderRequest is the request body for creating a new OAuth provider.
type CreateProviderRequest struct {
	Name                 string   `json:"name" binding:"required"`
	DisplayName          string   `json:"display_name" binding:"required"`
	ProviderClientID     string   `json:"provider_client_id" binding:"required"`
	ProviderClientSecret string   `json:"provider_client_secret" binding:"required"`
	AuthURL              string   `json:"auth_url" binding:"required"`
	TokenURL             string   `json:"token_url" binding:"required"`
	UserInfoURL          string   `json:"user_info_url" binding:"required"`
	Scopes               []string `json:"scopes" binding:"required,min=1"`
	IsEnabled            bool     `json:"is_enabled"`
}

// UpdateProviderRequest is the request body for updating an existing OAuth provider.
type UpdateProviderRequest struct {
	DisplayName          string   `json:"display_name" binding:"required"`
	ProviderClientID     string   `json:"provider_client_id" binding:"required"`
	ProviderClientSecret string   `json:"provider_client_secret"` // optional: empty retains existing secret
	AuthURL              string   `json:"auth_url" binding:"required"`
	TokenURL             string   `json:"token_url" binding:"required"`
	UserInfoURL          string   `json:"user_info_url" binding:"required"`
	Scopes               []string `json:"scopes" binding:"required,min=1"`
	IsEnabled            bool     `json:"is_enabled"`
}
