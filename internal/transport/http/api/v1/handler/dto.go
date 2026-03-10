package handler

import (
	"time"
)

// --- Client management ---

// ClientResponse is the client object returned in API responses.
// The client secret hash is never included.
type ClientResponse struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Description  *string   `json:"description,omitempty"`
	RedirectURIs []string  `json:"redirect_uris"`
	GrantTypes   []string  `json:"grant_types"`
	IsActive     bool      `json:"is_active"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ClientWithSecretResponse extends ClientResponse with the plain client secret.
// Only returned once at creation or secret regeneration.
type ClientWithSecretResponse struct {
	ClientResponse
	ClientSecret string `json:"client_secret"`
}

// ListClientsResponse wraps a paginated list of clients.
type ListClientsResponse struct {
	Clients []ClientResponse `json:"clients"`
	Total   int64            `json:"total"`
}

// CreateClientRequest is the request body for POST /api/v1/clients.
type CreateClientRequest struct {
	Name         string   `json:"name" binding:"required"`
	Description  *string  `json:"description"`
	RedirectURIs []string `json:"redirect_uris" binding:"required,min=1"`
	GrantTypes   []string `json:"grant_types" binding:"required,min=1"`
	IsActive     bool     `json:"is_active"`
}

// UpdateClientRequest is the request body for PATCH /api/v1/clients/:id.
type UpdateClientRequest struct {
	Name         string   `json:"name" binding:"required"`
	Description  *string  `json:"description"`
	RedirectURIs []string `json:"redirect_uris" binding:"required,min=1"`
	GrantTypes   []string `json:"grant_types" binding:"required,min=1"`
}

// --- Token exchange ---

// TokenExchangeRequest is the request body for POST /api/v1/auth/token.
// grant_type must be "authorization_code".
type TokenExchangeRequest struct {
	GrantType    string `json:"grant_type" binding:"required"`
	Code         string `json:"code" binding:"required"`
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	RedirectURI  string `json:"redirect_uri" binding:"required"`
}

// TokenExchangeResponse is the OAuth 2.0 token endpoint response.
type TokenExchangeResponse struct {
	AccessToken string  `json:"access_token"`
	TokenType   string  `json:"token_type"`
	ExpiresIn   int64   `json:"expires_in"`
	Scope       *string `json:"scope,omitempty"`
}

// --- Public provider list ---

// PublicProviderResponse is a client-safe view of an OAuth provider.
// No credentials or internal URLs are exposed.
type PublicProviderResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

// ListPublicProvidersResponse is the response for
// GET /api/v1/clients/:client_id/auth/providers.
type ListPublicProvidersResponse struct {
	Providers []PublicProviderResponse `json:"providers"`
}

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

// --- User management ---

// UserResponse is the user object returned in API responses.
type UserResponse struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	FirstName     *string   `json:"first_name,omitempty"`
	LastName      *string   `json:"last_name,omitempty"`
	IsActive      bool      `json:"is_active"`
	IsAdmin       bool      `json:"is_admin"`
	Locale        string    `json:"locale"`
	LastLoginAt   time.Time `json:"last_login_at"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ListUsersResponse wraps a paginated list of users.
type ListUsersResponse struct {
	Users []UserResponse `json:"users"`
	Total int64          `json:"total"`
}

// UpdateUserStatusRequest is the request body for PATCH /api/v1/users/:id.
type UpdateUserStatusRequest struct {
	IsActive bool `json:"is_active"`
}

// --- Session management ---

// AuthorizationCodeResponse is the authorization code object returned in API responses.
type AuthorizationCodeResponse struct {
	ID          string  `json:"id"`
	ClientID    string  `json:"client_id"`
	UserID      string  `json:"user_id"`
	ProviderID  string  `json:"provider_id"`
	RedirectURI string  `json:"redirect_uri"`
	Scope       *string `json:"scope,omitempty"`
	ExpiresAt   string  `json:"expires_at"`
	UsedAt      *string `json:"used_at,omitempty"`
	IsRevoked   bool    `json:"is_revoked"`
	CreatedAt   string  `json:"created_at"`
}

// ListAuthorizationCodesResponse wraps a paginated list of authorization codes.
type ListAuthorizationCodesResponse struct {
	Codes []AuthorizationCodeResponse `json:"codes"`
	Total int64                       `json:"total"`
}

// AccessTokenResponse is the access token object returned in API responses.
// The token hash is intentionally excluded.
type AccessTokenResponse struct {
	ID        string  `json:"id"`
	ClientID  string  `json:"client_id"`
	UserID    string  `json:"user_id"`
	Scope     *string `json:"scope,omitempty"`
	ExpiresAt string  `json:"expires_at"`
	IsRevoked bool    `json:"is_revoked"`
	CreatedAt string  `json:"created_at"`
}

// ListAccessTokensResponse wraps a paginated list of access tokens.
type ListAccessTokensResponse struct {
	Tokens []AccessTokenResponse `json:"tokens"`
	Total  int64                 `json:"total"`
}
