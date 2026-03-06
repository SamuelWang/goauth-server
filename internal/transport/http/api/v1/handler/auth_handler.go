package handler

import (
	"errors"
	"log"
	"net/http"

	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ListEnabledProviders returns the enabled OAuth providers for the given
// client. This is a public endpoint — no secret data is included.
//
// GET /api/v1/clients/:client_id/auth/providers
func (h *ApiV1Handler) ListEnabledProviders(c *gin.Context) {
	clientID, ok := parseClientID(c)
	if !ok {
		return
	}

	providers, err := h.providerService.ListEnabledProvidersByClient(c.Request.Context(), clientID)
	if err != nil {
		log.Printf("ListEnabledProviders: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	resp := make([]PublicProviderResponse, 0, len(providers))
	for _, p := range providers {
		resp = append(resp, PublicProviderResponse{
			Name:        p.Name,
			DisplayName: p.DisplayName,
		})
	}
	c.JSON(http.StatusOK, ListPublicProvidersResponse{Providers: resp})
}

// TokenExchange exchanges an authorization code for an access token.
// Returns an OAuth 2.0-compliant token response.
//
// POST /api/v1/auth/token
func (h *ApiV1Handler) TokenExchange(c *gin.Context) {
	var req TokenExchangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	if req.GrantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "only authorization_code grant type is supported",
		})
		return
	}

	clientID, err := uuid.Parse(req.ClientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "client_id is not a valid UUID",
		})
		return
	}

	tokenResp, err := h.authService.ExchangeCodeForToken(
		c.Request.Context(),
		req.Code,
		clientID,
		req.ClientSecret,
		req.RedirectURI,
	)
	if err != nil {
		handleTokenExchangeError(c, err)
		return
	}

	c.JSON(http.StatusOK, TokenExchangeResponse{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   tokenResp.ExpiresIn,
		Scope:       tokenResp.Scope,
	})
}

// handleTokenExchangeError maps auth service errors to OAuth 2.0 error responses.
func handleTokenExchangeError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, auth.ErrClientNotFound),
		errors.Is(err, auth.ErrClientInactive),
		errors.Is(err, auth.ErrInvalidClientSecret):
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_client",
			"error_description": "client authentication failed",
		})
	case errors.Is(err, auth.ErrCodeNotFound),
		errors.Is(err, auth.ErrCodeExpired),
		errors.Is(err, auth.ErrCodeUsed),
		errors.Is(err, auth.ErrCodeRevoked),
		errors.Is(err, auth.ErrCodeClientMismatch),
		errors.Is(err, auth.ErrCodeRedirectMismatch):
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
	default:
		log.Printf("TokenExchange: unexpected error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
	}
}

// Logout revokes the caller's access token and clears the session cookie.
// Requires a valid bearer token (enforced by AuthMiddleware).
//
// POST /api/v1/auth/logout
func (h *ApiV1Handler) Logout(c *gin.Context) {
	// Revoke the token so it cannot be replayed after the cookie is cleared.
	if raw, exists := c.Get("raw_token"); exists {
		if tokenStr, ok := raw.(string); ok {
			if err := h.authService.RevokeRawToken(c.Request.Context(), tokenStr); err != nil {
				if !errors.Is(err, auth.ErrTokenNotFound) {
					log.Printf("Logout: failed to revoke token: %v", err)
				}
			}
		}
	}

	c.SetCookie("access_token", "", -1, "/", "", getCookieSecure(c), true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
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
