package handler

import (
	"errors"
	"log"
	"net/http"

	"github.com/SamuelWang/goauth-server/internal/metrics"
	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ListEnabledProviders returns the enabled OAuth providers for the given
// client. This is a public endpoint — no secret data is included.
//
// @Summary     List enabled providers for a client
// @Description Returns provider names and display names enabled for the specified client. No credentials included.
// @Tags        Auth
// @Produce     json
// @Param       client_id  path      string  true  "Client UUID"
// @Success     200  {object}  handler.ListPublicProvidersResponse
// @Failure     400  {object}  handler.ErrorResponse
// @Failure     500  {object}  handler.ErrorResponse
// @Router      /api/v1/clients/{client_id}/auth/providers [get]
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
// @Summary     Exchange authorization code for access token
// @Description OAuth 2.0 token endpoint. Only the authorization_code grant type is supported.
// @Tags        Auth
// @Accept      json
// @Produce     json
// @Param       body  body      handler.TokenExchangeRequest  true  "Token exchange request"
// @Success     200  {object}  handler.TokenExchangeResponse
// @Failure     400  {object}  handler.ErrorResponse
// @Failure     401  {object}  handler.ErrorResponse
// @Failure     500  {object}  handler.ErrorResponse
// @Router      /api/v1/auth/token [post]
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
		util.LogTokenExchangeFailure(c.ClientIP(), c.GetString("request_id"), req.ClientID, err.Error())
		handleTokenExchangeError(c, err)
		return
	}

	c.JSON(http.StatusOK, TokenExchangeResponse{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        tokenResp.Scope,
		RefreshToken: tokenResp.RefreshToken,
	})
	metrics.TokensIssuedTotal.Inc()
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
			"error_description": "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI, or was issued to another client.",
		})
	default:
		log.Printf("TokenExchange: unexpected error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
	}
}

// Logout revokes the caller's access token and clears the session cookie.
// Requires a valid bearer token (enforced by AuthMiddleware).
//
// @Summary     Logout current user
// @Description Revokes the bearer access token and clears the session cookie.
// @Tags        Auth
// @Produce     json
// @Success     200  {object}  map[string]string
// @Failure     401  {object}  handler.ErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/auth/logout [post]
func (h *ApiV1Handler) Logout(c *gin.Context) {
	// Revoke the token so it cannot be replayed after the cookie is cleared.
	if raw, exists := c.Get("raw_token"); exists {
		if tokenStr, ok := raw.(string); ok {
			if err := h.authService.RevokeRawToken(c.Request.Context(), tokenStr); err != nil {
				if !errors.Is(err, auth.ErrTokenNotFound) {
					log.Printf("Logout: failed to revoke token: %v", err)
				}
			} else {
				userID := c.GetString("user_id")
				util.LogTokenRevoked(c.ClientIP(), c.GetString("request_id"), userID)
				metrics.TokenRevocationsTotal.Inc()
			}
		}
	}

	c.SetCookie("access_token", "", -1, "/", "", getCookieSecure(c), true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// GetCurrentUser returns the current authenticated user's information.
//
// @Summary     Get current user
// @Description Returns profile information for the currently authenticated user.
// @Tags        Auth
// @Produce     json
// @Success     200  {object}  handler.GetCurrentUserResponse
// @Failure     401  {object}  handler.ErrorResponse
// @Failure     500  {object}  handler.ErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/auth/me [get]
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
