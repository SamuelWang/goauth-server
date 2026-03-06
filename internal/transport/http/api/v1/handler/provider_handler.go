package handler

import (
	"errors"
	"log"
	"net/http"

	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// parseClientID extracts and validates the :client_id path parameter.
// Returns false and writes an error response if the parameter is missing or not a valid UUID.
func parseClientID(c *gin.Context) (uuid.UUID, bool) {
	clientID, err := uuid.Parse(c.Param("client_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client_id"})
		return uuid.UUID{}, false
	}
	return clientID, true
}

// parseProviderID extracts and validates the :id path parameter.
func parseProviderID(c *gin.Context) (uuid.UUID, bool) {
	providerID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider id"})
		return uuid.UUID{}, false
	}
	return providerID, true
}

// toProviderResponse converts a service-layer OAuthProvider to the API response DTO.
func toProviderResponse(p provider.OAuthProvider) ProviderResponse {
	return ProviderResponse{
		ID:          p.ID.String(),
		ClientID:    p.ClientID.String(),
		Name:        p.Name,
		DisplayName: p.DisplayName,
		AuthURL:     p.AuthURL,
		TokenURL:    p.TokenURL,
		UserInfoURL: p.UserInfoURL,
		Scopes:      p.Scopes,
		IsEnabled:   p.IsEnabled,
		CreatedAt:   p.CreatedAt.UTC(),
		UpdatedAt:   p.UpdatedAt.UTC(),
	}
}

// handleProviderError maps provider service errors to appropriate HTTP responses.
func handleProviderError(c *gin.Context, err error) {
	var valErr *provider.ValidationError
	switch {
	case errors.As(err, &valErr):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": valErr.Error()})
	case errors.Is(err, provider.ErrProviderNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
	case errors.Is(err, provider.ErrProviderClientMismatch):
		// Treat as not found to avoid revealing cross-client information.
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
	case errors.Is(err, provider.ErrDuplicateProviderName):
		c.JSON(http.StatusConflict, gin.H{"error": "a provider with this name already exists for this client"})
	default:
		log.Printf("provider handler: unexpected error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}

// ListProviders handles GET /api/v1/clients/:client_id/providers
// Returns all OAuth providers configured for the specified client (admin only).
func (h *ApiV1Handler) ListProviders(c *gin.Context) {
	clientID, ok := parseClientID(c)
	if !ok {
		return
	}

	providers, err := h.providerService.ListProvidersByClient(c.Request.Context(), clientID)
	if err != nil {
		log.Printf("ListProviders: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	resp := make([]ProviderResponse, 0, len(providers))
	for _, p := range providers {
		resp = append(resp, toProviderResponse(p))
	}

	c.JSON(http.StatusOK, ListProvidersResponse{Providers: resp})
}

// GetProvider handles GET /api/v1/clients/:client_id/providers/:id
// Returns a single OAuth provider, validating it belongs to the specified client (admin only).
func (h *ApiV1Handler) GetProvider(c *gin.Context) {
	clientID, ok := parseClientID(c)
	if !ok {
		return
	}

	providerID, ok := parseProviderID(c)
	if !ok {
		return
	}

	p, err := h.providerService.GetProvider(c.Request.Context(), providerID)
	if err != nil {
		handleProviderError(c, err)
		return
	}

	// Validate client ownership.
	if p.ClientID != clientID {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}

	c.JSON(http.StatusOK, toProviderResponse(*p))
}

// CreateProvider handles POST /api/v1/clients/:client_id/providers
// Creates a new OAuth provider scoped to the specified client (admin only).
func (h *ApiV1Handler) CreateProvider(c *gin.Context) {
	clientID, ok := parseClientID(c)
	if !ok {
		return
	}

	var req CreateProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	p, err := h.providerService.CreateProvider(c.Request.Context(), clientID, provider.CreateProviderDTO{
		Name:                 req.Name,
		DisplayName:          req.DisplayName,
		ProviderClientID:     req.ProviderClientID,
		ProviderClientSecret: req.ProviderClientSecret,
		AuthURL:              req.AuthURL,
		TokenURL:             req.TokenURL,
		UserInfoURL:          req.UserInfoURL,
		Scopes:               req.Scopes,
		IsEnabled:            req.IsEnabled,
	})
	if err != nil {
		handleProviderError(c, err)
		return
	}

	c.JSON(http.StatusCreated, toProviderResponse(*p))
}

// UpdateProvider handles PATCH /api/v1/clients/:client_id/providers/:id
// Updates an existing OAuth provider, validating client ownership (admin only).
func (h *ApiV1Handler) UpdateProvider(c *gin.Context) {
	clientID, ok := parseClientID(c)
	if !ok {
		return
	}

	providerID, ok := parseProviderID(c)
	if !ok {
		return
	}

	var req UpdateProviderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	p, err := h.providerService.UpdateProvider(c.Request.Context(), providerID, clientID, provider.UpdateProviderDTO{
		DisplayName:          req.DisplayName,
		ProviderClientID:     req.ProviderClientID,
		ProviderClientSecret: req.ProviderClientSecret,
		AuthURL:              req.AuthURL,
		TokenURL:             req.TokenURL,
		UserInfoURL:          req.UserInfoURL,
		Scopes:               req.Scopes,
		IsEnabled:            req.IsEnabled,
	})
	if err != nil {
		handleProviderError(c, err)
		return
	}

	c.JSON(http.StatusOK, toProviderResponse(*p))
}

// DeleteProvider handles DELETE /api/v1/clients/:client_id/providers/:id
// Permanently removes an OAuth provider, validating client ownership (admin only).
func (h *ApiV1Handler) DeleteProvider(c *gin.Context) {
	clientID, ok := parseClientID(c)
	if !ok {
		return
	}

	providerID, ok := parseProviderID(c)
	if !ok {
		return
	}

	if err := h.providerService.DeleteProvider(c.Request.Context(), providerID, clientID); err != nil {
		handleProviderError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}
