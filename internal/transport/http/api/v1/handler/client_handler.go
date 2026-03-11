package handler

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/SamuelWang/goauth-server/internal/service/client"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// parseClientResourceID extracts and validates the :client_id path parameter for client resources.
func parseClientResourceID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("client_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client id"})
		return uuid.UUID{}, false
	}
	return id, true
}

// toClientResponse converts a service-layer Client to the API response DTO.
func toClientResponse(cl client.Client) ClientResponse {
	return ClientResponse{
		ID:           cl.ID.String(),
		Name:         cl.Name,
		Description:  cl.Description,
		RedirectURIs: cl.RedirectURIs,
		GrantTypes:   cl.GrantTypes,
		IsActive:     cl.IsActive,
		CreatedBy:    cl.CreatedBy.String(),
		CreatedAt:    cl.CreatedAt.UTC(),
		UpdatedAt:    cl.UpdatedAt.UTC(),
	}
}

// handleClientError maps client service errors to appropriate HTTP responses.
func handleClientError(c *gin.Context, err error) {
	var valErr *client.ValidationError
	switch {
	case errors.As(err, &valErr):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": valErr.Error()})
	case errors.Is(err, client.ErrClientNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found"})
	case errors.Is(err, client.ErrDuplicateClientName):
		c.JSON(http.StatusConflict, gin.H{"error": "a client with this name already exists"})
	default:
		log.Printf("client handler: unexpected error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}

// ListClients handles GET /api/v1/clients
// Returns a paginated list of clients (admin only).
func (h *ApiV1Handler) ListClients(c *gin.Context) {
	limit, offset, ok := parsePaginationParams(c)
	if !ok {
		return
	}

	var isActive *bool
	if isActiveStr := c.Query("is_active"); isActiveStr != "" {
		val, err := strconv.ParseBool(isActiveStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "is_active must be true or false"})
			return
		}
		isActive = &val
	}

	result, err := h.clientService.ListClients(c.Request.Context(), client.ListClientsParams{
		IsActive: isActive,
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		log.Printf("ListClients: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	resp := make([]ClientResponse, 0, len(result.Clients))
	for _, cl := range result.Clients {
		resp = append(resp, toClientResponse(cl))
	}

	c.JSON(http.StatusOK, ListClientsResponse{Clients: resp, Total: result.Total})
}

// GetClient handles GET /api/v1/clients/:id
// Returns a single client by ID (admin only).
func (h *ApiV1Handler) GetClient(c *gin.Context) {
	id, ok := parseClientResourceID(c)
	if !ok {
		return
	}

	cl, err := h.clientService.GetClient(c.Request.Context(), id)
	if err != nil {
		handleClientError(c, err)
		return
	}

	c.JSON(http.StatusOK, toClientResponse(*cl))
}

// CreateClient handles POST /api/v1/clients
// Creates a new client. Returns the client with the plain secret (returned once only).
// Admin only.
func (h *ApiV1Handler) CreateClient(c *gin.Context) {
	adminUserID, ok := getUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	adminUUID, err := uuid.Parse(adminUserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	var req CreateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cl, err := h.clientService.CreateClient(c.Request.Context(), client.CreateClientDTO{
		Name:         req.Name,
		Description:  req.Description,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
		IsActive:     req.IsActive,
	}, adminUUID)
	if err != nil {
		handleClientError(c, err)
		return
	}

	c.JSON(http.StatusCreated, ClientWithSecretResponse{
		ClientResponse: toClientResponse(cl.Client),
		ClientSecret:   cl.PlainSecret,
	})
}

// UpdateClient handles PATCH /api/v1/clients/:id
// Updates a client's configuration (admin only).
func (h *ApiV1Handler) UpdateClient(c *gin.Context) {
	id, ok := parseClientResourceID(c)
	if !ok {
		return
	}

	var req UpdateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cl, err := h.clientService.UpdateClient(c.Request.Context(), id, client.UpdateClientDTO{
		Name:         req.Name,
		Description:  req.Description,
		RedirectURIs: req.RedirectURIs,
		GrantTypes:   req.GrantTypes,
	})
	if err != nil {
		handleClientError(c, err)
		return
	}

	c.JSON(http.StatusOK, toClientResponse(*cl))
}

// RegenerateClientSecret handles POST /api/v1/clients/:id/regenerate-secret
// Generates a new client secret. Returns the new plain secret once (admin only).
func (h *ApiV1Handler) RegenerateClientSecret(c *gin.Context) {
	id, ok := parseClientResourceID(c)
	if !ok {
		return
	}

	cl, err := h.clientService.RegenerateSecret(c.Request.Context(), id)
	if err != nil {
		handleClientError(c, err)
		return
	}

	c.JSON(http.StatusOK, ClientWithSecretResponse{
		ClientResponse: toClientResponse(cl.Client),
		ClientSecret:   cl.PlainSecret,
	})
}

// DeleteClient handles DELETE /api/v1/clients/:id
// Soft-deletes a client (sets is_active = false). Admin only.
func (h *ApiV1Handler) DeleteClient(c *gin.Context) {
	id, ok := parseClientResourceID(c)
	if !ok {
		return
	}

	if err := h.clientService.DeleteClient(c.Request.Context(), id); err != nil {
		handleClientError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}
