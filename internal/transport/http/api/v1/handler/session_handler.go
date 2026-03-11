package handler

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/SamuelWang/goauth-server/internal/service/session"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// toAuthorizationCodeResponse converts a session-layer AuthorizationCode to
// the API response DTO.
func toAuthorizationCodeResponse(c session.AuthorizationCode) AuthorizationCodeResponse {
	return AuthorizationCodeResponse{
		ID:          c.ID.String(),
		ClientID:    c.ClientID.String(),
		UserID:      c.UserID.String(),
		ProviderID:  c.ProviderID.String(),
		RedirectURI: c.RedirectURI,
		Scope:       c.Scope,
		ExpiresAt:   c.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		UsedAt:      formatTimePtr(c.UsedAt),
		IsRevoked:   c.IsRevoked,
		CreatedAt:   c.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

// toAccessTokenResponse converts a session-layer AccessToken to the API
// response DTO.
func toAccessTokenResponse(t session.AccessToken) AccessTokenResponse {
	return AccessTokenResponse{
		ID:        t.ID.String(),
		ClientID:  t.ClientID.String(),
		UserID:    t.UserID.String(),
		Scope:     t.Scope,
		ExpiresAt: t.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		IsRevoked: t.IsRevoked,
		CreatedAt: t.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

// handleSessionError maps session service errors to appropriate HTTP responses.
func handleSessionError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, session.ErrAuthorizationCodeNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "authorization code not found"})
	case errors.Is(err, session.ErrAccessTokenNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "access token not found"})
	default:
		log.Printf("session handler: unexpected error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}

// parseOptionalUUID parses an optional UUID query parameter.
// Returns nil when the parameter is absent, and an error when present but malformed.
func parseOptionalUUID(c *gin.Context, key string) (*uuid.UUID, error) {
	v := c.Query(key)
	if v == "" {
		return nil, nil
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// parseOptionalBool parses an optional boolean query parameter.
// Returns nil when the parameter is absent, and an error when present but malformed.
func parseOptionalBool(c *gin.Context, key string) (*bool, error) {
	v := c.Query(key)
	if v == "" {
		return nil, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// ListAuthorizationCodes handles GET /api/v1/sessions/codes
// Returns a paginated, optionally filtered list of authorization codes (admin only).
func (h *ApiV1Handler) ListAuthorizationCodes(c *gin.Context) {
	limit, offset, ok := parsePaginationParams(c)
	if !ok {
		return
	}

	clientID, err := parseOptionalUUID(c, "client_id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id must be a valid UUID"})
		return
	}

	userID, err := parseOptionalUUID(c, "user_id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id must be a valid UUID"})
		return
	}

	isRevoked, err := parseOptionalBool(c, "is_revoked")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "is_revoked must be true or false"})
		return
	}

	result, err := h.sessionService.ListAuthorizationCodes(c.Request.Context(), session.ListAuthorizationCodesParams{
		ClientID:  clientID,
		UserID:    userID,
		IsRevoked: isRevoked,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		log.Printf("ListAuthorizationCodes: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	codes := make([]AuthorizationCodeResponse, 0, len(result.Codes))
	for _, code := range result.Codes {
		codes = append(codes, toAuthorizationCodeResponse(code))
	}

	c.JSON(http.StatusOK, ListAuthorizationCodesResponse{
		Codes: codes,
		Total: result.Total,
	})
}

// RevokeAuthorizationCode handles DELETE /api/v1/sessions/codes/:id
// Revokes a single authorization code by ID (admin only).
func (h *ApiV1Handler) RevokeAuthorizationCode(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid authorization code ID"})
		return
	}

	if err := h.sessionService.RevokeAuthorizationCode(c.Request.Context(), id); err != nil {
		handleSessionError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// ListAccessTokens handles GET /api/v1/sessions/tokens
// Returns a paginated, optionally filtered list of access tokens (admin only).
func (h *ApiV1Handler) ListAccessTokens(c *gin.Context) {
	limit, offset, ok := parsePaginationParams(c)
	if !ok {
		return
	}

	clientID, err := parseOptionalUUID(c, "client_id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id must be a valid UUID"})
		return
	}

	userID, err := parseOptionalUUID(c, "user_id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id must be a valid UUID"})
		return
	}

	isRevoked, err := parseOptionalBool(c, "is_revoked")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "is_revoked must be true or false"})
		return
	}

	result, err := h.sessionService.ListAccessTokens(c.Request.Context(), session.ListAccessTokensParams{
		ClientID:  clientID,
		UserID:    userID,
		IsRevoked: isRevoked,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		log.Printf("ListAccessTokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	tokens := make([]AccessTokenResponse, 0, len(result.Tokens))
	for _, t := range result.Tokens {
		tokens = append(tokens, toAccessTokenResponse(t))
	}

	c.JSON(http.StatusOK, ListAccessTokensResponse{
		Tokens: tokens,
		Total:  result.Total,
	})
}

// RevokeAccessToken handles DELETE /api/v1/sessions/tokens/:id
// Revokes a single access token by ID (admin only).
func (h *ApiV1Handler) RevokeAccessToken(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid access token ID"})
		return
	}

	if err := h.sessionService.RevokeAccessToken(c.Request.Context(), id); err != nil {
		handleSessionError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}
