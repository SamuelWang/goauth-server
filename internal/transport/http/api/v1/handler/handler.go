package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/service/client"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/SamuelWang/goauth-server/internal/service/session"
	"github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/gin-gonic/gin"
)

type ApiV1Handler struct {
	authService     *auth.Service
	userService     *user.Service
	providerService *provider.Service
	clientService   *client.Service
	sessionService  *session.Service
}

func New(authService *auth.Service, userService *user.Service, providerService *provider.Service, clientService *client.Service, sessionService *session.Service) *ApiV1Handler {
	return &ApiV1Handler{
		authService:     authService,
		userService:     userService,
		providerService: providerService,
		clientService:   clientService,
		sessionService:  sessionService,
	}
}

// formatTimePtr formats a *time.Time pointer as an RFC3339 string pointer.
// Returns nil when t is nil.
func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format("2006-01-02T15:04:05Z")
	return &s
}

// getCookieSecure retrieves the cookie_secure value from the Gin context
func getCookieSecure(c *gin.Context) bool {
	if val, exists := c.Get("cookie_secure"); exists {
		if secure, ok := val.(bool); ok {
			return secure
		}
	}
	return false
}

// getUserID retrieves the user_id value from the Gin context
// Returns the user ID and a boolean indicating whether it was found
func getUserID(c *gin.Context) (string, bool) {
	if val, exists := c.Get("user_id"); exists {
		if userID, ok := val.(string); ok {
			return userID, true
		}
	}
	return "", false
}

// paginationMaxLimit is the maximum number of items that can be requested per page.
const paginationMaxLimit = 100

// parsePaginationParams extracts and validates the "limit" and "offset" query
// parameters.  Returns (0, 0, false) and writes an error response when the
// values are outside acceptable bounds.  Valid ranges: limit [1, 100],
// offset [0, ∞).
func parsePaginationParams(c *gin.Context) (limit int32, offset int32, ok bool) {
	rawLimit := c.DefaultQuery("limit", "20")
	rawOffset := c.DefaultQuery("offset", "0")

	l, err := strconv.Atoi(rawLimit)
	if err != nil || l < 1 || l > paginationMaxLimit {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "limit must be an integer between 1 and 100",
		})
		return 0, 0, false
	}

	o, err := strconv.Atoi(rawOffset)
	if err != nil || o < 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "offset must be a non-negative integer",
		})
		return 0, 0, false
	}

	return int32(l), int32(o), true
}
