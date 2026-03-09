package handler

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/SamuelWang/goauth-server/internal/service/auth"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Login initiates the OAuth 2.0 Authorization Code flow for a client-scoped
// provider.
//
// GET /web/auth/:client_id/:provider/login?redirect_uri=<client_redirect>&scope=<optional>
func (h *WebHandler) Login(c *gin.Context) {
	clientID, ok := parseClientID(c)
	if !ok {
		return
	}
	providerName := c.Param("provider")
	if providerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing provider"})
		return
	}

	redirectURI := c.Query("redirect_uri")
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri is required"})
		return
	}
	var scopePtr *string
	if s := c.Query("scope"); s != "" {
		scopePtr = &s
	}

	state, err := generateRandomState()
	if err != nil {
		log.Printf("Login: failed to generate state: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Build the signed session cookie so the callback can reconstruct context.
	session := oauthSession{
		State:       state,
		ClientID:    clientID.String(),
		Provider:    providerName,
		RedirectURI: redirectURI,
	}
	cookieVal, err := encodeSession(session, h.signingKey)
	if err != nil {
		log.Printf("Login: failed to encode session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.SetCookie(
		oauthSessionCookieName,
		cookieVal,
		600, // 10 minutes
		"/",
		"",
		getCookieSecure(c),
		true, // HttpOnly
	)

	callbackURL := h.buildCallbackURL(clientID, providerName)

	authURL, err := h.authService.InitiateAuthorization(
		c.Request.Context(),
		clientID,
		providerName,
		callbackURL,
		redirectURI,
		state,
		scopePtr,
	)
	if err != nil {
		h.handleLoginError(c, err)
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// Callback handles the OAuth provider's redirect back to our server after the
// user authenticates.
//
// GET /web/auth/:client_id/:provider/callback?code=<code>&state=<state>
func (h *WebHandler) Callback(c *gin.Context) {
	clientID, ok := parseClientID(c)
	if !ok {
		return
	}
	providerName := c.Param("provider")
	if providerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing provider"})
		return
	}

	// Surface provider-returned errors (e.g. user denied access).
	if oauthErr := c.Query("error"); oauthErr != "" {
		desc := c.Query("error_description")
		log.Printf("Callback: provider returned error=%q description=%q", oauthErr, desc)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             oauthErr,
			"error_description": desc,
		})
		return
	}

	code := c.Query("code")
	state := c.Query("state")
	if code == "" || state == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code or state parameter"})
		return
	}

	// Retrieve and verify the signed session cookie.
	cookieVal, err := c.Cookie(oauthSessionCookieName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing session cookie; please restart the login flow"})
		return
	}
	session, err := decodeSession(cookieVal, h.signingKey)
	if err != nil {
		log.Printf("Callback: invalid session cookie: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session; please restart the login flow"})
		return
	}

	// Clear the session cookie regardless of outcome to prevent reuse.
	c.SetCookie(oauthSessionCookieName, "", -1, "/", "", getCookieSecure(c), true)

	// Validate state (CSRF protection).
	if state != session.State {
		c.JSON(http.StatusBadRequest, gin.H{"error": "state mismatch; possible CSRF attack"})
		return
	}

	// Verify path parameters match the session to prevent cookie injection.
	if session.ClientID != clientID.String() || session.Provider != providerName {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session context mismatch; please restart the login flow"})
		return
	}

	callbackURL := h.buildCallbackURL(clientID, providerName)

	authCode, err := h.authService.HandleProviderCallback(
		c.Request.Context(),
		clientID,
		providerName,
		code,
		callbackURL,
		session.RedirectURI,
	)
	if err != nil {
		h.handleCallbackError(c, err)
		return
	}

	// Redirect the user back to the client application with the authorization code.
	redirectURL, err := url.Parse(session.RedirectURI)
	if err != nil {
		log.Printf("Callback: invalid redirect URI %q: %v", session.RedirectURI, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid redirect URI"})
		return
	}
	q := redirectURL.Query()
	q.Set("code", authCode)
	redirectURL.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, redirectURL.String())
}

// buildCallbackURL constructs the absolute URL for this server's callback
// endpoint using the configured scheme, host, and port.
func (h *WebHandler) buildCallbackURL(clientID uuid.UUID, providerName string) string {
	scheme := h.cfg.Server.Scheme
	host := h.cfg.Server.HostName
	port := h.cfg.Server.Port

	hostPort := host
	if port != "" && port != "80" && port != "443" {
		hostPort = host + ":" + port
	}
	return fmt.Sprintf("%s://%s/web/auth/%s/%s/callback", scheme, hostPort, clientID, providerName)
}

// parseClientID extracts the :client_id path parameter and parses it as a UUID.
// On failure it writes an error response and returns false.
func parseClientID(c *gin.Context) (uuid.UUID, bool) {
	raw := c.Param("client_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client_id; must be a UUID"})
		return uuid.UUID{}, false
	}
	return id, true
}

// handleLoginError maps auth/provider service errors to HTTP responses.
func (h *WebHandler) handleLoginError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, auth.ErrClientNotFound), errors.Is(err, auth.ErrClientInactive):
		c.JSON(http.StatusNotFound, gin.H{"error": "client not found or inactive"})
	case errors.Is(err, auth.ErrInvalidRedirectURI):
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri is not registered for this client"})
	case errors.Is(err, provider.ErrProviderNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found for this client"})
	case errors.Is(err, auth.ErrProviderDisabled):
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider is disabled"})
	default:
		log.Printf("Login: unexpected error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}

// handleCallbackError maps auth/provider service errors to HTTP responses.
func (h *WebHandler) handleCallbackError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, auth.ErrClientNotFound), errors.Is(err, auth.ErrClientInactive):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "client not found or inactive"})
	case errors.Is(err, provider.ErrProviderNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found for this client"})
	case errors.Is(err, auth.ErrProviderDisabled):
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider is disabled"})
	default:
		log.Printf("Callback: unexpected error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication failed"})
	}
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
