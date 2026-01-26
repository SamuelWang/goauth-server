package handler

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GoogleLogin initiates the Google OAuth flow
func (h *WebHandler) GoogleLogin(c *gin.Context) {
	// Generate random state for CSRF protection
	state, err := generateRandomState()
	if err != nil {
		log.Printf("Failed to generate state: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Store state in a secure cookie
	c.SetCookie(
		"oauth_state",
		state,
		600, // 10 minutes
		"/",
		"",
		getCookieSecure(c), // Secure
		true,               // HttpOnly
	)

	// Get authorization URL
	url, err := h.authService.GetGoogleLoginURL(state)
	if err != nil {
		log.Printf("Failed to handle Google callback: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to authenticate"})
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, url)
}

// GoogleCallback handles the OAuth callback from Google
func (h *WebHandler) GoogleCallback(c *gin.Context) {
	// Verify state for CSRF protection
	state := c.Query("state")
	storedState, err := c.Cookie("oauth_state")
	if err != nil || state != storedState {
		log.Printf("Invalid state: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid state parameter"})
		return
	}

	// Clear the state cookie
	c.SetCookie("oauth_state", "", -1, "/", "", getCookieSecure(c), true)

	// Get authorization code
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing authorization code"})
		return
	}

	// Exchange code for token and handle user creation/login
	accessToken, err := h.authService.HandleGoogleCallback(c.Request.Context(), code)
	if err != nil {
		log.Printf("Failed to handle Google callback: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to authenticate"})
		return
	}

	// Set access token in a secure HttpOnly cookie
	c.SetCookie(
		"access_token",
		accessToken,
		3600, // 1 hour
		"/",
		"",
		getCookieSecure(c), // Secure
		true,               // HttpOnly
	)

	// Also set SameSite attribute for CSRF protection
	c.SetSameSite(http.SameSiteStrictMode)

	// Redirect to success page or return JSON
	c.JSON(http.StatusOK, gin.H{
		"message": "Authentication successful",
	})
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
