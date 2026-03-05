package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// hashToken returns the hex-encoded SHA-256 hash of tokenString.
// This is stored in the database so that a bearer token can be looked up and
// revoked without storing the plain token value.
func hashToken(tokenString string) string {
	h := sha256.Sum256([]byte(tokenString))
	return hex.EncodeToString(h[:])
}

// generateAuthCode returns a cryptographically secure, URL-safe authorization code
// (43 characters of base64url-encoded random bytes).
func generateAuthCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
