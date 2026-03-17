package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// oauthSession holds the context needed to complete the OAuth flow.
// It is stored (signed) in a cookie so the callback handler can reconstruct
// the full request context without a server-side session store.
type oauthSession struct {
	State       string `json:"state"`
	ClientID    string `json:"client_id"`
	Provider    string `json:"provider"`
	RedirectURI string `json:"redirect_uri"`
}

const oauthSessionCookieName = "oauth_session"

// encodeSession serialises and HMAC-signs the session data.
// The resulting string has the form `<b64url(json)>.<b64url(hmac)>`.
func encodeSession(s oauthSession, signingKey []byte) (string, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	b64Payload := base64.RawURLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(b64Payload))
	sig := mac.Sum(nil)
	b64Sig := base64.RawURLEncoding.EncodeToString(sig)

	return b64Payload + "." + b64Sig, nil
}

// decodeSession verifies the HMAC signature and deserialises the session data.
// Returns an error if the cookie is malformed or the signature is invalid.
func decodeSession(cookieValue string, signingKey []byte) (oauthSession, error) {
	parts := strings.SplitN(cookieValue, ".", 2)
	if len(parts) != 2 {
		return oauthSession{}, errors.New("malformed session cookie")
	}
	b64Payload, b64Sig := parts[0], parts[1]

	// Verify HMAC.
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(b64Payload))
	expectedSig := mac.Sum(nil)

	gotSig, err := base64.RawURLEncoding.DecodeString(b64Sig)
	if err != nil {
		return oauthSession{}, errors.New("invalid session signature encoding")
	}
	if !hmac.Equal(expectedSig, gotSig) {
		return oauthSession{}, errors.New("session cookie signature mismatch")
	}

	payload, err := base64.RawURLEncoding.DecodeString(b64Payload)
	if err != nil {
		return oauthSession{}, errors.New("invalid session payload encoding")
	}

	var s oauthSession
	if err := json.Unmarshal(payload, &s); err != nil {
		return oauthSession{}, errors.New("malformed session payload")
	}
	return s, nil
}
