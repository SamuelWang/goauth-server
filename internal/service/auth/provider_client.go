package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	providerservice "github.com/SamuelWang/goauth-server/internal/service/provider"
	"golang.org/x/oauth2"
)

// httpClient is used for all outbound requests to OAuth provider endpoints.
// A timeout prevents resource exhaustion from slow or malicious providers.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// ProviderUserInfo holds normalized user information from an OAuth provider.
// Fields are populated from the provider's user-info response; absent fields
// are left as zero values.
type ProviderUserInfo struct {
	Sub           string
	Email         string
	EmailVerified bool
	GivenName     string
	FamilyName    string
	Locale        string
	Picture       string
}

// exchangeProviderCode exchanges an authorization code with the OAuth provider
// for an access token using the provider's token endpoint.
func exchangeProviderCode(ctx context.Context, p *providerservice.OAuthProviderWithSecret, code, callbackURL string) (*oauth2.Token, error) {
	cfg := &oauth2.Config{
		ClientID:     p.ProviderClientID,
		ClientSecret: p.ProviderClientSecret,
		RedirectURL:  callbackURL,
		Scopes:       p.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.AuthURL,
			TokenURL: p.TokenURL,
		},
	}
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging code with provider: %w", err)
	}
	return token, nil
}

// fetchUserInfo calls the provider's user-info endpoint with the bearer access
// token and maps the response to a ProviderUserInfo.  The function handles the
// common field-name variations across different OAuth providers.
func fetchUserInfo(ctx context.Context, accessToken, userInfoURL string) (*ProviderUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating user info request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info endpoint returned HTTP %d", resp.StatusCode)
	}

	// Limit response size to prevent memory exhaustion.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading user info response: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing user info response: %w", err)
	}

	info := &ProviderUserInfo{
		Sub:           strField(raw, "sub"),
		Email:         strField(raw, "email"),
		EmailVerified: boolField(raw, "email_verified"),
		Locale:        strField(raw, "locale"),
		Picture:       strField(raw, "picture"),
	}

	// "given_name" is standard OIDC; some providers use "first_name".
	if v := strField(raw, "given_name"); v != "" {
		info.GivenName = v
	} else {
		info.GivenName = strField(raw, "first_name")
	}

	// "family_name" is standard OIDC; some providers use "last_name".
	if v := strField(raw, "family_name"); v != "" {
		info.FamilyName = v
	} else {
		info.FamilyName = strField(raw, "last_name")
	}

	if info.Sub == "" {
		return nil, fmt.Errorf("user info response missing required 'sub' field")
	}
	if info.Email == "" {
		return nil, fmt.Errorf("user info response missing required 'email' field")
	}

	return info, nil
}

func strField(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func boolField(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}
