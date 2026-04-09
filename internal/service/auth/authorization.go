package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"crypto/subtle"

	"github.com/SamuelWang/goauth-server/internal/models"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/audit"
	"github.com/SamuelWang/goauth-server/internal/service/provider"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
)

// Sentinel errors returned by the authorization flow.
var (
	ErrClientNotFound       = errors.New("client not found")
	ErrClientInactive       = errors.New("client is inactive")
	ErrProviderDisabled     = errors.New("provider is disabled")
	ErrInvalidRedirectURI   = errors.New("redirect URI not registered for this client")
	ErrInvalidClientSecret  = errors.New("invalid client credentials")
	ErrCodeNotFound         = errors.New("authorization code not found")
	ErrCodeExpired          = errors.New("authorization code has expired")
	ErrCodeUsed             = errors.New("authorization code has already been used")
	ErrCodeRevoked          = errors.New("authorization code has been revoked")
	ErrCodeClientMismatch   = errors.New("authorization code was not issued for this client")
	ErrCodeRedirectMismatch = errors.New("redirect URI does not match authorization code")
	ErrTokenNotFound        = errors.New("access token not found")
)

// TokenResponse holds the issued access token and its metadata.
type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64 // seconds until expiry
	Scope        *string
	RefreshToken string // non-empty when a refresh token was issued
}

// InitiateAuthorization validates the client and provider, checks that
// clientRedirectURI is registered for the client, and returns the OAuth
// provider authorization URL for the user to be redirected to.
//
// callbackURL is the URL on our server that the OAuth provider will redirect
// to after the user authenticates (e.g. /web/auth/:clientID/:provider/callback).
// clientRedirectURI is the client application's final redirect URI; it is
// validated against the client's registered redirect_uris.
func (s *Service) InitiateAuthorization(
	ctx context.Context,
	clientID uuid.UUID,
	providerName string,
	callbackURL string,
	clientRedirectURI string,
	state string,
	scope *string,
) (string, error) {
	// 1. Validate client.
	client, err := s.repo.GetClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrClientNotFound
		}
		return "", fmt.Errorf("getting client: %w", err)
	}
	if client.IsActive == nil || !*client.IsActive {
		return "", ErrClientInactive
	}

	// 2. Validate client redirect URI.
	if !slices.Contains(client.RedirectUris, clientRedirectURI) {
		return "", ErrInvalidRedirectURI
	}

	// 3. Validate provider (with secret needed to build the config).
	p, err := s.providerSvc.GetProviderWithSecretByClientAndName(ctx, clientID, providerName)
	if err != nil {
		if errors.Is(err, provider.ErrProviderNotFound) {
			return "", provider.ErrProviderNotFound
		}
		return "", fmt.Errorf("getting provider: %w", err)
	}
	if !p.IsEnabled {
		return "", ErrProviderDisabled
	}

	// 4. Build the OAuth2 config and generate the authorization URL.
	oauthCfg := buildOAuthConfig(p, callbackURL)
	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	if scope != nil && *scope != "" {
		opts = append(opts, oauth2.SetAuthURLParam("scope", *scope))
	}
	authURL := oauthCfg.AuthCodeURL(state, opts...)
	return authURL, nil
}

// HandleProviderCallback processes the OAuth provider's authorization callback.
// It exchanges the provider code for tokens, fetches user information, upserts
// the user record, generates a short-lived authorization code, persists it, and
// returns the authorization code string to pass back to the client application.
//
// callbackURL must be the same URL used in InitiateAuthorization so that the
// provider accepts the code exchange.
// clientRedirectURI is stored in the authorization code for later validation.
func (s *Service) HandleProviderCallback(
	ctx context.Context,
	clientID uuid.UUID,
	providerName string,
	code string,
	callbackURL string,
	clientRedirectURI string,
) (string, error) {
	// 1. Validate client.
	client, err := s.repo.GetClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrClientNotFound
		}
		return "", fmt.Errorf("getting client: %w", err)
	}
	if client.IsActive == nil || !*client.IsActive {
		return "", ErrClientInactive
	}

	// 2. Get provider with decrypted credentials.
	p, err := s.providerSvc.GetProviderWithSecretByClientAndName(ctx, clientID, providerName)
	if err != nil {
		return "", fmt.Errorf("getting provider: %w", err)
	}
	if !p.IsEnabled {
		return "", ErrProviderDisabled
	}

	// 3. Exchange the authorization code with the OAuth provider.
	providerToken, err := exchangeProviderCode(ctx, p, code, callbackURL)
	if err != nil {
		return "", fmt.Errorf("exchanging provider code: %w", err)
	}

	// 4. Fetch user information from the provider's user-info endpoint.
	userInfo, err := fetchUserInfo(ctx, providerToken.AccessToken, p.UserInfoURL)
	if err != nil {
		return "", fmt.Errorf("fetching user info from provider: %w", err)
	}

	// 5. Upsert the user record.
	user, err := s.upsertUser(ctx, p.Name, userInfo)
	if err != nil {
		return "", err
	}

	// 6. Generate a short-lived authorization code.
	authCode, err := util.GenerateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("generating authorization code: %w", err)
	}

	// 7. Persist the authorization code (expires in 5 minutes, single-use).
	_, err = s.repo.CreateAuthorizationCode(ctx, repository.CreateAuthorizationCodeParams{
		Code:        authCode,
		ClientID:    clientID,
		UserID:      user.ID,
		ProviderID:  p.ID,
		RedirectUri: clientRedirectURI,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	})
	if err != nil {
		return "", fmt.Errorf("storing authorization code: %w", err)
	}

	return authCode, nil
}

// ExchangeCodeForToken validates the authorization code and client credentials,
// marks the code as used, generates a JWT access token, stores its hash in the
// database for revocation support, and returns a TokenResponse.
func (s *Service) ExchangeCodeForToken(
	ctx context.Context,
	code string,
	clientID uuid.UUID,
	clientSecret string,
	redirectURI string,
) (*TokenResponse, error) {
	// 1. Validate client credentials.
	client, err := s.repo.GetClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, fmt.Errorf("getting client: %w", err)
	}
	if client.IsActive == nil || !*client.IsActive {
		return nil, ErrClientInactive
	}
	h := util.SHA256Hex(clientSecret)
	if subtle.ConstantTimeCompare([]byte(client.ClientSecretHash), []byte(h)) != 1 {
		return nil, ErrInvalidClientSecret
	}

	// 2. Retrieve the authorization code.
	authCode, err := s.repo.GetAuthorizationCode(ctx, code)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCodeNotFound
		}
		return nil, fmt.Errorf("getting authorization code: %w", err)
	}

	// 3. Validate the authorization code.
	if authCode.IsRevoked != nil && *authCode.IsRevoked {
		return nil, ErrCodeRevoked
	}
	if authCode.UsedAt != nil {
		return nil, ErrCodeUsed
	}
	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrCodeExpired
	}
	if authCode.ClientID != clientID {
		return nil, ErrCodeClientMismatch
	}
	if authCode.RedirectUri != redirectURI {
		return nil, ErrCodeRedirectMismatch
	}

	// 4. Mark the code as used (single-use enforcement).
	if _, err := s.repo.MarkAuthorizationCodeUsed(ctx, authCode.ID); err != nil {
		return nil, fmt.Errorf("marking authorization code as used: %w", err)
	}

	// 5. Load the user for JWT claims.
	user, err := s.repo.GetUserByID(ctx, authCode.UserID)
	if err != nil {
		return nil, fmt.Errorf("getting user: %w", err)
	}

	// 6. Generate and sign the JWT access token.
	tokenString, err := s.GenerateAccessToken(user.ID.String(), user.Email)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	// 7. Store the token hash for revocation lookup.
	tokenHash := util.SHA256Hex(tokenString)
	expiresAt := time.Now().Add(s.Expiry())
	accessTokenRecord, err := s.repo.CreateAccessToken(ctx, repository.CreateAccessTokenParams{
		TokenHash: tokenHash,
		ClientID:  &clientID,
		UserID:    user.ID,
		Scope:     authCode.Scope,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("storing access token record: %w", err)
	}

	// 8. Issue a refresh token when the client allows it and "offline_access" scope
	// was granted. The raw token value is returned to the caller; only its SHA-256
	// hash is persisted to the database.
	var rawRefreshToken string
	grantedScope := ""
	if authCode.Scope != nil {
		grantedScope = *authCode.Scope
	}
	if client.AllowRefreshTokens && strings.Contains(grantedScope, "offline_access") {
		tokenValue, err := util.GenerateSecureToken(32)
		if err != nil {
			return nil, fmt.Errorf("generating refresh token: %w", err)
		}
		rtHash := util.SHA256Hex(tokenValue)
		familyID := uuid.New()
		rtExpiresAt := time.Now().Add(time.Duration(s.cfg.RefreshToken.ExpiryDays) * 24 * time.Hour)
		_, err = s.repo.CreateRefreshToken(ctx, repository.CreateRefreshTokenParams{
			TokenHash:       rtHash,
			TokenFamilyID:   familyID,
			ClientID:        clientID,
			UserID:          user.ID,
			AccessTokenID:   accessTokenRecord.ID,
			PreviousTokenID: nil,
			Scope:           grantedScope,
			ExpiresAt:       rtExpiresAt,
		})
		if err != nil {
			return nil, fmt.Errorf("storing refresh token: %w", err)
		}
		if s.auditSvc != nil {
			uid := user.ID
			cid := clientID
			_ = s.auditSvc.LogEvent(ctx, audit.AuditEntry{
				EventType: audit.EventRefreshTokenIssued,
				UserID:    &uid,
				ClientID:  &cid,
				Metadata: map[string]any{
					"scope":      grantedScope,
					"expires_at": rtExpiresAt.UTC().Format(time.RFC3339),
				},
			})
		}
		rawRefreshToken = tokenValue
	}

	return &TokenResponse{
		AccessToken:  tokenString,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.Expiry().Seconds()),
		Scope:        authCode.Scope,
		RefreshToken: rawRefreshToken,
	}, nil
}

// RevokeToken immediately revokes the access token identified by its SHA-256
// hash.  Returns ErrTokenNotFound if no matching token exists.
func (s *Service) RevokeToken(ctx context.Context, tokenHash string) error {
	token, err := s.repo.GetAccessToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTokenNotFound
		}
		return fmt.Errorf("getting access token: %w", err)
	}
	if err := s.repo.RevokeAccessToken(ctx, token.ID); err != nil {
		return fmt.Errorf("revoking access token: %w", err)
	}
	return nil
}

// RevokeRawToken hashes rawToken and revokes it. This is a convenience wrapper
// for callers (e.g. the logout handler) that hold the plain token string.
func (s *Service) RevokeRawToken(ctx context.Context, rawToken string) error {
	return s.RevokeToken(ctx, util.SHA256Hex(rawToken))
}

// RevokeUserRefreshTokens revokes all active refresh tokens for the given user.
// reason is recorded on each token row for auditing (e.g. "logout", "password_change").
// Errors are returned to callers so they may log or ignore them appropriately.
func (s *Service) RevokeUserRefreshTokens(ctx context.Context, userID uuid.UUID, reason string) error {
	return s.repo.RevokeRefreshTokensByUser(ctx, repository.RevokeRefreshTokensByUserParams{
		UserID:       userID,
		RevokeReason: &reason,
	})
}

// IsTokenRevoked reports whether the raw access token has been explicitly
// revoked in the database. It should be called after JWT signature/expiry
// validation so the database is only consulted for cryptographically valid tokens.
//
// All access tokens issued by this service are persisted in the access_tokens
// table (direct-login tokens with NULL client_id, OAuth-flow tokens with the
// issuing client_id). A token not found in the database is treated as revoked
// to guard against edge-cases where the record was not written.
func (s *Service) IsTokenRevoked(ctx context.Context, rawToken string) (bool, error) {
	record, err := s.repo.GetAccessToken(ctx, util.SHA256Hex(rawToken))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Token not found in DB — treat as revoked (no valid record exists).
			return true, nil
		}
		return false, fmt.Errorf("looking up access token: %w", err)
	}
	return record.IsRevoked != nil && *record.IsRevoked, nil
}

// upsertUser looks up a user by their OAuth provider ID. If the user exists,
// it updates the last-login timestamp; otherwise it creates a new account.
func (s *Service) upsertUser(ctx context.Context, providerName string, info *ProviderUserInfo) (repository.User, error) {
	user, err := s.repo.GetUserByProviderID(ctx, repository.GetUserByProviderIDParams{
		Provider:   util.StrPtr(providerName),
		ProviderID: util.StrPtr(info.Sub),
	})
	if err == nil {
		// User exists — update last login.
		user, err = s.repo.UpdateLastLogin(ctx, repository.UpdateLastLoginParams{
			ID:           user.ID,
			ProviderData: &models.OAuthProviderData{},
			LastLoginAt:  time.Now(),
		})
		if err != nil {
			return repository.User{}, fmt.Errorf("updating last login: %w", err)
		}
		return user, nil
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		return repository.User{}, fmt.Errorf("looking up user: %w", err)
	}

	// New user — create account.
	locale := info.Locale
	if locale == "" {
		locale = "en-US"
	}
	user, err = s.repo.CreateUser(ctx, repository.CreateUserParams{
		Email:         info.Email,
		EmailVerified: info.EmailVerified,
		FirstName:     nonEmptyStrPtr(info.GivenName),
		LastName:      nonEmptyStrPtr(info.FamilyName),
		Provider:      util.StrPtr(providerName),
		ProviderID:    util.StrPtr(info.Sub),
		ProviderData:  &models.OAuthProviderData{},
		Locale:        locale,
		LastLoginAt:   time.Now(),
	})
	if err != nil {
		return repository.User{}, fmt.Errorf("creating user: %w", err)
	}
	return user, nil
}

// buildOAuthConfig constructs an oauth2.Config from a provider row.
func buildOAuthConfig(p *provider.OAuthProviderWithSecret, callbackURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.ProviderClientID,
		ClientSecret: p.ProviderClientSecret,
		RedirectURL:  callbackURL,
		Scopes:       p.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.AuthURL,
			TokenURL: p.TokenURL,
		},
	}
}

// nonEmptyStrPtr returns a pointer to s when s is non-empty, otherwise nil.
func nonEmptyStrPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
