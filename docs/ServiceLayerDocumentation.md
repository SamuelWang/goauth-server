# Service Layer Documentation

**Version:** 0.3.0  
**Updated:** April 1, 2026  
**Location:** `internal/service/`  
**Language:** Go 1.24

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Auth Service](#auth-service)
   - [Types](#auth-types)
   - [Constructor](#auth-constructor)
   - [Authorization Flow](#authorization-flow)
   - [Direct Login Flow](#direct-login-flow)
   - [Force Password Change](#force-password-change)
   - [Token Operations](#token-operations)
   - [Legacy Google OIDC Flow](#legacy-google-oidc-flow)
   - [Sentinel Errors](#auth-sentinel-errors)
4. [Audit Service](#audit-service)
   - [Types](#audit-types)
   - [Constructor](#audit-constructor)
   - [Methods](#audit-methods)
   - [Event Types](#audit-event-types)
5. [Client Service](#client-service)
   - [Types](#client-types)
   - [Constructor](#client-constructor)
   - [Methods](#client-methods)
   - [Validation](#client-validation)
   - [Sentinel Errors](#client-sentinel-errors)
6. [Provider Service](#provider-service)
   - [Types](#provider-types)
   - [Constructor](#provider-constructor)
   - [Methods](#provider-methods)
   - [Encryption](#provider-encryption)
   - [Validation](#provider-validation)
   - [Sentinel Errors](#provider-sentinel-errors)
7. [Session Service](#session-service)
   - [Types](#session-types)
   - [Constructor](#session-constructor)
   - [Methods](#session-methods)
   - [Sentinel Errors](#session-sentinel-errors)
8. [User Service](#user-service)
   - [Types](#user-types)
   - [Constructor](#user-constructor)
   - [Methods](#user-methods)
   - [Sentinel Errors](#user-sentinel-errors)
9. [Testing](#testing)

---

## Overview

The service layer is the application's business-logic core. It sits between the HTTP transport layer and the repository layer, enforcing domain rules, validating inputs, and orchestrating multi-step operations.

Each sub-package (`auth`, `client`, `provider`, `session`, `user`) owns a single `Service` struct that is constructed with the dependencies it needs. Services communicate with the database exclusively through the `repository.Querier` interface, which allows mock injection in unit tests.

---

## Architecture

```
transport/http/
      │
      ▼
┌─────────────────────────────────────────────────────┐
│                    Service Layer                    │
│                                                     │
│  ┌──────────────┐    ┌──────────────────┐           │
│  │ auth.Service │──▶│provider.Svc      │           │
│  │              │    │(providerServicer)│           │
│  └──────┬───────┘    └──────┬───────────┘           │
│         │                   │                       │
│  ┌──────▼───────┐    ┌──────▼───────┐               │
│  │client.Service│    │session.Svc   │               │
│  └──────┬───────┘    └──────┬───────┘               │
│         │                   │                       │
│  ┌──────▼───────────────────▼──────┐                │
│  │           user.Service          │                │
│  └──────────────────┬──────────────┘                │
└─────────────────────┼───────────────────────────────┘
                      │
                      ▼
              repository.Querier
                      │
                      ▼
                  PostgreSQL
```

`auth.Service` depends on `provider.Service` through the narrow `providerServicer` interface and on `audit.Service` for emitting security events. Both dependencies are optional (may be `nil` in tests or minimal deployments).

In v0.3.0 `audit.Service` is also injected into `client.Service` (for `RegenerateSecret` audit events). The `audit.Service` itself has no external dependencies beyond `repository.Querier`.

```
transport/http/
      │
      ▼
┌─────────────────────────────────────────────────────┐
│                    Service Layer                     │
│                                                     │
│  ┌──────────────┐   ┌──────────────┐               │
│  │ auth.Service │──▶│provider.Svc  │               │
│  │   (+audit)   │   │(providerServicer)│            │
│  └──────┬───────┘   └──────┬───────┘               │
│         │                  │                        │
│  ┌──────▼───────┐   ┌──────▼───────┐               │
│  │client.Service│   │session.Svc   │               │
│  │   (+audit)   │   └──────┬───────┘               │
│  └──────┬───────┘          │                        │
│         │    ┌─────────────┘                        │
│  ┌──────▼────▼──────────────────────┐              │
│  │   audit.Service  │  user.Service  │              │
│  └──────────────────┴───────────────┘              │
└─────────────────────┼───────────────────────────────┘
                       │
                       ▼
              repository.Querier
                       │
                       ▼
                  PostgreSQL
```

---

## Auth Service

**Package:** `auth`  
**Location:** `internal/service/auth/`

### Auth Types

#### `Service`

```go
type Service struct {
    cfg         *config.Config
    privateKey  *ecdsa.PrivateKey
    publicKey   *ecdsa.PublicKey
    repo        repository.Querier
    providerSvc providerServicer
    auditSvc    *audit.Service
}
```

The central service for the OAuth 2.0 authorization code flow and JWT management. It holds parsed ECDSA key material loaded from PEM strings in configuration.

#### `Claims`

```go
type Claims struct {
    UserID string `json:"user_id"`
    Email  string `json:"email"`
    jwt.RegisteredClaims
}
```

JWT claims payload embedded in every issued access token.

#### `TokenResponse`

```go
type TokenResponse struct {
    AccessToken  string
    TokenType    string
    ExpiresIn    int64   // seconds until expiry
    Scope        *string
    RefreshToken string  // non-empty when a refresh token was issued
}
```

Returned by `ExchangeCodeForToken` and `RotateRefreshToken`. `RefreshToken` is populated only when the client has `allow_refresh_tokens = true` and the granted scope includes `offline_access`.

#### `ProviderUserInfo`

```go
type ProviderUserInfo struct {
    Sub           string
    Email         string
    EmailVerified bool
    GivenName     string
    FamilyName    string
    Locale        string
    Picture       string
}
```

Normalized user profile fetched from any OAuth provider's user-info endpoint.

#### `GoogleUserInfo` / `IDTokenClaims`

```go
type GoogleUserInfo struct {
    Sub           string `json:"sub"`
    Email         string `json:"email"`
    EmailVerified bool   `json:"email_verified"`
    GivenName     string `json:"given_name"`
    FamilyName    string `json:"family_name"`
    Locale        string `json:"locale"`
}

type IDTokenClaims struct {
    Sub           string `json:"sub"`
    Email         string `json:"email"`
    EmailVerified bool   `json:"email_verified"`
    GivenName     string `json:"given_name"`
    FamilyName    string `json:"family_name"`
    Locale        string `json:"locale"`
    Picture       string `json:"picture"`
}
```

Used exclusively by the legacy Google OIDC flow.

#### `providerServicer` (internal interface)

```go
type providerServicer interface {
    GetProviderWithSecretByClientAndName(
        ctx context.Context,
        clientID uuid.UUID,
        name string,
    ) (*provider.OAuthProviderWithSecret, error)
}
```

The narrow interface that `auth.Service` uses to look up provider credentials. `provider.Service` satisfies this interface; tests inject a mock.

---

### Auth Constructor

#### `New`

```go
func New(
    repo      repository.Querier,
    cfg       *config.Config,
    providerSvc providerServicer,
    auditSvc *audit.Service,
) (*Service, error)
```

Parses PEM-encoded ECDSA keys from `cfg.AccessToken.PrivateKey` and `cfg.AccessToken.PublicKey`, then returns a fully initialized `*Service`. `auditSvc` may be `nil`; when provided, security events (failed logins, lockouts, token operations) are written to the audit log. Returns an error if either key cannot be parsed.

---

### Authorization Flow

The standard OAuth 2.0 authorization code flow proceeds in three steps:

```
Client App                  Auth Server                  OAuth Provider
    │                           │                              │
    │── InitiateAuthorization ──▶│                              │
    │                           │── GetProviderWithSecret ──▶  │
    │◀── provider auth URL ─────│                              │
    │                           │                              │
    │                           │◀──── callback with code ─────│
    │                           │── HandleProviderCallback      │
    │◀── authorization code ────│                              │
    │                           │                              │
    │── ExchangeCodeForToken ──▶│                              │
    │◀── JWT access token ──────│                              │
```

#### `InitiateAuthorization`

```go
func (s *Service) InitiateAuthorization(
    ctx context.Context,
    clientID uuid.UUID,
    providerName string,
    callbackURL string,
    clientRedirectURI string,
    state string,
    scope *string,
) (string, error)
```

Validates the client (must exist and be active), verifies that `clientRedirectURI` is registered for the client, looks up the named OAuth provider (must be enabled), and returns the external provider's authorization URL for the browser redirect.

| Error | Condition |
|-------|-----------|
| `ErrClientNotFound` | No client with the given ID exists |
| `ErrClientInactive` | Client exists but `is_active = false` |
| `ErrInvalidRedirectURI` | `clientRedirectURI` is not in the client's registered list |
| `ErrProviderDisabled` | Provider exists but is disabled for this client |

#### `HandleProviderCallback`

```go
func (s *Service) HandleProviderCallback(
    ctx context.Context,
    clientID uuid.UUID,
    providerName string,
    code string,
    callbackURL string,
    clientRedirectURI string,
) (string, error)
```

Processes the OAuth provider's callback. Exchanges the provider's authorization code for an access token, fetches user info from the provider's user-info endpoint, upserts the user account (creates on first login, updates `last_login_at` on subsequent logins), and issues a server-side authorization code that is stored in the database and returned to the client.

#### `ExchangeCodeForToken`

```go
func (s *Service) ExchangeCodeForToken(
    ctx context.Context,
    code string,
    clientID uuid.UUID,
    clientSecret string,
    redirectURI string,
) (*TokenResponse, error)
```

Validates the authorization code against the database, verifies it has not expired, been used, or been revoked, checks that `clientID` and `redirectURI` match what was recorded at issuance, verifies the client secret with **SHA-256 constant-time comparison**, marks the code as used, generates a signed JWT, stores its SHA-256 hash for revocation support. In v0.3.0, a refresh token is also issued when `client.allow_refresh_tokens = true` and the granted scope contains `offline_access`; the raw token value is included in the returned `TokenResponse.RefreshToken`.

| Error | Condition |
|-------|-----------|
| `ErrCodeNotFound` | No code in the database matches the given value |
| `ErrCodeExpired` | Code has passed its `expires_at` timestamp |
| `ErrCodeUsed` | Code has previously been exchanged (`used_at != nil`) |
| `ErrCodeRevoked` | Code has been explicitly revoked |
| `ErrCodeClientMismatch` | Code was issued for a different client |
| `ErrCodeRedirectMismatch` | `redirectURI` does not match what was recorded |
| `ErrInvalidClientSecret` | SHA-256 constant-time comparison of the client secret failed |

#### `RevokeToken`

```go
func (s *Service) RevokeToken(ctx context.Context, tokenHash string) error
```

Immediately revokes the access token identified by its hex-encoded SHA-256 hash. Returns `ErrTokenNotFound` if no matching token exists.

---

### Token Operations

#### `GenerateAccessToken`

```go
func (s *Service) GenerateAccessToken(userID, email string) (string, error)
```

Signs a JWT containing `userID` and `email` with the service's ECDSA private key. The token expiry is taken from `cfg.AccessToken.ExpiresIn`.

#### `ValidateAccessToken`

```go
func (s *Service) ValidateAccessToken(tokenString string) (*Claims, error)
```

Parses and verifies a JWT using the service's ECDSA public key. Returns the decoded `*Claims` on success.

#### `Expiry`

```go
func (s *Service) Expiry() time.Duration
```

Returns the configured access token lifetime as a `time.Duration`.

---

### Auth Sentinel Errors

| Symbol | Description |
|--------|-------------|
| `ErrClientNotFound` | No client found for the given ID |
| `ErrClientInactive` | Client is deactivated |
| `ErrProviderDisabled` | OAuth provider is disabled for this client |
| `ErrInvalidRedirectURI` | Redirect URI is not registered for the client |
| `ErrInvalidClientSecret` | Client secret did not match the stored SHA-256 hash |
| `ErrCodeNotFound` | Authorization code does not exist in the database |
| `ErrCodeExpired` | Authorization code has passed its expiry time |
| `ErrCodeUsed` | Authorization code has already been exchanged |
| `ErrCodeRevoked` | Authorization code was explicitly revoked |
| `ErrCodeClientMismatch` | Authorization code was issued for a different client |
| `ErrCodeRedirectMismatch` | Redirect URI does not match the one used at issuance |
| `ErrTokenNotFound` | Access token not found during revocation |
| `ErrAccountLocked` | User account is within an active lockout window |
| `ErrInvalidCredentials` | Email not found, missing password hash, or wrong password |
| `ErrInvalidGrant` | Invalid or replayed refresh token |
| `ErrTokenExpired` | Refresh token has passed its expiry timestamp |
| `ErrForcePasswordChangeSatisfied` | Force-password-change flag is already cleared |
| `ErrUserNotFound` | User referenced in a change-password challenge does not exist |

---

## Audit Service

**Package:** `audit`  
**Location:** `internal/service/audit/`

The `audit.Service` is a lightweight, append-only event log. It is injected into `auth.Service` and `client.Service` to record security-significant actions without blocking the primary operation. All event writing is best-effort: if `LogEvent` returns an error it is logged at `WARN` level but the caller continues normally.

### Audit Types

#### `AuditEntry`

```go
type AuditEntry struct {
    EventType EventType
    UserID    *uuid.UUID  // nil when no user is involved
    ClientID  *uuid.UUID  // nil when no client is involved
    ActorID   *uuid.UUID  // nil when the actor is the system itself
    IPAddress *string     // nil when source IP is unavailable
    Metadata  map[string]any // must NOT contain secrets; serialized to JSONB
}
```

---

### Audit Constructor

#### `New`

```go
func New(repo repository.Querier) *Service
```

Returns a `*Service` backed by the given `Querier`.

---

### Audit Methods

#### `LogEvent`

```go
func (s *Service) LogEvent(ctx context.Context, entry AuditEntry) error
```

Marshals `entry.Metadata` to JSON (defaulting to `{}` when `nil`), then calls `CreateAuditLogEntry`. DB errors are logged at `WARN` level and returned to the caller; callers treat them as non-blocking.

---

### Audit Event Types

`EventType` is a typed string constant defined in `internal/service/audit/events.go`.

| Constant | String Value | Emitted By |
|---|---|---|
| `EventDefaultAdminCreated` | `default_admin_created` | Bootstrap service |
| `EventDefaultClientCreated` | `default_client_created` | Bootstrap service |
| `EventUserPasswordChanged` | `user_password_changed` | `auth.ChangePassword` |
| `EventForcePasswordChangeSatisfied` | `force_password_change_satisfied` | `auth.ChangePassword` |
| `EventRefreshTokenIssued` | `refresh_token_issued` | `auth.ExchangeCodeForToken` |
| `EventRefreshTokenRotated` | `refresh_token_rotated` | `auth.RotateRefreshToken` |
| `EventRefreshTokenRevoked` | `refresh_token_revoked` | `auth.RevokeToken` (refresh path) |
| `EventRefreshTokenFamilyRevoked` | `refresh_token_family_revoked` | `auth.RotateRefreshToken` (replay) |
| `EventReplayDetected` | `replay_detected` | `auth.RotateRefreshToken` |
| `EventAccessTokenRevoked` | `access_token_revoked` | `auth.RevokeToken` |
| `EventAdminSessionRevoked` | `admin_session_revoked` | `session.RevokeUserSessions` / `RevokeClientSessions` |
| `EventLoginFailed` | `login_failed` | `auth.VerifyCredentials` |
| `EventAccountLocked` | `account_locked` | `auth.VerifyCredentials` |
| `EventAccountUnlocked` | `account_unlocked` | `user.UnlockUser` |
| `EventClientSecretRegenerated` | `client_secret_regenerated` | `client.RegenerateSecret` |

---

## Client Service

**Package:** `client`  
**Location:** `internal/service/client/`

Manages the lifecycle of OAuth 2.0 client applications registered with the auth server.

### Client Types

#### `Client`

```go
type Client struct {
    ID           uuid.UUID
    Name         string
    Description  *string
    RedirectURIs []string
    GrantTypes   []string
    IsActive     bool
    CreatedBy    uuid.UUID
    CreatedAt    time.Time
    UpdatedAt    time.Time
}
```

The public representation of a client application. Does **not** include the client secret.

#### `ClientWithSecret`

```go
type ClientWithSecret struct {
    Client
    PlainSecret string
}
```

Returned only on creation (`CreateClient`) and secret rotation (`RegenerateSecret`). `PlainSecret` is the only time the secret value is visible — it is not stored and cannot be retrieved afterwards.

#### `CreateClientDTO`

```go
type CreateClientDTO struct {
    Name         string
    Description  *string
    RedirectURIs []string
    GrantTypes   []string
    IsActive     bool
}
```

Input for creating a new client. Validated by `validateCreateDTO` before persistence.

#### `UpdateClientDTO`

```go
type UpdateClientDTO struct {
    Name         string
    Description  *string
    RedirectURIs []string
    GrantTypes   []string
}
```

Input for updating a client's mutable fields. Validated by `validateUpdateDTO` before persistence.

#### `ListClientsParams`

```go
type ListClientsParams struct {
    IsActive *bool
    Limit    int32
    Offset   int32
}
```

Pagination and filter parameters for `ListClients`. When `IsActive` is `nil`, the service defaults to returning only active clients.

#### `ListClientsResult`

```go
type ListClientsResult struct {
    Clients []Client
    Total   int64
}
```

Paginated result returned by `ListClients`. `Total` reflects the count across all matching pages.

#### `Service`

```go
type Service struct {
    repo     repository.Querier
    auditSvc *audit.Service
    env      string
}
```

`env` is the deployment environment string (e.g. `"production"`, `"development"`). Redirect URI validation enforces HTTPS only when `env == "production"`. `auditSvc` may be `nil`; when non-nil, `client_secret_regenerated` events are written.

---

### Client Constructor

#### `New`

```go
func New(repo repository.Querier, env string, auditSvc *audit.Service) *Service
```

Returns a `*Service`. `env` controls whether redirect URI validation requires HTTPS. `auditSvc` may be `nil`.

---

### Client Methods

#### `ListClients`

```go
func (s *Service) ListClients(ctx context.Context, params ListClientsParams) (*ListClientsResult, error)
```

Returns a paginated list of clients. When `params.IsActive` is `nil`, defaults to active clients only. `Total` is fetched with a separate `COUNT` query to support pagination metadata.

#### `GetClient`

```go
func (s *Service) GetClient(ctx context.Context, id uuid.UUID) (*Client, error)
```

Fetches a client by ID regardless of its active status. Returns `ErrClientNotFound` if no matching record exists.

#### `CreateClient`

```go
func (s *Service) CreateClient(
    ctx context.Context,
    dto CreateClientDTO,
    adminUserID uuid.UUID,
) (*ClientWithSecret, error)
```

Validates the DTO, generates a random 32-byte client secret, hashes it with **SHA-256**, and inserts the client record. The returned `ClientWithSecret.PlainSecret` is the only opportunity to retrieve the plaintext secret.

| Error | Condition |
|-------|-----------|
| `*ValidationError` | DTO failed field-level validation |
| `ErrDuplicateClientName` | A client with the same name already exists |

#### `UpdateClient`

```go
func (s *Service) UpdateClient(ctx context.Context, id uuid.UUID, dto UpdateClientDTO) (*Client, error)
```

Validates the DTO and updates the client's mutable fields. Returns `ErrClientNotFound` if the client does not exist, or `ErrDuplicateClientName` if the new name conflicts.

#### `RegenerateSecret`

```go
func (s *Service) RegenerateSecret(ctx context.Context, id uuid.UUID) (*ClientWithSecret, error)
```

Generates a new random 32-byte client secret, hashes it with **SHA-256**, persists the hash, emits a `client_secret_regenerated` audit event (when `auditSvc != nil`), and returns a `*ClientWithSecret` containing the plaintext secret. Returns `ErrClientNotFound` if the client does not exist.

#### `DeleteClient`

```go
func (s *Service) DeleteClient(ctx context.Context, id uuid.UUID) error
```

Soft-deletes the client by setting `is_active = false`. Returns `ErrClientNotFound` if the client does not exist.

---

### `ValidateClientSecret` (package-level)

```go
func ValidateClientSecret(storedHash, suppliedSecret string) bool
```

Reports whether `suppliedSecret` matches `storedHash` by computing `SHA256Hex(suppliedSecret)` and performing a constant-time byte comparison. This is a package-level helper used by callers that have already loaded the client but do not need a full service method round-trip.

---

### Client Validation

`validation.go` provides field-level DTO validation used before any database write. A failed validation returns `*ValidationError{Field, Message}`.

Allowed grant types: `"authorization_code"`, `"refresh_token"`.

Redirect URI rules:
- Must be a valid URL (parseable by `url.Parse`).
- In `"production"` environment: scheme must be `https`.
- In non-production environments: `http` and `https` are both accepted.

---

### Client Sentinel Errors

| Symbol | Description |
|--------|-------------|
| `ErrClientNotFound` | No client found for the given ID |
| `ErrDuplicateClientName` | A client with the same name already exists |

---

## Provider Service

**Package:** `provider`  
**Location:** `internal/service/provider/`

Manages the OAuth provider configurations that are attached to client applications. Provider client secrets are stored encrypted at rest using AES-256-GCM.

### Provider Types

#### `OAuthProvider`

```go
type OAuthProvider struct {
    ID          uuid.UUID
    ClientID    uuid.UUID
    Name        string
    DisplayName string
    AuthURL     string
    TokenURL    string
    UserInfoURL string
    Scopes      []string
    IsEnabled   bool
    CreatedAt   time.Time
    UpdatedAt   time.Time
}
```

The public representation of a provider configuration. Does **not** include the provider client ID or secret.

#### `OAuthProviderWithSecret`

```go
type OAuthProviderWithSecret struct {
    OAuthProvider
    ProviderClientID     string
    ProviderClientSecret string  // decrypted plaintext
}
```

Includes the decrypted provider application credentials. Used internally by `auth.Service` to build the OAuth 2.0 exchange request.

#### `CreateProviderDTO`

```go
type CreateProviderDTO struct {
    Name                 string
    DisplayName          string
    ProviderClientID     string
    ProviderClientSecret string
    AuthURL              string
    TokenURL             string
    UserInfoURL          string
    Scopes               []string
    IsEnabled            bool
}
```

Input for creating a new provider. The secret is encrypted before storage.

#### `UpdateProviderDTO`

```go
type UpdateProviderDTO struct {
    DisplayName          string
    ProviderClientID     string
    ProviderClientSecret string  // leave empty to retain existing secret
    AuthURL              string
    TokenURL             string
    UserInfoURL          string
    Scopes               []string
    IsEnabled            bool
}
```

Input for updating a provider. If `ProviderClientSecret` is empty, the stored secret is not changed.

#### `Service`

```go
type Service struct {
    repo          repository.Querier
    encryptionKey []byte  // must be exactly 32 bytes (AES-256)
}
```

---

### Provider Constructor

#### `New`

```go
func New(repo repository.Querier, encryptionKey []byte) (*Service, error)
```

Validates that `encryptionKey` is exactly 32 bytes (required for AES-256). Returns an error if the key length is invalid.

---

### Provider Methods

#### `ListProvidersByClient`

```go
func (s *Service) ListProvidersByClient(ctx context.Context, clientID uuid.UUID) ([]OAuthProvider, error)
```

Returns all providers (enabled and disabled) for the given client.

#### `ListEnabledProvidersByClient`

```go
func (s *Service) ListEnabledProvidersByClient(ctx context.Context, clientID uuid.UUID) ([]OAuthProvider, error)
```

Returns only enabled providers for the given client. Used to populate the login page.

#### `GetProvider`

```go
func (s *Service) GetProvider(ctx context.Context, id uuid.UUID) (*OAuthProvider, error)
```

Fetches a single provider by ID. Returns `ErrProviderNotFound` if no record exists.

#### `GetProviderByClientAndName`

```go
func (s *Service) GetProviderByClientAndName(
    ctx context.Context,
    clientID uuid.UUID,
    name string,
) (*OAuthProvider, error)
```

Fetches a provider by `(client_id, name)` pair. Returns `ErrProviderNotFound` if not found.

#### `GetProviderWithSecret`

```go
func (s *Service) GetProviderWithSecret(ctx context.Context, id uuid.UUID) (*OAuthProviderWithSecret, error)
```

Fetches a provider and decrypts `ProviderClientSecret` before returning. Returns `ErrProviderNotFound` if not found.

#### `GetProviderWithSecretByClientAndName`

```go
func (s *Service) GetProviderWithSecretByClientAndName(
    ctx context.Context,
    clientID uuid.UUID,
    name string,
) (*OAuthProviderWithSecret, error)
```

Combination lookup by `(client_id, name)` with decrypted secret. Used by `auth.Service` via the `providerServicer` interface to build OAuth exchange requests.

#### `CreateProvider`

```go
func (s *Service) CreateProvider(
    ctx context.Context,
    clientID uuid.UUID,
    dto CreateProviderDTO,
) (*OAuthProvider, error)
```

Validates the DTO, encrypts `ProviderClientSecret`, and inserts the provider record. Returns `ErrDuplicateProviderName` if a provider with the same name already exists for this client.

#### `UpdateProvider`

```go
func (s *Service) UpdateProvider(
    ctx context.Context,
    id uuid.UUID,
    clientID uuid.UUID,
    dto UpdateProviderDTO,
) (*OAuthProvider, error)
```

Verifies that the provider belongs to `clientID`, validates the DTO, encrypts a new secret if supplied, and persists the changes.

| Error | Condition |
|-------|-----------|
| `ErrProviderNotFound` | Provider does not exist |
| `ErrProviderClientMismatch` | Provider exists but belongs to a different client |
| `*ValidationError` | DTO failed field-level validation |

#### `EnableProvider` / `DisableProvider`

```go
func (s *Service) EnableProvider(ctx context.Context, id uuid.UUID, clientID uuid.UUID) error
func (s *Service) DisableProvider(ctx context.Context, id uuid.UUID, clientID uuid.UUID) error
```

Toggle the `is_enabled` flag after verifying ownership. Both return `ErrProviderNotFound` if the ID is unknown, or `ErrProviderClientMismatch` if the provider belongs to a different client.

#### `DeleteProvider`

```go
func (s *Service) DeleteProvider(ctx context.Context, id uuid.UUID, clientID uuid.UUID) error
```

Permanently deletes the provider record after verifying ownership.

---

### Provider Encryption

Secrets are encrypted by `encryption.go` using **AES-256-GCM** with a random 12-byte nonce prepended to the ciphertext, then base64url-encoded for storage.

```go
func encrypt(key []byte, plaintext string) (string, error)
func decrypt(key []byte, ciphertext string) (string, error)
```

The `encryptionKey` passed to `provider.New` must be exactly 32 bytes. The key is typically loaded from an environment variable or secret manager and validated at startup.

---

### Provider Validation

`validation.go` enforces field presence and URL format for provider DTOs.

```go
type ValidationError struct {
    Field   string
    Message string
}
```

`validateCreateDTO` checks: `Name`, `DisplayName`, `ProviderClientID`, `ProviderClientSecret`, `AuthURL`, `TokenURL`, `UserInfoURL`, and `Scopes`.  
`validateUpdateDTO` checks all fields except `ProviderClientSecret` (which is optional on update).

URLs are validated with `validateURL`, which requires a parseable, non-empty URL with an `http` or `https` scheme.

---

### Provider Sentinel Errors

| Symbol | Description |
|--------|-------------|
| `ErrProviderNotFound` | Provider not found by the given ID or name |
| `ErrProviderClientMismatch` | Provider belongs to a different client than supplied |
| `ErrDuplicateProviderName` | A provider with the same name already exists for this client |

---

## Session Service

**Package:** `session`  
**Location:** `internal/service/session/`

Provides administrative read and revoke operations over authorization codes and access tokens. Also exposes bulk-revoke and periodic cleanup utilities.

### Session Types

#### `AuthorizationCode`

```go
type AuthorizationCode struct {
    ID          uuid.UUID
    Code        string
    ClientID    uuid.UUID
    UserID      uuid.UUID
    ProviderID  uuid.UUID
    RedirectURI string
    Scope       *string
    ExpiresAt   time.Time
    UsedAt      *time.Time
    IsRevoked   bool
    CreatedAt   time.Time
}
```

#### `AccessToken`

```go
type AccessToken struct {
    ID        uuid.UUID
    ClientID  uuid.UUID
    UserID    uuid.UUID
    Scope     *string
    ExpiresAt time.Time
    IsRevoked bool
    CreatedAt time.Time
}
```

Note: The token hash is intentionally excluded from this type; it is an internal detail and is never surfaced through the service layer.

#### `ListAuthorizationCodesParams`

```go
type ListAuthorizationCodesParams struct {
    ClientID  *uuid.UUID
    UserID    *uuid.UUID
    IsRevoked *bool
    Limit     int32
    Offset    int32
}
```

All filter fields are optional (`nil` to skip). `Limit` defaults to a safe maximum if zero.

#### `ListAuthorizationCodesResult`

```go
type ListAuthorizationCodesResult struct {
    Codes []AuthorizationCode
    Total int64
}
```

#### `ListAccessTokensParams`

```go
type ListAccessTokensParams struct {
    ClientID  *uuid.UUID
    UserID    *uuid.UUID
    IsRevoked *bool
    Limit     int32
    Offset    int32
}
```

#### `ListAccessTokensResult`

```go
type ListAccessTokensResult struct {
    Tokens []AccessToken
    Total  int64
}
```

#### `Service`

```go
type Service struct {
    repo repository.Querier
}
```

---

### Session Constructor

#### `New`

```go
func New(repo repository.Querier) *Service
```

---

### Session Methods

#### `ListAuthorizationCodes`

```go
func (s *Service) ListAuthorizationCodes(
    ctx context.Context,
    params ListAuthorizationCodesParams,
) (*ListAuthorizationCodesResult, error)
```

Returns a paginated list of authorization codes with optional filters. Fetches the total record count in a separate query for pagination metadata.

#### `RevokeAuthorizationCode`

```go
func (s *Service) RevokeAuthorizationCode(ctx context.Context, id uuid.UUID) error
```

Fetches the code by ID (returns `ErrAuthorizationCodeNotFound` if missing) then sets its `is_revoked` flag.

#### `ListAccessTokens`

```go
func (s *Service) ListAccessTokens(
    ctx context.Context,
    params ListAccessTokensParams,
) (*ListAccessTokensResult, error)
```

Returns a paginated list of access tokens with optional filters.

#### `RevokeAccessToken`

```go
func (s *Service) RevokeAccessToken(ctx context.Context, id uuid.UUID) error
```

Revokes a single access token by ID. Returns `ErrAccessTokenNotFound` if not found.

#### `RevokeUserSessions`

```go
func (s *Service) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error
```

Bulk-revokes all access tokens belonging to a user. Useful when a user account is deactivated or suspended.

#### `RevokeClientSessions`

```go
func (s *Service) RevokeClientSessions(ctx context.Context, clientID uuid.UUID) error
```

Bulk-revokes all access tokens issued for a specific client. Useful when a client is deactivated or deleted.

#### `CleanupExpiredCodes`

```go
func (s *Service) CleanupExpiredCodes(ctx context.Context) error
```

Deletes all authorization codes whose `expires_at` is in the past. Intended to run on a scheduled interval.

#### `CleanupExpiredTokens`

```go
func (s *Service) CleanupExpiredTokens(ctx context.Context) error
```

Deletes all access tokens whose `expires_at` is in the past.

---

### Session Sentinel Errors

| Symbol | Description |
|--------|-------------|
| `ErrAuthorizationCodeNotFound` | Authorization code not found by the given ID |
| `ErrAccessTokenNotFound` | Access token not found by the given ID |

---

## User Service

**Package:** `user`  
**Location:** `internal/service/user/`

Provides administrative operations over user accounts.

### User Types

#### `User`

```go
type User struct {
    ID            uuid.UUID
    Email         string
    EmailVerified bool
    FirstName     *string
    LastName      *string
    IsActive      bool
    IsAdmin       bool
    Locale        string
    LastLoginAt   time.Time
    CreatedAt     time.Time
    UpdatedAt     time.Time
}
```

The service-layer representation of a user. `IsAdmin` is flattened from a nullable database field: a `nil` database value is treated as `false`.

#### `ListUsersParams`

```go
type ListUsersParams struct {
    IsActive *bool  // nil → true (active users only)
    IsAdmin  *bool  // nil → false (non-admin users only)
    Limit    int32
    Offset   int32
}
```

When `IsActive` is `nil` the service defaults to returning only active users. When `IsAdmin` is `nil` the service defaults to returning only non-admin users.

#### `ListUsersResult`

```go
type ListUsersResult struct {
    Users []User
    Total int64
}
```

#### `Service`

```go
type Service struct {
    repo repository.Querier
}
```

---

### User Constructor

#### `New`

```go
func New(repo repository.Querier) *Service
```

---

### User Methods

#### `ListUsers`

```go
func (s *Service) ListUsers(ctx context.Context, params ListUsersParams) (*ListUsersResult, error)
```

Returns a paginated, optionally filtered list of users. Applies default filters when `IsActive` or `IsAdmin` are `nil`. Fetches the total record count for pagination metadata.

#### `GetUser`

```go
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (*User, error)
```

Fetches a single user by ID. Returns `ErrUserNotFound` if no record exists.

#### `UpdateUserStatus`

```go
func (s *Service) UpdateUserStatus(ctx context.Context, id uuid.UUID, isActive bool) (*User, error)
```

Enables or disables a user account by setting `is_active`. Returns `ErrUserNotFound` if the user does not exist.

#### `IsAdmin`

```go
func (s *Service) IsAdmin(ctx context.Context, userID uuid.UUID) (bool, error)
```

Returns `true` if the user's `is_admin` field is explicitly `true`. A `nil` database value or `false` both return `false`. Returns `ErrUserNotFound` if the user does not exist.

---

### User Sentinel Errors

| Symbol | Description |
|--------|-------------|
| `ErrUserNotFound` | User not found for the given ID |

---

## Testing

All service packages use table-driven unit tests and mock injection via `testutil/mocks/MockQuerier` (generated from `repository.Querier`). In v0.3.0 the `MockQuerier` was extended with the following additional methods: `GetUserByEmailForAuth`, `UpdatePasswordHash`, `SetForcePasswordChange`, `IncrementFailedLoginAttempts`, `LockUserAccount`, `ResetLoginAttempts`, `UnlockUserAccount`, `CountAdminUsers`, `CreateRefreshToken`, `GetRefreshTokenByHash`, `GetRefreshTokenByID`, `ListRefreshTokensByUser`, `CountRefreshTokensByUser`, `RevokeRefreshToken`, `RevokeRefreshTokenFamily`, `MarkRefreshTokenUsed`, `RevokeRefreshTokensByUser`, `DeleteExpiredRefreshTokens`, `CreateAuditLogEntry`, `ListAuditLogEntries`, `CountAuditLogEntries`.

### Auth Service Tests (`auth_test.go`)

| Test | Description |
|------|-------------|
| `TestNew_Constructor` | Verifies key parsing and service initialization |
| `TestInitiateAuthorization_Success` | Happy-path authorization URL generation |
| `TestInitiateAuthorization_ClientNotFound` | Returns `ErrClientNotFound` |
| `TestInitiateAuthorization_ClientInactive` | Returns `ErrClientInactive` |
| `TestInitiateAuthorization_InvalidRedirectURI` | Returns `ErrInvalidRedirectURI` |
| `TestInitiateAuthorization_ProviderDisabled` | Returns `ErrProviderDisabled` |
| `TestExchangeCodeForToken_Success` | Full token exchange flow |
| `TestExchangeCodeForToken_InvalidClientSecret` | Returns `ErrInvalidClientSecret` |
| `TestExchangeCodeForToken_CodeNotFound` | Returns `ErrCodeNotFound` |
| `TestExchangeCodeForToken_CodeExpired` | Returns `ErrCodeExpired` |
| `TestExchangeCodeForToken_CodeAlreadyUsed` | Returns `ErrCodeUsed` |
| `TestExchangeCodeForToken_CodeRevoked` | Returns `ErrCodeRevoked` |
| `TestExchangeCodeForToken_ClientMismatch` | Returns `ErrCodeClientMismatch` |
| `TestExchangeCodeForToken_RedirectMismatch` | Returns `ErrCodeRedirectMismatch` |
| `TestRevokeToken_Success` | Happy-path token revocation |
| `TestRevokeToken_NotFound` | Returns `ErrTokenNotFound` |
| `TestValidateAccessToken_ValidToken` | Parses a valid JWT and returns claims |
| `TestValidateAccessToken_InvalidToken` | Returns error on bad signature |
| `TestHandleProviderCallback_Success` | Full callback processing including user upsert |
| `TestHandleProviderCallback_ClientInactive` | Returns `ErrClientInactive` |
| `TestGetGoogleLoginURL_Enabled` / `_Disabled` | Legacy Google flow URL generation |
| `TestHandleGoogleCallback_Disabled` | Returns error when Google OAuth is unconfigured |
| `TestVerifyCredentials_Success` | Happy-path login with `force_password_change = false` |
| `TestVerifyCredentials_ForcePasswordChange` | Returns `ForcePasswordChange = true` in result |
| `TestVerifyCredentials_AccountLocked` | Returns `ErrAccountLocked` with `LockedUntil` populated |
| `TestVerifyCredentials_InvalidCredentials` | Wrong password increments counter |
| `TestVerifyCredentials_LockTriggered` | Lockout triggered after max attempts within window |
| `TestRotateRefreshToken_Success` | Issues new access + refresh tokens |
| `TestRotateRefreshToken_ReplayDetected` | Revokes family and returns `ErrInvalidGrant` |
| `TestRotateRefreshToken_Expired` | Returns `ErrTokenExpired` |
| `TestChangePassword_Success` | Updates hash, clears flag, revokes refresh tokens |
| `TestChangePassword_AlreadySatisfied` | Returns `ErrForcePasswordChangeSatisfied` |

### Client Service Tests (`client_test.go`)

| Test | Description |
|------|-------------|
| `TestListClients_DefaultsToActive` | Nil filter defaults to active clients |
| `TestGetClient_Found` / `_NotFound` / `_RepoError` | Fetch by ID variants |
| `TestCreateClient_Success` | Creates client and returns plain secret |
| `TestCreateClient_DuplicateName` | Returns `ErrDuplicateClientName` |
| `TestCreateClient_ValidationError_*` | Missing name, invalid redirect URI, unsupported grant type |
| `TestCreateClient_ValidationError_ProductionHTTPS` | Rejects `http://` in production |
| `TestUpdateClient_Success` / `_NotFound` / `_DuplicateName` | Update variants |
| `TestUpdateClient_ValidationErrors` | Table-driven validation failures |
| `TestRegenerateSecret_Success` / `_NotFound` | Secret rotation variants |
| `TestDeleteClient_Success` / `_NotFound` | Soft-delete variants |
| `TestGenerateSecret_IsBase64URL` | Secret format check |
| `TestHashSecret_MatchesPlain` | SHA-256 hex digest is 64 characters; constant-time compare matches |

### Audit Service Tests (`audit_test.go`)

| Test | Description |
|------|-------------|
| `TestLogEvent_Success` | Happy-path: persists entry with marshaled metadata |
| `TestLogEvent_NilMetadata` | Stores `{}` when `Metadata` is nil |
| `TestLogEvent_RepoError` | Returns error and logs at WARN; caller continues |

### Provider Service Tests (`provider_test.go`)

| Test | Description |
|------|-------------|
| `TestNew_InvalidKeyLength` | Returns error for key ≠ 32 bytes |
| `TestListProvidersByClient` | Returns providers / propagates repo error |
| `TestListEnabledProvidersByClient` | Returns only enabled providers |
| `TestGetProvider` / `TestGetProviderByClientAndName` | Fetch variants |
| `TestGetProviderWithSecret` / `TestGetProviderWithSecretByClientAndName` | Fetch with decrypted credentials |
| `TestCreateProvider_Success` | Stores encrypted secret |
| `TestCreateProvider_ValidationErrors` | Table-driven: all required URL fields |
| `TestUpdateProvider` | Secret retained when field is empty / replaced when provided |
| `TestEnableProvider` / `TestDisableProvider` | Toggle with ownership validation |
| `TestDeleteProvider` | Delete with ownership validation |

### Session Service Tests (`session_test.go`)

| Test | Description |
|------|-------------|
| `TestListAuthorizationCodes_DefaultLimit` | Applies limit when zero |
| `TestListAuthorizationCodes_WithClientIDFilter` | Filter propagated to repo |
| `TestRevokeAuthorizationCode_Success` | Happy-path revocation |
| `TestRevokeAuthorizationCode_NotFound` | Returns `ErrAuthorizationCodeNotFound` |
| `TestListAccessTokens_DefaultLimit` | Applies limit when zero |
| `TestListAccessTokens_WithUserIDFilter` | Filter propagated to repo |
| `TestRevokeAccessToken_Success` / `_NotFound` | Token revocation variants |
| `TestRevokeUserSessions_Success` / `_Error` | Bulk user revoke |
| `TestRevokeClientSessions_Success` / `_Error` | Bulk client revoke |
| `TestCleanupExpiredCodes_Success` / `_Error` | Cleanup variants |
| `TestCleanupExpiredTokens_Success` / `_Error` | Cleanup variants |

### User Service Tests (`user_test.go`)

| Test | Description |
|------|-------------|
| `TestListUsers_NilFiltersDefaultToActiveNonAdmin` | Default filter behavior |
| `TestListUsers_ExplicitFilters` | Explicit `IsActive`/`IsAdmin` filters |
| `TestListUsers_DefaultLimit` | Applies limit when zero |
| `TestGetUser_Found` / `_NotFound` / `_RepoError` | Fetch variants |
| `TestUpdateUserStatus_Enable` / `_Disable` / `_NotFound` | Status toggle variants |
| `TestIsAdmin_True` / `_False` / `_NilIsAdminField` / `_UserNotFound` | Admin check edge cases |
