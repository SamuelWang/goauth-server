# Repository Layer Documentation

**Package:** `repository`  
**Location:** `internal/repository/`  
**Generator:** [sqlc](https://sqlc.dev/) v1.30.0  
**Database Driver:** `pgx/v5`

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Data Models](#data-models)
   - [User](#user)
   - [Client](#client)
   - [OauthProvider](#oauthprovider)
   - [AuthorizationCode](#authorizationcode)
   - [AccessToken](#accesstoken)
4. [Database Interface](#database-interface)
5. [Query Methods](#query-methods)
   - [Users](#users)
   - [Clients](#clients)
   - [OAuth Providers](#oauth-providers)
   - [Authorization Codes](#authorization-codes)
   - [Access Tokens](#access-tokens)
6. [Testing](#testing)

---

## Overview

The repository layer provides the entire data access interface for the goauth-server. All SQL queries are written in `db/queries/` and compiled into type-safe Go code by **sqlc**. The generated files (`*.sql.go`) and models (`models.go`) must not be edited by hand — changes should be made to the source SQL files and regenerated.

The layer exposes a single `Queries` struct that is instantiated with any `DBTX`-compatible connection (a raw `pgx.Conn`, a `pgxpool.Pool`, or a `pgx.Tx`). Transaction support is available via the `WithTx` method.

---

## Architecture

```
db/queries/          ← Hand-written SQL (source of truth)
    users.sql
    clients.sql
    oauth_providers.sql
    authorization_codes.sql
    access_tokens.sql

internal/repository/ ← sqlc-generated Go code (do not edit)
    db.go            ← DBTX interface, Queries struct, New(), WithTx()
    models.go        ← Go struct definitions for every table
    users.sql.go
    clients.sql.go
    oauth_providers.sql.go
    authorization_codes.sql.go
    access_tokens.sql.go
```

Regenerate after editing SQL:

```bash
sqlc generate
```

---

## Data Models

All models are defined in `models.go` and map 1-to-1 with the corresponding PostgreSQL tables.

### User

```go
type User struct {
    ID            uuid.UUID
    Email         string
    EmailVerified bool
    FirstName     *string
    LastName      *string
    IsActive      bool
    Locale        string
    Provider      *string
    ProviderID    *string
    ProviderData  *models.OAuthProviderData
    LastLoginAt   time.Time
    CreatedAt     time.Time
    UpdatedAt     time.Time
    IsAdmin       *bool
}
```

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `uuid.UUID` | Primary key, auto-generated |
| `Email` | `string` | Unique, used as the canonical user identifier |
| `EmailVerified` | `bool` | Set to `true` when the OAuth provider confirms the email |
| `FirstName` | `*string` | Nullable |
| `LastName` | `*string` | Nullable |
| `IsActive` | `bool` | Soft-delete flag; defaults to `true` |
| `Locale` | `string` | BCP 47 locale code (e.g. `"en"`) |
| `Provider` | `*string` | Identity provider name (e.g. `"google"`) |
| `ProviderID` | `*string` | Subject identifier from the provider |
| `ProviderData` | `*models.OAuthProviderData` | Raw provider token/profile data (JSONB) |
| `LastLoginAt` | `time.Time` | Updated on every successful authentication |
| `CreatedAt` | `time.Time` | Immutable, set on INSERT |
| `UpdatedAt` | `time.Time` | Updated by trigger on every row change |
| `IsAdmin` | `*bool` | Nullable; `true` grants administrative privileges |

---

### Client

```go
type Client struct {
    ID               uuid.UUID
    Name             string
    Description      *string
    ClientSecretHash string
    RedirectUris     []string
    GrantTypes       []string
    IsActive         *bool
    CreatedBy        uuid.UUID
    CreatedAt        time.Time
    UpdatedAt        time.Time
}
```

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `uuid.UUID` | Primary key |
| `Name` | `string` | Human-readable application name |
| `Description` | `*string` | Nullable |
| `ClientSecretHash` | `string` | Bcrypt hash of the client secret — never stored in plaintext |
| `RedirectUris` | `[]string` | Allowed redirect URIs for the authorization code flow |
| `GrantTypes` | `[]string` | Permitted OAuth 2.0 grant types (e.g. `["authorization_code"]`) |
| `IsActive` | `*bool` | Soft-delete flag |
| `CreatedBy` | `uuid.UUID` | FK → `users.id` |
| `CreatedAt` | `time.Time` | Immutable |
| `UpdatedAt` | `time.Time` | Updated by trigger |

---

### OauthProvider

```go
type OauthProvider struct {
    ID                   uuid.UUID
    ClientID             uuid.UUID
    Name                 string
    DisplayName          string
    ProviderClientID     string
    ProviderClientSecret string
    AuthUrl              string
    TokenUrl             string
    UserInfoUrl          string
    Scopes               []string
    IsEnabled            *bool
    CreatedAt            time.Time
    UpdatedAt            time.Time
}
```

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `uuid.UUID` | Primary key |
| `ClientID` | `uuid.UUID` | FK → `clients.id`; provider is scoped to a single client |
| `Name` | `string` | Machine-readable identifier (e.g. `"google"`) |
| `DisplayName` | `string` | UI label (e.g. `"Sign in with Google"`) |
| `ProviderClientID` | `string` | OAuth app client ID from the external provider |
| `ProviderClientSecret` | `string` | OAuth app client secret from the external provider |
| `AuthUrl` | `string` | Provider's authorization endpoint |
| `TokenUrl` | `string` | Provider's token endpoint |
| `UserInfoUrl` | `string` | Provider's user-info endpoint |
| `Scopes` | `[]string` | Requested OAuth scopes (e.g. `["openid","email","profile"]`) |
| `IsEnabled` | `*bool` | When `false`, the provider is hidden from the login page |
| `CreatedAt` | `time.Time` | Immutable |
| `UpdatedAt` | `time.Time` | Updated by trigger |

---

### AuthorizationCode

```go
type AuthorizationCode struct {
    ID                  uuid.UUID
    Code                string
    ClientID            uuid.UUID
    UserID              uuid.UUID
    ProviderID          uuid.UUID
    RedirectUri         string
    Scope               *string
    State               *string
    CodeChallenge       *string
    CodeChallengeMethod *string
    ExpiresAt           time.Time
    UsedAt              *time.Time
    IsRevoked           *bool
    CreatedAt           time.Time
}
```

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `uuid.UUID` | Primary key |
| `Code` | `string` | Opaque authorization code value sent to the client |
| `ClientID` | `uuid.UUID` | FK → `clients.id` |
| `UserID` | `uuid.UUID` | FK → `users.id` |
| `ProviderID` | `uuid.UUID` | FK → `oauth_providers.id` |
| `RedirectUri` | `string` | Must match the redirect URI presented at issuance |
| `Scope` | `*string` | Space-separated list of granted scopes |
| `State` | `*string` | CSRF state parameter echoed back to the client |
| `CodeChallenge` | `*string` | PKCE code challenge (S256 or plain) |
| `CodeChallengeMethod` | `*string` | `"S256"` or `"plain"` |
| `ExpiresAt` | `time.Time` | Short-lived (typically 5–10 minutes) |
| `UsedAt` | `*time.Time` | Set when the code is exchanged for a token; `nil` if unused |
| `IsRevoked` | `*bool` | Explicitly revoked before expiry |
| `CreatedAt` | `time.Time` | Immutable |

---

### AccessToken

```go
type AccessToken struct {
    ID        uuid.UUID
    TokenHash string
    ClientID  uuid.UUID
    UserID    uuid.UUID
    Scope     *string
    ExpiresAt time.Time
    IsRevoked *bool
    CreatedAt time.Time
}
```

| Field | Type | Notes |
|-------|------|-------|
| `ID` | `uuid.UUID` | Primary key |
| `TokenHash` | `string` | SHA-256 hash of the bearer token — never stored in plaintext |
| `ClientID` | `uuid.UUID` | FK → `clients.id` |
| `UserID` | `uuid.UUID` | FK → `users.id` |
| `Scope` | `*string` | Space-separated list of granted scopes |
| `ExpiresAt` | `time.Time` | Token expiry timestamp |
| `IsRevoked` | `*bool` | Explicitly revoked before expiry |
| `CreatedAt` | `time.Time` | Immutable |

---

## Database Interface

### `DBTX`

```go
type DBTX interface {
    Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
    Query(context.Context, string, ...interface{}) (pgx.Rows, error)
    QueryRow(context.Context, string, ...interface{}) pgx.Row
}
```

Any `pgx`-compatible connection satisfies this interface, including `*pgx.Conn`, `*pgxpool.Pool`, and `pgx.Tx`.

### `New(db DBTX) *Queries`

Constructs a new `Queries` instance wrapping the provided connection.

### `(*Queries) WithTx(tx pgx.Tx) *Queries`

Returns a new `Queries` instance scoped to the given transaction. Use this when multiple queries must execute atomically.

```go
tx, _ := pool.Begin(ctx)
q := repository.New(pool).WithTx(tx)
// ... execute queries
tx.Commit(ctx)
```

---

## Query Methods

### Users

Source file: `users.sql.go`

#### `CreateUser`

```go
func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error)
```

Inserts a new user row and returns the full record. Used during first-time OAuth login.

**Parameters (`CreateUserParams`):**

| Field | Type |
|-------|------|
| `Email` | `string` |
| `EmailVerified` | `bool` |
| `FirstName` | `*string` |
| `LastName` | `*string` |
| `Provider` | `*string` |
| `ProviderID` | `*string` |
| `ProviderData` | `*models.OAuthProviderData` |
| `Locale` | `string` |
| `LastLoginAt` | `time.Time` |

---

#### `GetUserByID`

```go
func (q *Queries) GetUserByID(ctx context.Context, id uuid.UUID) (User, error)
```

Fetches a single user by primary key. Returns `pgx.ErrNoRows` if not found.

---

#### `GetUserByEmail`

```go
func (q *Queries) GetUserByEmail(ctx context.Context, email string) (User, error)
```

Fetches a single user by email address. Returns `pgx.ErrNoRows` if not found.

---

#### `GetUserByProviderID`

```go
func (q *Queries) GetUserByProviderID(ctx context.Context, arg GetUserByProviderIDParams) (User, error)
```

Fetches the user matching a `(provider, provider_id)` pair. Used during OAuth callback to check whether an account already exists.

**Parameters (`GetUserByProviderIDParams`):**

| Field | Type |
|-------|------|
| `Provider` | `*string` |
| `ProviderID` | `*string` |

---

#### `UpdateLastLogin`

```go
func (q *Queries) UpdateLastLogin(ctx context.Context, arg UpdateLastLoginParams) (User, error)
```

Updates `provider_data` and `last_login_at` for a returning user and returns the updated record.

**Parameters (`UpdateLastLoginParams`):**

| Field | Type |
|-------|------|
| `ID` | `uuid.UUID` |
| `ProviderData` | `*models.OAuthProviderData` |
| `LastLoginAt` | `time.Time` |

---

#### `ListUsers`

```go
func (q *Queries) ListUsers(ctx context.Context, arg ListUsersParams) ([]User, error)
```

Returns a paginated, optionally filtered list of users ordered by `created_at DESC`.

**Parameters (`ListUsersParams`):**

| Field | Type | Notes |
|-------|------|-------|
| `Column1` | `bool` | Filter by `is_active`; pass `nil` to skip |
| `Column2` | `bool` | Filter by `is_admin`; pass `nil` to skip |
| `Limit` | `int32` | Page size |
| `Offset` | `int32` | Page offset |

---

#### `CountUsers`

```go
func (q *Queries) CountUsers(ctx context.Context, arg CountUsersParams) (int64, error)
```

Returns the total number of users matching the same optional filters as `ListUsers`. Intended for pagination metadata.

**Parameters (`CountUsersParams`):**

| Field | Type | Notes |
|-------|------|-------|
| `Column1` | `bool` | Filter by `is_active`; pass `nil` to skip |
| `Column2` | `bool` | Filter by `is_admin`; pass `nil` to skip |

---

#### `GetUsersByAdmin`

```go
func (q *Queries) GetUsersByAdmin(ctx context.Context, isAdmin *bool) ([]User, error)
```

Returns all users where `is_admin` matches the supplied value, ordered by `created_at DESC`.

---

### Clients

Source file: `clients.sql.go`

#### `CreateClient`

```go
func (q *Queries) CreateClient(ctx context.Context, arg CreateClientParams) (Client, error)
```

Inserts a new OAuth client and returns the full record.

**Parameters (`CreateClientParams`):**

| Field | Type |
|-------|------|
| `Name` | `string` |
| `Description` | `*string` |
| `ClientSecretHash` | `string` |
| `RedirectUris` | `[]string` |
| `GrantTypes` | `[]string` |
| `IsActive` | `*bool` |
| `CreatedBy` | `uuid.UUID` |

---

#### `GetClient`

```go
func (q *Queries) GetClient(ctx context.Context, id uuid.UUID) (Client, error)
```

Fetches a client by ID regardless of `is_active` status. Intended for administrative use.

---

#### `GetClientByID`

```go
func (q *Queries) GetClientByID(ctx context.Context, id uuid.UUID) (Client, error)
```

Fetches an **active** client by ID (`is_active = true`). Use this in the authorization flow to reject deactivated clients.

---

#### `UpdateClient`

```go
func (q *Queries) UpdateClient(ctx context.Context, arg UpdateClientParams) (Client, error)
```

Updates mutable client fields and returns the updated record.

**Parameters (`UpdateClientParams`):**

| Field | Type |
|-------|------|
| `ID` | `uuid.UUID` |
| `Name` | `string` |
| `Description` | `*string` |
| `RedirectUris` | `[]string` |
| `GrantTypes` | `[]string` |

---

#### `RegenerateClientSecret`

```go
func (q *Queries) RegenerateClientSecret(ctx context.Context, arg RegenerateClientSecretParams) (Client, error)
```

Replaces `client_secret_hash` and returns the updated record.

**Parameters (`RegenerateClientSecretParams`):**

| Field | Type |
|-------|------|
| `ID` | `uuid.UUID` |
| `ClientSecretHash` | `string` |

---

#### `DeleteClient`

```go
func (q *Queries) DeleteClient(ctx context.Context, id uuid.UUID) error
```

Soft-deletes a client by setting `is_active = false`. The row is retained in the database.

---

#### `ListClients`

```go
func (q *Queries) ListClients(ctx context.Context, arg ListClientsParams) ([]Client, error)
```

Returns a paginated, optionally filtered list of clients ordered by `created_at DESC`.

**Parameters (`ListClientsParams`):**

| Field | Type | Notes |
|-------|------|-------|
| `Column1` | `bool` | Filter by `is_active`; pass `nil` to skip |
| `Limit` | `int32` | Page size |
| `Offset` | `int32` | Page offset |

---

#### `CountClients`

```go
func (q *Queries) CountClients(ctx context.Context, dollar_1 bool) (int64, error)
```

Returns the total number of clients matching the optional `is_active` filter.

---

### OAuth Providers

Source file: `oauth_providers.sql.go`

#### `CreateOAuthProvider`

```go
func (q *Queries) CreateOAuthProvider(ctx context.Context, arg CreateOAuthProviderParams) (OauthProvider, error)
```

Registers a new OAuth provider configuration for a client.

**Parameters (`CreateOAuthProviderParams`):**

| Field | Type |
|-------|------|
| `ClientID` | `uuid.UUID` |
| `Name` | `string` |
| `DisplayName` | `string` |
| `ProviderClientID` | `string` |
| `ProviderClientSecret` | `string` |
| `AuthUrl` | `string` |
| `TokenUrl` | `string` |
| `UserInfoUrl` | `string` |
| `Scopes` | `[]string` |
| `IsEnabled` | `*bool` |

---

#### `GetOAuthProvider`

```go
func (q *Queries) GetOAuthProvider(ctx context.Context, id uuid.UUID) (OauthProvider, error)
```

Fetches a provider by primary key.

---

#### `GetOAuthProviderByClientAndName`

```go
func (q *Queries) GetOAuthProviderByClientAndName(ctx context.Context, arg GetOAuthProviderByClientAndNameParams) (OauthProvider, error)
```

Fetches a provider by the `(client_id, name)` composite lookup. Useful for validating a provider name during an authorization request.

**Parameters (`GetOAuthProviderByClientAndNameParams`):**

| Field | Type |
|-------|------|
| `ClientID` | `uuid.UUID` |
| `Name` | `string` |

---

#### `UpdateOAuthProvider`

```go
func (q *Queries) UpdateOAuthProvider(ctx context.Context, arg UpdateOAuthProviderParams) (OauthProvider, error)
```

Updates all mutable provider fields except `name` (which is immutable) and returns the updated record.

**Parameters (`UpdateOAuthProviderParams`):**

| Field | Type |
|-------|------|
| `ID` | `uuid.UUID` |
| `DisplayName` | `string` |
| `ProviderClientID` | `string` |
| `ProviderClientSecret` | `string` |
| `AuthUrl` | `string` |
| `TokenUrl` | `string` |
| `UserInfoUrl` | `string` |
| `Scopes` | `[]string` |
| `IsEnabled` | `*bool` |

---

#### `DisableOAuthProvider`

```go
func (q *Queries) DisableOAuthProvider(ctx context.Context, id uuid.UUID) error
```

Sets `is_enabled = false` for the specified provider.

---

#### `DeleteOAuthProvider`

```go
func (q *Queries) DeleteOAuthProvider(ctx context.Context, id uuid.UUID) error
```

Hard-deletes the provider row. Unlike clients and tokens, OAuth providers are fully removed.

---

#### `ListOAuthProvidersByClient`

```go
func (q *Queries) ListOAuthProvidersByClient(ctx context.Context, clientID uuid.UUID) ([]OauthProvider, error)
```

Returns all providers belonging to a client, ordered by `display_name`.

---

#### `ListEnabledOAuthProvidersByClient`

```go
func (q *Queries) ListEnabledOAuthProvidersByClient(ctx context.Context, clientID uuid.UUID) ([]OauthProvider, error)
```

Returns only enabled providers (`is_enabled = true`) for a client, ordered by `display_name`. Used to populate the login page.

---

### Authorization Codes

Source file: `authorization_codes.sql.go`

#### `CreateAuthorizationCode`

```go
func (q *Queries) CreateAuthorizationCode(ctx context.Context, arg CreateAuthorizationCodeParams) (AuthorizationCode, error)
```

Issues a new authorization code.

**Parameters (`CreateAuthorizationCodeParams`):**

| Field | Type |
|-------|------|
| `Code` | `string` |
| `ClientID` | `uuid.UUID` |
| `UserID` | `uuid.UUID` |
| `ProviderID` | `uuid.UUID` |
| `RedirectUri` | `string` |
| `Scope` | `*string` |
| `State` | `*string` |
| `CodeChallenge` | `*string` |
| `CodeChallengeMethod` | `*string` |
| `ExpiresAt` | `time.Time` |

---

#### `GetAuthorizationCode`

```go
func (q *Queries) GetAuthorizationCode(ctx context.Context, code string) (AuthorizationCode, error)
```

Fetches a code record by its opaque code string. Returns `pgx.ErrNoRows` if not found.

---

#### `GetAuthorizationCodeByID`

```go
func (q *Queries) GetAuthorizationCodeByID(ctx context.Context, id uuid.UUID) (AuthorizationCode, error)
```

Fetches a code record by primary key.

---

#### `MarkAuthorizationCodeUsed`

```go
func (q *Queries) MarkAuthorizationCodeUsed(ctx context.Context, id uuid.UUID) (AuthorizationCode, error)
```

Sets `used_at = now()` and returns the updated record. Must be called immediately after a successful token exchange to prevent code reuse.

---

#### `RevokeAuthorizationCode`

```go
func (q *Queries) RevokeAuthorizationCode(ctx context.Context, id uuid.UUID) error
```

Sets `is_revoked = true` by primary key.

---

#### `RevokeAuthorizationCodeByCode`

```go
func (q *Queries) RevokeAuthorizationCodeByCode(ctx context.Context, code string) error
```

Sets `is_revoked = true` by the opaque code string. Useful when the code value is known but the ID is not.

---

#### `ListAuthorizationCodes`

```go
func (q *Queries) ListAuthorizationCodes(ctx context.Context, arg ListAuthorizationCodesParams) ([]AuthorizationCode, error)
```

Returns a paginated, optionally filtered list of authorization codes ordered by `created_at DESC`.

**Parameters (`ListAuthorizationCodesParams`):**

| Field | Type | Notes |
|-------|------|-------|
| `Column1` | `uuid.UUID` | Filter by `client_id`; pass nil UUID to skip |
| `Column2` | `uuid.UUID` | Filter by `user_id`; pass nil UUID to skip |
| `Column3` | `bool` | Filter by `is_revoked`; pass `nil` to skip |
| `Limit` | `int32` | Page size |
| `Offset` | `int32` | Page offset |

---

#### `CountAuthorizationCodes`

```go
func (q *Queries) CountAuthorizationCodes(ctx context.Context, arg CountAuthorizationCodesParams) (int64, error)
```

Returns the total count matching the same optional filters as `ListAuthorizationCodes`.

**Parameters (`CountAuthorizationCodesParams`):**

| Field | Type | Notes |
|-------|------|-------|
| `Column1` | `uuid.UUID` | Filter by `client_id`; pass nil UUID to skip |
| `Column2` | `uuid.UUID` | Filter by `user_id`; pass nil UUID to skip |
| `Column3` | `bool` | Filter by `is_revoked`; pass `nil` to skip |

---

#### `DeleteExpiredAuthorizationCodes`

```go
func (q *Queries) DeleteExpiredAuthorizationCodes(ctx context.Context) error
```

Hard-deletes all authorization codes where `expires_at < now()`. Intended for a periodic cleanup job.

---

### Access Tokens

Source file: `access_tokens.sql.go`

#### `CreateAccessToken`

```go
func (q *Queries) CreateAccessToken(ctx context.Context, arg CreateAccessTokenParams) (AccessToken, error)
```

Persists a new access token record. The raw token value must be hashed by the caller before storage.

**Parameters (`CreateAccessTokenParams`):**

| Field | Type |
|-------|------|
| `TokenHash` | `string` |
| `ClientID` | `uuid.UUID` |
| `UserID` | `uuid.UUID` |
| `Scope` | `*string` |
| `ExpiresAt` | `time.Time` |

---

#### `GetAccessToken`

```go
func (q *Queries) GetAccessToken(ctx context.Context, tokenHash string) (AccessToken, error)
```

Fetches a token record by its hash. The caller must hash the incoming bearer token before calling this method. Returns `pgx.ErrNoRows` if not found.

---

#### `GetAccessTokenByID`

```go
func (q *Queries) GetAccessTokenByID(ctx context.Context, id uuid.UUID) (AccessToken, error)
```

Fetches a token record by primary key.

---

#### `RevokeAccessToken`

```go
func (q *Queries) RevokeAccessToken(ctx context.Context, id uuid.UUID) error
```

Sets `is_revoked = true` for the specified token.

---

#### `RevokeAccessTokensByUser`

```go
func (q *Queries) RevokeAccessTokensByUser(ctx context.Context, userID uuid.UUID) error
```

Revokes all tokens issued to a user. Useful for logout-all-devices functionality.

---

#### `RevokeAccessTokensByClient`

```go
func (q *Queries) RevokeAccessTokensByClient(ctx context.Context, clientID uuid.UUID) error
```

Revokes all tokens issued under a specific client. Called when a client is deactivated.

---

#### `ListAccessTokens`

```go
func (q *Queries) ListAccessTokens(ctx context.Context, arg ListAccessTokensParams) ([]AccessToken, error)
```

Returns a paginated, optionally filtered list of access tokens ordered by `created_at DESC`.

**Parameters (`ListAccessTokensParams`):**

| Field | Type | Notes |
|-------|------|-------|
| `Column1` | `uuid.UUID` | Filter by `client_id`; pass nil UUID to skip |
| `Column2` | `uuid.UUID` | Filter by `user_id`; pass nil UUID to skip |
| `Column3` | `bool` | Filter by `is_revoked`; pass `nil` to skip |
| `Limit` | `int32` | Page size |
| `Offset` | `int32` | Page offset |

---

#### `CountAccessTokens`

```go
func (q *Queries) CountAccessTokens(ctx context.Context, arg CountAccessTokensParams) (int64, error)
```

Returns the total count matching the same optional filters as `ListAccessTokens`.

**Parameters (`CountAccessTokensParams`):**

| Field | Type | Notes |
|-------|------|-------|
| `Column1` | `uuid.UUID` | Filter by `client_id`; pass nil UUID to skip |
| `Column2` | `uuid.UUID` | Filter by `user_id`; pass nil UUID to skip |
| `Column3` | `bool` | Filter by `is_revoked`; pass `nil` to skip |

---

#### `DeleteExpiredAccessTokens`

```go
func (q *Queries) DeleteExpiredAccessTokens(ctx context.Context) error
```

Hard-deletes all access tokens where `expires_at < now()`. Intended for a periodic cleanup job.

---

## Testing

Tests are located alongside the generated files (`*_test.go`) and use **testcontainers-go** to spin up a real PostgreSQL 16 instance in Docker. There are no mocks — all tests exercise actual SQL against an ephemeral database seeded with migrations.

**Requirements:**
- Docker must be running and accessible to the current user
- The test database is named `goauth_test`

**Run all repository tests:**

```bash
go test ./internal/repository/...
```

**Run with verbose output:**

```bash
go test -v ./internal/repository/...
```

Helper fixtures and shared setup are in `testhelpers_test.go`. The `TestMain` function in `users_test.go` manages container lifecycle for the entire test suite.
