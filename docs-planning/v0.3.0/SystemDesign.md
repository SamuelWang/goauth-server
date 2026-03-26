# System Design Document - v0.3.0

## 1. System Analysis

### 1.1 Overview

Goauth v0.3.0 extends the v0.2.0 authorization server with three major capability areas:

1. **Default Administrator Bootstrap:** A startup mechanism that creates an initial administrator account from environment variables when no administrator exists. This removes the manual setup step described in the v0.2.0 Administrator Guide and is intended for first-run and CI/CD deployments.

2. **Default Client Bootstrap:** A startup mechanism that creates an initial OAuth 2.0 client from environment variables when no clients exist. Together with the default admin bootstrap, this enables a fully automated first-run experience.

3. **Authorization Code Grant with Refresh Tokens:** Extends the existing Authorization Code Grant flow to issue refresh tokens when the `offline_access` scope is requested by eligible clients. Refresh tokens support long-lived sessions with token rotation, replay detection, and RFC 7009 revocation.

Both bootstrap features are gated by environment-level opt-in flags and emit audit events to support compliance requirements. Refresh token operations are fully audited and never expose token material in logs or responses.

### 1.2 Actors

Same as v0.2.0, with no new actor types. The capabilities of each actor are expanded:

* **User:** Can now change their password when `force_password_change` is set (e.g., after bootstrap-created accounts), can use refresh tokens for silent session renewal, and is subject to account lockout after repeated failed login attempts.
* **Administrator:** Can list, filter, and revoke refresh tokens in addition to existing session management capabilities. Can view audit log entries and manually unlock locked user accounts.
* **Client Application:** May receive refresh tokens when `offline_access` scope is requested and the client is configured as confidential with `allow_refresh_tokens=true`.
* **OAuth Provider:** Unchanged.

### 1.3 Functional Requirements

#### Default Administrator Account Creation

* The startup routine reads `DEFAULT_ADMIN_EMAIL`, `DEFAULT_ADMIN_PASSWORD`, and `ALLOW_DEFAULT_ADMIN` environment variables.
* If `ALLOW_DEFAULT_ADMIN` is `false` (or unset) AND `ENV=production`, the bootstrap is skipped silently.
* If both email and password are present and no administrator user exists in the database, the system creates an administrator account with `is_admin=true` and `force_password_change=true`.
* The password is hashed with the application's standard Argon2id/bcrypt mechanism before persistence. The plaintext value is never stored or logged.
* The password hashing method for the default admin account is determined by the `PASSWORD_HASH_METHOD` environment variable (e.g., `argon2id` (by default) or `bcrypt` or `PBKDF2` or `scrypt`), allowing flexibility for different security requirements.
* If validation fails (empty or invalid email address, password fails complexity), startup terminates with a descriptive error.
* An audit log entry is written on successful creation (without the password).

#### Default Client Bootstrap

* The startup routine reads `DEFAULT_CLIENT_ID`, `DEFAULT_CLIENT_SECRET`, `DEFAULT_CLIENT_REDIRECT_URIS`, `DEFAULT_CLIENT_NAME`, `DEFAULT_CLIENT_CONFIDENTIAL`, and `ALLOW_DEFAULT_CLIENT` environment variables.
* If `ALLOW_DEFAULT_CLIENT` is `false` (or unset) AND `ENV=production`, the bootstrap is skipped silently.
* If `DEFAULT_CLIENT_ID` and `DEFAULT_CLIENT_SECRET` are present and no clients exist in the database, the system creates a client with the supplied metadata.
* The client secret is hashed (SHA-256) before storage. The plaintext is never stored or logged.
* If validation fails (empty client ID, invalid redirect URIs), startup terminates with a descriptive error.
* An audit log entry is written on successful creation (without the client secret).

#### Authorization Code Grant — Refresh Tokens

* When the authorization code grant request includes `offline_access` in the requested scope and the client has `allow_refresh_tokens=true`, the token endpoint returns both an access token and a refresh token.
* Refresh tokens are cryptographically random (32 bytes), stored as a SHA-256 hash, and bound to `(client_id, user_id, token_family_id)`.
* A new `POST /api/v1/auth/token` call with `grant_type=refresh_token` exchanges a valid refresh token for a new access token and a new refresh token (rotation).
* On rotation: the previous refresh token is marked used/revoked; the new token carries the same `token_family_id`.
* On replay (a revoked token is presented again): all refresh tokens sharing the same `token_family_id` are revoked immediately, and an audit event is written.
* A `POST /api/v1/auth/revoke` endpoint (RFC 7009) allows clients or administrators to revoke a refresh token (and optionally its associated access token) immediately.
* Refresh tokens are revoked on: user password change, administrator-initiated session invalidation, explicit logout.

#### Force Password Change

* Users with `force_password_change=true` can exchange credentials for a short-lived "change-password" challenge token at login. They must call `POST /api/v1/auth/change-password` with the challenge token and a new password before a full access token is issued.
* After a successful password change, `force_password_change` is set to `false` and an audit event is written.

#### Account Lockout

* The login endpoint tracks failed authentication attempts per user account using a sliding-window counter persisted in the database.
* When a user account accumulates `LOGIN_MAX_ATTEMPTS` (default: 5) failed attempts within `LOGIN_ATTEMPT_WINDOW_SECONDS` (default: 600 seconds / 10 minutes), the account is locked for `LOGIN_LOCKOUT_DURATION_SECONDS` (default: 900 seconds / 15 minutes).
* All login attempts during the lockout period return `429 Too Many Requests` with a `Retry-After` header indicating the UTC timestamp when the lockout expires.
* The lockout state is stored in the `users` table (`locked_until`, `failed_login_attempts`, `last_failed_login_at`) so it is consistent across multiple instances and survives restarts.
* A successful login resets the failed-attempt counter and clears any expired lockout.
* An `account_locked` audit event is written when the account transitions into the locked state (recording email and source IP; never the password). An `account_unlocked` audit event is written when the lockout expires naturally or is cleared by an administrator.
* Administrators can unlock an account immediately via `DELETE /api/v1/admin/users/{id}/lockout`.
* Lockout thresholds are configurable via environment variables; see §2.4.2.

#### Client Secret Hashing Change

* The client secret hashing method uses bcrypt in previous versions. In v0.3.0, the method has been changed to SHA-256 for improved performance and compatibility. This change can ignore previous client secrets in database.

### 1.4 Non-Functional Requirements

Refer to the v0.3.0 SRS for full detail. Key additions over v0.2.0:

* **Security:** Bootstrap features disabled in production by default; explicit opt-in required. All bootstrap creation events and token lifecycle events (issue, rotate, revoke, replay) audited without secret material. Refresh tokens hashed at rest, never emitted in logs.
* **Performance:** Token issuance and refresh operations should complete within 200 ms under normal single-instance load. Password-hashing cost tuned for ≤ 150 ms on the target hardware.
* **Audit retention:** Audit log entries retained for at least 90 days by default; retention period is configurable.

## 2. System Design

### 2.1 Architecture

The project continues to follow a **Clean/Layered Architecture**:

* **Presentation Layer (Transport):** HTTP handlers under `internal/transport/http/`. No structural changes; new handlers added for the revocation endpoint, change-password endpoint, and refresh-token session management.
* **Business Logic Layer (Service):** Core use cases under `internal/service/`. New sub-packages for bootstrap and audit. Existing `auth` service extended for refresh token operations.
* **Data Access Layer (Repository):** sqlc-generated code under `internal/repository/`. New queries for `refresh_tokens` and `audit_log` tables.
* **Startup / Bootstrap Hook:** A new `internal/app/auth-server/bootstrap.go` module that runs after database migrations and before the HTTP server starts. It conditionally creates default admin and client records.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Startup Sequence                             │
│                                                                     │
│  main() → Load Config → Run Migrations → Bootstrap Hook → HTTP      │
│                                    ↓                                │
│                         DefaultAdminBootstrap()                     │
│                         DefaultClientBootstrap()                    │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Technology Stack

Same as v0.2.0. No new external dependencies are required:

| Component | Technology |
|-----------|-----------|
| Language | Go 1.25+ |
| Web Framework | Gin (`github.com/gin-gonic/gin`) |
| Database | PostgreSQL 16+ |
| ORM/SQL | sqlc + pgx/v5 |
| Migrations | golang-migrate |
| JWT | `github.com/golang-jwt/jwt/v5` (ES256) |
| Password Hashing | SHA-256 (client secrets); Argon2id (user passwords) |
| Crypto | `crypto/rand`, `crypto/sha256` (stdlib) |
| Config | `godotenv` |
| Metrics | Prometheus-compatible (`internal/metrics`) |

### 2.3 Database Design

#### 2.3.1 Schema Changes to Existing Tables

**`users` table — new columns**

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `password_hash` | TEXT | Nullable | Argon2id hash of the user's local password; NULL for users authenticated exclusively via OAuth providers |
| `force_password_change` | BOOLEAN | Default: false, Not Null | When true, user must change password before receiving a full access token |
| `failed_login_attempts` | INTEGER | Default: 0, Not Null | Running count of consecutive failed login attempts within the current window |
| `last_failed_login_at` | TIMESTAMPTZ | Nullable | Timestamp of the most recent failed login attempt; used to enforce the sliding window |
| `locked_until` | TIMESTAMPTZ | Nullable | When set and in the future, all login attempts are rejected until this time |

Migration: `yyyyMMddHHmmss_add_force_password_change_to_users`

**`clients` table — new columns**

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `is_confidential` | BOOLEAN | Default: true, Not Null | Whether the client is a confidential client capable of keeping a secret |
| `allow_refresh_tokens` | BOOLEAN | Default: false, Not Null | Whether the client is permitted to receive and use refresh tokens |

Migration: `yyyyMMddHHmmss_add_confidential_refresh_tokens_to_clients`

#### 2.3.2 New Tables

**`refresh_tokens`**

Stores issued refresh tokens using a token family model to support rotation and replay detection.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PK, Default: `gen_random_uuid()` | Unique token record identifier |
| `token_family_id` | UUID | Not Null | Shared across all tokens in a rotation chain; used for family-wide revocation on replay |
| `token_hash` | TEXT | Unique, Not Null | SHA-256 hash of the raw refresh token value |
| `client_id` | UUID | FK → clients(id), Not Null | Issuing client |
| `user_id` | UUID | FK → users(id), Not Null | Token owner |
| `access_token_id` | UUID | FK → access_tokens(id), Nullable | Access token issued alongside this refresh token |
| `previous_token_id` | UUID | FK → refresh_tokens(id), Nullable | ID of the refresh token this one replaced (rotation chain) |
| `scope` | TEXT | Default: '' | Scopes granted with this token |
| `expires_at` | TIMESTAMPTZ | Not Null | Refresh token expiry (default: 30 days; configurable) |
| `is_revoked` | BOOLEAN | Default: false | Whether this token has been invalidated |
| `revoked_at` | TIMESTAMPTZ | Nullable | When the token was revoked |
| `revoke_reason` | TEXT | Nullable | Reason: `used`, `replay_detected`, `logout`, `password_change`, `admin_revoked`, `family_revoked` |
| `used_at` | TIMESTAMPTZ | Nullable | When this token was exchanged during rotation |
| `created_at` | TIMESTAMPTZ | Default: now() | Token issuance time |

*Indexes:*

* `refresh_tokens_token_hash_key` UNIQUE on `token_hash`
* `idx_refresh_tokens_token_family_id` on `token_family_id` — used for family-wide revocation
* `idx_refresh_tokens_user_id` on `user_id`
* `idx_refresh_tokens_client_id` on `client_id`
* `idx_refresh_tokens_expires_at` on `expires_at` — used by cleanup jobs
* `idx_refresh_tokens_access_token_id` on `access_token_id`

*Foreign keys:*

* `refresh_tokens_client_id_fkey` references `clients(id) ON DELETE CASCADE`
* `refresh_tokens_user_id_fkey` references `users(id) ON DELETE CASCADE`
* `refresh_tokens_access_token_id_fkey` references `access_tokens(id) ON DELETE SET NULL`
* `refresh_tokens_previous_token_id_fkey` references `refresh_tokens(id) ON DELETE SET NULL`

Migration: `yyyyMMddHHmmss_create_refresh_tokens_table`

**`audit_log`**

Append-only table for security-relevant events. No secrets or token values are written to this table.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PK, Default: `gen_random_uuid()` | Unique log entry identifier |
| `event_type` | TEXT | Not Null | Machine-readable event type (see Event Types below) |
| `user_id` | UUID | Nullable | User the event concerns (if applicable) |
| `client_id` | UUID | Nullable | Client the event concerns (if applicable) |
| `actor_id` | UUID | Nullable | Administrator or automated actor that triggered the event |
| `ip_address` | TEXT | Nullable | Source IP address of the request |
| `metadata` | JSONB | Default: '{}' | Non-sensitive contextual data (usernames, client names, event IDs — never secrets or tokens) |
| `created_at` | TIMESTAMPTZ | Default: now() | Event timestamp |

*Audit Event Types:*

| Event Type | Description |
|------------|-------------|
| `default_admin_created` | Default administrator account created at startup |
| `default_client_created` | Default OAuth client created at startup |
| `user_password_changed` | User changed their password |
| `force_password_change_satisfied` | User fulfilled the forced password change requirement |
| `refresh_token_issued` | New refresh token issued as part of authorization code exchange |
| `refresh_token_rotated` | Refresh token used and rotated; previous token invalidated |
| `refresh_token_revoked` | Refresh token explicitly revoked (logout, admin, or client) |
| `refresh_token_family_revoked` | Entire token family revoked due to replay detection |
| `replay_detected` | A previously rotated (revoked) refresh token was presented |
| `access_token_revoked` | Access token explicitly revoked |
| `admin_session_revoked` | Administrator revoked a user session |
| `login_failed` | A login attempt failed (wrong password or unknown email) |
| `account_locked` | Account locked after exceeding the failed-attempt threshold |
| `account_unlocked` | Account lockout cleared (expired naturally or by administrator action) |

*Indexes:*

* `idx_audit_log_event_type` on `event_type`
* `idx_audit_log_user_id` on `user_id`
* `idx_audit_log_client_id` on `client_id`
* `idx_audit_log_created_at` on `created_at` — supports retention queries and time-range filtering

Migration: `yyyyMMddHHmmss_create_audit_log_table`

#### 2.3.3 Updated Database Triggers

The existing `set_updated_at` trigger is extended to cover no new tables (audit_log is append-only; refresh_tokens does not need an updated_at).

### 2.4 Configuration Design

#### 2.4.1 New Config Structs

Two new configuration sub-structs are added to `internal/config/config.go`:

```go
type BootstrapConfig struct {
    // Default admin
    DefaultAdminEmail    string
    DefaultAdminPassword string
    AllowDefaultAdmin    bool // requires ALLOW_DEFAULT_ADMIN=true in production

    // Default client
    DefaultClientID           string
    DefaultClientSecret       string
    DefaultClientRedirectURIs []string
    DefaultClientName         string
    DefaultClientConfidential bool
    AllowDefaultClient        bool // requires ALLOW_DEFAULT_CLIENT=true in production
}

type RefreshTokenConfig struct {
    ExpiryDays      int  // default: 30
    RotationEnabled bool // default: true
    MaxLifetimeDays int  // default: 90; absolute max regardless of rotation
}

type LockoutConfig struct {
    MaxAttempts      int // default: 5; failed attempts before lockout
    WindowSeconds    int // default: 600 (10 min); sliding window for counting attempts
    DurationSeconds  int // default: 900 (15 min); how long the account stays locked
}
```

#### 2.4.2 New Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DEFAULT_ADMIN_EMAIL` | No | — | Email address for the default admin account |
| `DEFAULT_ADMIN_PASSWORD` | No | — | Password for the default admin account |
| `ALLOW_DEFAULT_ADMIN` | No | `false` | Set to `true` to permit default admin creation in production |
| `DEFAULT_CLIENT_ID` | No | — | Client ID string for the default client |
| `DEFAULT_CLIENT_SECRET` | No | — | Client secret for the default client |
| `DEFAULT_CLIENT_REDIRECT_URIS` | No | — | Comma-separated list of redirect URIs |
| `DEFAULT_CLIENT_NAME` | No | `GoAuth Client` | Human-readable name for the default client |
| `DEFAULT_CLIENT_CONFIDENTIAL` | No | `true` | Whether the default client is confidential |
| `ALLOW_DEFAULT_CLIENT` | No | `false` | Set to `true` to permit default client creation in production |
| `REFRESH_TOKEN_EXPIRY_DAYS` | No | `30` | Refresh token lifetime in days |
| `REFRESH_TOKEN_ROTATION_ENABLED` | No | `true` | Enable refresh token rotation on each use |
| `REFRESH_TOKEN_MAX_LIFETIME_DAYS` | No | `90` | Absolute maximum lifetime for any refresh token in a family |
| `LOGIN_MAX_ATTEMPTS` | No | `5` | Failed login attempts within the window before account lockout |
| `LOGIN_ATTEMPT_WINDOW_SECONDS` | No | `600` | Sliding window duration (seconds) for counting failed attempts |
| `LOGIN_LOCKOUT_DURATION_SECONDS` | No | `900` | Duration (seconds) an account remains locked after exceeding the threshold |

### 2.5 API Design

#### 2.5.1 Extended Token Endpoint

**`POST /api/v1/auth/token`** is extended with a second grant type.

**Refresh Token Grant:**

```
Request body (application/x-www-form-urlencoded):
  grant_type    = "refresh_token"
  refresh_token = <refresh_token_value>
  client_id     = <client_id>
  client_secret = <client_secret>
  scope         = <optional; must be subset of original scope>

Response 200:
{
  "access_token":  "<jwt>",
  "token_type":    "Bearer",
  "expires_in":    3600,
  "refresh_token": "<new_refresh_token>",
  "scope":         "openid email profile offline_access"
}
```

**Authorization Code Grant — updated response when `offline_access` scope is issued:**

```json
{
  "access_token":  "<jwt>",
  "token_type":    "Bearer",
  "expires_in":    3600,
  "refresh_token": "<refresh_token>",
  "scope":         "openid email profile offline_access"
}
```

#### 2.5.2 Token Revocation Endpoint (RFC 7009)

**`POST /api/v1/auth/revoke`**

```
Request body (application/x-www-form-urlencoded):
  token           = <token_value>
  token_type_hint = "refresh_token" | "access_token"  (optional)

Authentication: HTTP Basic with client_id:client_secret  
                OR Bearer token for user self-service revocation

Response: 200 OK (always, per RFC 7009; errors returned only for auth failures)
```

Behaviour:
* If `token_type_hint=refresh_token` or the token matches a refresh token hash, the refresh token and its currently-active descendants in the family are revoked. The linked access token is also revoked.
* If `token_type_hint=access_token` or the token matches an access token hash, only that access token is revoked.
* An audit event is written for each revoked token.

#### 2.5.3 Login Endpoint

**`POST /api/v1/auth/login`**

```
Request (application/json):
{
  "email":    "user@example.com",
  "password": "<plaintext_password>"
}

Response 200 (normal login):
{
  "access_token":  "<jwt>",
  "token_type":    "Bearer",
  "expires_in":    3600,
  "refresh_token": "<refresh_token>"   // only when offline_access was previously granted
}

Response 200 (force_password_change=true):
{
  "challenge_token": "<short_lived_challenge_token>",
  "require":         "password_change"
}

Response 400: invalid or missing email / malformed request body
Response 401: invalid credentials (generic; does not distinguish unknown email from wrong password)
Response 429: rate limit exceeded
```

**Password Policy** (enforced on all password submission paths — login validation of new passwords, registration, and change-password):

| Rule | Requirement |
|------|-------------|
| Minimum length | 12 characters |
| Uppercase | At least 1 letter A–Z |
| Lowercase | At least 1 letter a–z |
| Digit | At least 1 digit 0–9 |
| Special character | At least 1 character from `! @ # $ % ^ & * ( ) _ + - = [ ] { } ; : ' " , . < > / ? \ \| ~` |
| Deny-list | MUST NOT match any of the top-1000 commonly-used passwords (OWASP/NIST list) |
| No email substring | MUST NOT contain the user's email address (local part or full address) as a case-insensitive substring |

Behaviour:
- Email MUST be a well-formed address (RFC 5322); malformed values return `400 Bad Request`.
- Before checking credentials, the handler queries `users.locked_until`; if the lockout is still active, it returns `429 Too Many Requests` immediately with `Retry-After: <unix_timestamp>` and does not attempt password verification.
- The plaintext password is verified against the stored Argon2id hash; it is never stored or logged.
- On a **failed** attempt: `failed_login_attempts` is incremented and `last_failed_login_at` is set. If `last_failed_login_at` is older than `LOGIN_ATTEMPT_WINDOW_SECONDS`, the counter is reset to 1 first (sliding window). When `failed_login_attempts` reaches `LOGIN_MAX_ATTEMPTS`, `locked_until` is set to `now() + LOGIN_LOCKOUT_DURATION_SECONDS` and an `account_locked` audit event is written.
- On a **successful** attempt: `failed_login_attempts` is reset to 0 and `locked_until` is cleared (if it had expired).
- Rate limiting is applied per IP address and per email (configurable thresholds); `429 Too Many Requests` is returned on breach.
- All failed login attempts are written to the audit log as `login_failed` events (email and source IP only; no password material).

#### 2.5.4 Password Change Endpoint

**`POST /api/v1/auth/change-password`**

```
Request (application/json):
{
  "challenge_token": "<short_lived_challenge_token>",
  "new_password":    "<new_password>"
}

Response 200:
{
  "access_token":  "<jwt>",
  "token_type":    "Bearer",
  "expires_in":    3600
}
```

* The `challenge_token` is a short-lived (5-minute) JWT issued at login when `force_password_change=true`. It contains only the user ID and the claim `{"require": "password_change"}`. It cannot be used for API access.
* On success: `force_password_change` is set to `false`, all existing refresh tokens for the user are revoked (password change event), an audit entry is written, and a full access token is returned.

#### 2.5.4 Admin — Refresh Token Session Management

**`GET /api/v1/sessions/refresh-tokens`**

```
Query params: ?page=1&limit=20&client_id=...&user_id=...&is_revoked=false&family_id=...
Response: Paginated list of refresh token records (no token values; hashes only for reference)
```

**`DELETE /api/v1/sessions/refresh-tokens/{id}`**

Revokes a refresh token by its record ID. All tokens in the same family are also revoked. Writes an audit event with `revoke_reason=admin_revoked`.

#### 2.5.5 Admin — Audit Log

**`GET /api/v1/audit-log`**

```
Query params: ?page=1&limit=50&event_type=...&user_id=...&client_id=...&from=...&to=...
Response: Paginated list of audit log entries
```

Requires `is_admin=true`. Entries never contain secrets or raw token values.

#### 2.5.6 Admin — Account Lockout Management

**`DELETE /api/v1/admin/users/{id}/lockout`**

```
Path param: id  — UUID of the user to unlock

Response 200:
{
  "message": "account unlocked"
}

Response 404: user not found
Response 400: account is not locked
```

Requires `is_admin=true`. Clears `locked_until` and resets `failed_login_attempts` to 0 for the specified user. Writes an `account_unlocked` audit event with `actor_id` set to the acting administrator's user ID.

### 2.6 Bootstrap / Startup Flow

#### 2.6.1 Default Administrator Bootstrap

```
Startup
  ↓
Load Config → validate BootstrapConfig
  ↓
Is ENV=production AND ALLOW_DEFAULT_ADMIN != true?
  → Yes: skip, log INFO "default admin bootstrap disabled in production"
  → No: continue
  ↓
DEFAULT_ADMIN_EMAIL and DEFAULT_ADMIN_PASSWORD both present?
  → No: skip
  → Yes: continue
  ↓
Validate email (non-empty, valid email format) and password (complexity rules)
  → Fail: log FATAL with descriptive error; exit(1)
  ↓
Query: does any user with is_admin=true exist?
  → Yes: skip; log INFO "admin user already exists, skipping bootstrap"
  → No: continue
  ↓
Hash password (Argon2id)
Create user: is_admin=true, force_password_change=true
Write audit_log: event_type=default_admin_created, metadata={email}
Log WARN: "Default administrator account created — rotate credentials immediately"
```

#### 2.6.2 Default Client Bootstrap

```
Startup (after admin bootstrap)
  ↓
Is ENV=production AND ALLOW_DEFAULT_CLIENT != true?
  → Yes: skip
  → No: continue
  ↓
DEFAULT_CLIENT_ID and DEFAULT_CLIENT_SECRET both present?
  → No: skip
  → Yes: continue
  ↓
Validate client_id (non-empty, no whitespace), redirect_uris (valid URI format), secret (non-empty)
  → Fail: log FATAL; exit(1)
  ↓
Query: does any client exist?
  → Yes: skip; log INFO "client already exists, skipping bootstrap"
  → No: continue
  ↓
Hash secret (SHA-256)
Create client: is_confidential per DEFAULT_CLIENT_CONFIDENTIAL, allow_refresh_tokens=false by default
Write audit_log: event_type=default_client_created, metadata={client_id, name, redirect_uris}
Log WARN: "Default client created — rotate credentials immediately"
```

### 2.7 Refresh Token Flow

#### 2.7.1 Authorization Code Exchange with Refresh Token

```
Client → POST /api/v1/auth/token (grant_type=authorization_code, scope includes offline_access)
  ↓
Validate client credentials (client_id + client_secret hash)
  ↓
Is client.allow_refresh_tokens=true AND client.is_confidential=true?
  → No: issue access token only (no refresh token)
  → Yes: continue
  ↓
Validate authorization code (not expired, not used, not revoked, client_id matches, redirect_uri matches)
  ↓
Mark authorization code as used
  ↓
Generate access token (JWT, 60-minute expiry)
Store access token hash in access_tokens
  ↓
Generate refresh token (crypto/rand 32 bytes → base64url)
Compute token_hash = SHA-256(raw_token)
Generate token_family_id = new UUID
Store refresh_tokens record:
  { token_hash, client_id, user_id, access_token_id, token_family_id,
    previous_token_id=NULL, scope, expires_at=now()+30d }
  ↓
Write audit_log: event_type=refresh_token_issued
  ↓
Return { access_token, refresh_token, token_type, expires_in, scope }
```

#### 2.7.2 Refresh Token Rotation

```
Client → POST /api/v1/auth/token (grant_type=refresh_token)
  ↓
Validate client credentials
  ↓
Compute lookup_hash = SHA-256(presented_token)
Query refresh_tokens WHERE token_hash = lookup_hash
  ↓
Record not found?
  → Return 400 invalid_grant
  ↓
Record found AND is_revoked=true?
  → REPLAY DETECTED
  → Revoke all refresh_tokens WHERE token_family_id = record.token_family_id
  → Revoke associated access_tokens
  → Write audit_log: event_type=replay_detected, metadata={family_id, client_id, user_id}
  → Write audit_log: event_type=refresh_token_family_revoked
  → Return 400 invalid_grant (generic message — no hint about replay)
  ↓
Record found AND is_revoked=false:
  ↓
  Is token expired?
    → Revoke token; return 400 invalid_grant
  ↓
  Check RefreshTokenConfig.MaxLifetimeDays: has the family exceeded absolute max lifetime?
    → Revoke family; return 400 invalid_grant
  ↓
  Mark current token: is_revoked=true, revoked_at=now(), revoke_reason=used, used_at=now()
  ↓
  Generate new access token (JWT, 60-minute expiry)
  Store new access token hash
  ↓
  Generate new refresh token (crypto/rand 32 bytes → base64url)
  Store new refresh_tokens record:
    { token_hash, client_id, user_id, access_token_id=new, token_family_id=same,
      previous_token_id=old_record.id, scope, expires_at=now()+30d }
  ↓
  Write audit_log: event_type=refresh_token_rotated, metadata={family_id}
  ↓
  Return { access_token, refresh_token, token_type, expires_in, scope }
```

#### 2.7.3 Force Password Change at Login

```
Client → POST /api/v1/auth/token (grant_type=authorization_code)
  ↓
... (standard code validation) ...
  ↓
user.force_password_change = true?
  → Yes:
    Generate challenge_token (JWT, 5-minute expiry, claim: require=password_change)
    Return 200 { "challenge_token": "...", "requires_action": "password_change" }
    (NO access token or refresh token issued)
  → No:
    Issue access token (and refresh token if eligible)
    Return standard token response
```

### 2.8 Security Design

#### 2.8.1 Bootstrap Security

* Bootstrap features are disabled by default in production (`ENV=production`). The `ALLOW_DEFAULT_ADMIN` and `ALLOW_DEFAULT_CLIENT` flags must be explicitly set to `true` for the bootstrap to run in production.
* The plaintext password and client secret from environment variables are immediately hashed and then the references are allowed to be garbage collected; they are never assigned to any database column in plaintext form.
* Log statements in the bootstrap routines are audited with `WARN` severity to ensure operators notice the events.
* Startup fails fast (non-zero exit) on invalid bootstrap configuration to prevent silently misconfigured deployments.

#### 2.8.2 Refresh Token Security

* **Storage:** Refresh tokens are stored as `SHA-256(raw_token)`. The raw token value exists only in memory during the single token issuance transaction and in the response body over TLS.
* **Token family model:** Every rotation chain shares a `token_family_id`. On replay, the entire family is revoked atomically within a database transaction.
* **Revocation on sensitive events:** User password changes trigger revocation of all active refresh token families for that user. Administrator-initiated session revocation can target individual tokens or entire families.
* **Binding:** Refresh tokens are bound to `(client_id, user_id, token_family_id)`. A token from one client cannot be used at another client.
* **Audit integrity:** All refresh token lifecycle events are written to `audit_log` without any token material. The `metadata` JSONB column may include `family_id`, `client_id`, `user_id`, and `event_id` for correlation.
* **No logging:** Application logging code must never log raw token values or token hashes. Log statements related to token operations use only record IDs.

#### 2.8.3 Challenge Token Security

* The password-change challenge token is a separate JWT with a distinct claim (`require=password_change`). The auth middleware rejects challenge tokens for any endpoint except `POST /auth/change-password`, preventing privilege escalation through a challenge token in the `Authorization: Bearer` header.
* Challenge tokens expire in 5 minutes and are single-use (validated against a short-lived in-memory or DB state to prevent reuse).

#### 2.8.4 Account Lockout Security

* **Counter persistence:** Lockout state is stored in the `users` table, not in memory or a cache. This ensures consistency across horizontally scaled instances and survival across restarts.
* **Sliding window:** The window is reset when `last_failed_login_at` is older than `LOGIN_ATTEMPT_WINDOW_SECONDS`, preventing permanent ratcheting of the counter from old events.
* **Timing-safe response:** Locked accounts return `429 Too Many Requests` without performing password hashing, preventing timing side-channels from revealing whether the account exists.
* **No enumeration:** The `429` response for a locked account and the `401` response for wrong credentials use the same generic message; the distinction is visible only via the HTTP status code and `Retry-After` header, not in the response body.
* **Audit trail:** Both the lockout event (`account_locked`) and the unlock event (`account_unlocked`) are recorded in `audit_log`. The `metadata` field includes the source IP and email; no password material is ever written.
* **Admin unlock:** Only accounts with `is_admin=true` may call the unlock endpoint; requests are authenticated via the standard Bearer token middleware.

#### 2.8.5 Existing Security Controls (Carried Forward)

All security controls from v0.2.0 remain unchanged:

* CSRF: state-parameter validation in OAuth flows
* XSS prevention: Content-Security-Policy, HttpOnly cookies, output encoding
* SQL injection prevention: exclusive use of sqlc parameterized queries
* CORS: origin whitelist per environment
* Rate limiting: existing middleware applied to new endpoints
* Client secret hashing: SHA-256
* JWT: ES256 with private key in environment / secrets manager

### 2.9 Data Flow Diagrams

#### 2.9.1 Startup Bootstrap Flow

```
main()
  │
  ├─→ config.Load()
  │       └─ validates required env vars; returns *Config (including BootstrapConfig)
  │
  ├─→ db.Connect() + runMigrations()
  │
  ├─→ bootstrap.RunAdminBootstrap(db, cfg.Bootstrap)
  │       ├─ production guard
  │       ├─ env var presence check
  │       ├─ input validation
  │       ├─ existence check (SELECT COUNT(*) FROM users WHERE is_admin=true)
  │       ├─ hash password
  │       ├─ INSERT INTO users
  │       └─ INSERT INTO audit_log
  │
  ├─→ bootstrap.RunClientBootstrap(db, cfg.Bootstrap)
  │       ├─ production guard
  │       ├─ env var presence check
  │       ├─ input validation
  │       ├─ existence check (SELECT COUNT(*) FROM clients)
  │       ├─ hash secret
  │       ├─ INSERT INTO clients
  │       └─ INSERT INTO audit_log
  │
  └─→ httpServer.Start()
```

#### 2.9.2 Token Revocation Flow (RFC 7009)

```
Client → POST /api/v1/auth/revoke
          │
          ├─ Authenticate client (Basic Auth or Bearer)
          │
          ├─ Compute SHA-256(token)
          │
          ├─ Try lookup in refresh_tokens by token_hash
          │     ↓ found
          │     ├─ UPDATE refresh_tokens SET is_revoked=true, revoke_reason='logout' WHERE token_family_id=...
          │     └─ UPDATE access_tokens SET is_revoked=true WHERE id=refresh_token.access_token_id
          │
          ├─ Try lookup in access_tokens by token_hash (if not found in refresh_tokens)
          │     ↓ found
          │     └─ UPDATE access_tokens SET is_revoked=true
          │
          ├─ INSERT INTO audit_log (event_type per token type)
          │
          └─ Return 200 OK (always, per RFC 7009)
```

### 2.10 Error Handling

All existing error response formats and HTTP status codes from v0.2.0 are preserved.

New OAuth 2.0 error cases:

| Scenario | OAuth Error Code | HTTP Status |
|----------|-----------------|-------------|
| Refresh token not found or expired | `invalid_grant` | 400 |
| Refresh token replay detected | `invalid_grant` | 400 |
| Client not eligible for refresh tokens | `unauthorized_client` | 400 |
| `offline_access` scope rejected | `invalid_scope` | 400 |
| Revocation request unauthenticated | `invalid_client` | 401 |
| Force-password-change required | n/a — returns `requires_action` | 200 |
| Challenge token invalid or expired | `invalid_grant` | 400 |
| Account locked (too many failed attempts) | n/a — returns generic error | 429 (with `Retry-After` header) |

**Important:** Replay detection MUST NOT reveal to the caller that a replay was detected. The `invalid_grant` error is returned identically for expired, not-found, and replayed tokens to prevent oracle attacks.

### 2.11 Deployment Architecture

#### 2.11.1 Updated Environment Variable Summary

In addition to all v0.2.0 variables, deployments must configure (or consciously leave unset) the new variables listed in §2.4.2.

Kubernetes `Secret` and `ConfigMap` manifests in `k8s/` will be updated to document the new variables. Bootstrap variables are intentionally optional and should be omitted from production secrets unless a first-run bootstrap is needed.

#### 2.11.2 Production Deployment Guidance for Bootstrap

The recommended production deployment workflow for the bootstrap feature is:

1. Deploy v0.3.0 with `ALLOW_DEFAULT_ADMIN=true`, `DEFAULT_ADMIN_USERNAME`, and `DEFAULT_ADMIN_PASSWORD` set in a short-lived Kubernetes Job or init container.
2. On next startup (the main Deployment), omit these variables. The bootstrap is skipped because an admin already exists.
3. Immediately rotate the default admin password via the `change-password` flow.
4. Follow the same pattern for `ALLOW_DEFAULT_CLIENT`.

### 2.12 Monitoring and Logging

#### 2.12.1 Audit Log Integration

The `audit_log` table is the primary compliance and forensics record. High-severity events (`replay_detected`, `refresh_token_family_revoked`) should additionally emit structured log lines at `WARN` level with the `event_type` and correlation IDs (but not token material) for real-time alerting.

#### 2.12.2 Metrics Additions

New Prometheus-compatible metric labels/counters for v0.3.0 (extending existing `internal/metrics`):

| Metric | Type | Description |
|--------|------|-------------|
| `goauth_refresh_tokens_issued_total` | Counter | Refresh tokens issued |
| `goauth_refresh_tokens_rotated_total` | Counter | Successful refresh token rotations |
| `goauth_refresh_tokens_revoked_total` | Counter | Explicit revocations (by reason label) |
| `goauth_replay_detections_total` | Counter | Replay attacks detected |
| `goauth_bootstrap_events_total` | Counter | Bootstrap events by type label (admin/client) |
| `goauth_force_password_changes_total` | Counter | Force-password-change completions |
| `goauth_login_failures_total` | Counter | Failed login attempts (by reason label: `wrong_password`, `unknown_user`, `locked`) |
| `goauth_account_lockouts_total` | Counter | Accounts locked out due to exceeding the failed-attempt threshold |
| `goauth_account_unlocks_total` | Counter | Accounts unlocked (by actor label: `expired`, `admin`) |

#### 2.12.3 Alerting Recommendations

* Alert on `goauth_replay_detections_total` rate > 0 (any replay is a potential security incident).
* Alert on `goauth_bootstrap_events_total` in production environments.
* Alert on `goauth_refresh_tokens_revoked_total{reason="family_revoked"}` rate spike.
* Alert on `goauth_account_lockouts_total` rate spike (may indicate a credential-stuffing or brute-force attack).
* Alert on `goauth_login_failures_total` rate spike per IP or email across instances.

## 3. Testing Strategy

### 3.1 Unit Tests

* Bootstrap logic: admin and client creation with mocked repository, production guard enforcement, validation failures causing startup errors.
* Refresh token service: issuance, rotation, replay detection, family revocation, expiry checks.
* Challenge token: issuance, validation, rejection on wrong claim type.
* Password change: correct flow, invalid challenge token, password complexity failure.
* Audit service: event insertion, no secret material in metadata.
* Account lockout: counter increments on each failure, lockout applied at threshold, counter resets on success, sliding window resets stale counters, admin unlock clears lockout.

### 3.2 Integration Tests

* End-to-end authorization code exchange with `offline_access`: verify access token + refresh token returned.
* End-to-end token rotation: N successive rotations, verify each issues a new token.
* Replay detection: use a rotated token; verify family revocation and `invalid_grant` response.
* RFC 7009 revocation: revoke refresh token; verify subsequent use returns `invalid_grant`; verify access token also revoked.
* Bootstrap: start with empty DB and bootstrap env vars; verify admin and client created; restart with non-empty DB; verify bootstrap skipped.
* Force password change: verify challenge token returned on first login; verify full access token returned after `change-password`; verify challenge token rejected on other endpoints.
* Production guard: set `ENV=production` without opt-in; verify bootstrap skipped.
* Account lockout: submit N-1 wrong passwords, verify account still accessible; submit Nth wrong password, verify `account_locked` audit event written and subsequent attempts return `429` with `Retry-After`; verify correct password after lockout expires succeeds and counter is reset; verify admin unlock clears lockout early.

### 3.3 Security Tests

* Confirm raw token values never appear in log output (log capture in tests).
* Confirm audit log entries contain no secrets or token material.
* Confirm challenge tokens cannot be used as Bearer tokens on protected endpoints.
* Confirm replay detection triggers family-wide revocation atomically.
* Confirm bootstrap fails with a clear error on weak passwords and invalid URIs.
* Confirm `account_locked` audit events contain email and IP but no password material.
* Confirm locked accounts return `429` without performing Argon2id hashing (timing test).

## 4. Traceability

| SRS Requirement | Design Section |
|----------------|---------------|
| Default admin creation via env vars | §2.6.1, §2.4.2 |
| `force_password_change` on first login | §2.3.1, §2.7.3, §2.5.3 |
| Default client bootstrap | §2.6.2, §2.4.2 |
| Refresh token issuance | §2.7.1, §2.3.2 |
| Refresh token rotation | §2.7.2, §2.3.2 |
| Replay detection and family revocation | §2.7.2, §2.8.2 |
| RFC 7009 revocation endpoint | §2.5.2, §2.9.2 |
| Audit logging without token material | §2.3.2, §2.8.2 |
| Production opt-in flags | §2.4.2, §2.8.1 |
| Metrics for token lifecycle | §2.12.2 |
| Client manual (frontend) | §2.11 |
| Login endpoint with email/password | §2.5.3, §1.3 |
| Account lockout after failed attempts | §1.3 (Account Lockout), §2.3.1, §2.4.2, §2.5.3, §2.5.6, §2.8.4 |
