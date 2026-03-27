# Execution Plan - v0.3.0

## Document Information

| Field | Value |
|-------|-------|
| **Version** | 0.3.0 |
| **Created** | March 26, 2026 |
| **Based on** | System Design Document v0.3.0 / SRS v0.3.0 |
| **Project** | Goauth Server |

## 1. Overview

This document defines the implementation tasks for v0.3.0. The release adds four capability areas on top of v0.2.0:

1. **Default Admin & Client Bootstrap** — environment-driven first-run account creation.
2. **Account Lockout** — sliding-window failed-attempt tracking with configurable thresholds.
3. **Force Password Change** — challenge-token flow gating access tokens for flagged accounts.
4. **Refresh Token System** — rotate-on-use refresh tokens with replay detection and RFC 7009 revocation.

Cross-cutting concerns (audit logging, configuration, SHA-256 client-secret migration) are treated as foundational tasks that unblock the features above.

### Dependency Order

```
T1 (DB Schema)
  └─ T2 (Config)
       ├─ T3 (Audit Service)         ← required by T4, T5, T6, T7
       │    ├─ T4 (Client Secret)
       │    ├─ T5 (Bootstrap)
       │    ├─ T6 (Account Lockout)
       │    ├─ T7 (Force PW Change)
       │    └─ T8 (Refresh Tokens)
       └─────────────────────────────── T9 (Tests)
```

## 2. Tasks

### Task 1 — Database Schema, Queries, and Repository

**Dependencies:** None  
**Blocks:** All other tasks

#### Sub-task 1.1 — Migration: extend `users` table

Create the migration pair:
```
migrate create -ext sql -dir ./db/migrations add_lockout_force_password_to_users
```

*Up:* `ALTER TABLE users ADD COLUMN` for each new column:
- `password_hash TEXT` — nullable; stores Argon2id hash for local-auth accounts.
- `force_password_change BOOLEAN NOT NULL DEFAULT false`
- `failed_login_attempts INTEGER NOT NULL DEFAULT 0`
- `last_failed_login_at TIMESTAMPTZ` — nullable
- `locked_until TIMESTAMPTZ` — nullable

Create index `idx_users_locked_until ON users(locked_until)` (supports lock-expiry queries).

*Down:* `DROP INDEX` then `ALTER TABLE users DROP COLUMN` for all five columns.

**Acceptance Criteria:**
- [x] Up migration applies cleanly on top of existing v0.2.0 schema
- [x] Down migration restores the table to its previous state
- [x] Column defaults match specification

#### Sub-task 1.2 — Migration: extend `clients` table

Create the migration pair:
```
migrate create -ext sql -dir ./db/migrations add_confidential_refresh_tokens_to_clients
```

*Up:*
```sql
ALTER TABLE clients
  ADD COLUMN is_confidential BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN allow_refresh_tokens BOOLEAN NOT NULL DEFAULT false;
```

*Down:* `ALTER TABLE clients DROP COLUMN` for both columns.

**Acceptance Criteria:**
- [x] Up and down apply cleanly
- [x] Existing client rows default to `is_confidential=true`, `allow_refresh_tokens=false`

#### Sub-task 1.3 — Migration: create `refresh_tokens` table

Create the migration pair:
```
migrate create -ext sql -dir ./db/migrations create_refresh_tokens_table
```

*Up:* Full `CREATE TABLE refresh_tokens (...)` per System Design §2.3.2 including all columns, foreign keys (`clients(id) ON DELETE CASCADE`, `users(id) ON DELETE CASCADE`, `access_tokens(id) ON DELETE SET NULL`, self-ref `refresh_tokens(id) ON DELETE SET NULL`), and all six indexes.

*Down:* `DROP TABLE IF EXISTS refresh_tokens CASCADE`.

**Acceptance Criteria:**
- [x] All columns, constraints, and indexes created as specified
- [x] Foreign key referential integrity enforced (test with an insert + parent delete)
- [x] Migration and rollback succeed

#### Sub-task 1.4 — Migration: create `audit_log` table

Create the migration pair:
```
migrate create -ext sql -dir ./db/migrations create_audit_log_table
```

*Up:* `CREATE TABLE audit_log (...)` per System Design §2.3.2 — append-only; no `updated_at`; four indexes on `event_type`, `user_id`, `client_id`, `created_at`.

*Down:* `DROP TABLE IF EXISTS audit_log CASCADE`.

**Acceptance Criteria:**
- [x] Table has no `updated_at` trigger (append-only)
- [x] All four indexes created
- [x] Migration and rollback succeed

#### Sub-task 1.5 — SQL queries: `db/queries/users.sql`

Add the following named queries to `users.sql`:

| Query | Purpose |
|-------|---------|
| `GetUserByEmailForAuth` | Fetch user including `password_hash`, `force_password_change`, `failed_login_attempts`, `last_failed_login_at`, `locked_until` |
| `UpdatePasswordHash` | Set `password_hash` for a user by ID |
| `SetForcePasswordChange` | Update `force_password_change` flag by user ID |
| `IncrementFailedLoginAttempts` | `+1` on `failed_login_attempts`, set `last_failed_login_at = now()` |
| `LockUserAccount` | Set `locked_until = $2` for user ID |
| `ResetLoginAttempts` | Zero out `failed_login_attempts`, `last_failed_login_at`, `locked_until` |
| `UnlockUserAccount` | Set `locked_until = NULL` for user ID |
| `CountAdminUsers` | `SELECT COUNT(*) FROM users WHERE is_admin = true` |

**Acceptance Criteria:**
- [x] All queries compile with `sqlc vet`
- [x] Parameter and result types match column definitions

#### Sub-task 1.6 — SQL queries: `db/queries/clients.sql`

Update `CreateClient` and `UpdateClient` queries to include `is_confidential` and `allow_refresh_tokens` columns in both the `INSERT`/`UPDATE` statements and result rows.

**Acceptance Criteria:**
- [x] `CreateClient` inserts all new columns
- [x] `UpdateClient` can mutate all new columns

#### Sub-task 1.7 — SQL queries: `db/queries/refresh_tokens.sql` (new file)

Create the file with all nine named queries:

| Query | Purpose |
|-------|---------|
| `CreateRefreshToken` | Insert a new token record |
| `GetRefreshTokenByHash` | Lookup by `token_hash` (primary lookup path) |
| `GetRefreshTokenByID` | Lookup by `id` |
| `ListRefreshTokensByUser` | Paginated list for admin/session views |
| `CountRefreshTokensByUser` | Count for pagination |
| `RevokeRefreshToken` | Set `is_revoked=true`, `revoked_at`, `revoke_reason` for a single token by ID |
| `RevokeRefreshTokenFamily` | Set `is_revoked=true` for all tokens sharing a `token_family_id` |
| `MarkRefreshTokenUsed` | Set `used_at`, `is_revoked=true`, `revoke_reason='used'` |
| `DeleteExpiredRefreshTokens` | `DELETE … WHERE expires_at < now()` |

**Acceptance Criteria:**
- [x] All queries compile with `sqlc vet`
- [x] `RevokeRefreshTokenFamily` updates all rows in the family in one statement

#### Sub-task 1.8 — SQL queries: `db/queries/audit_log.sql` (new file)

Create the file with three named queries:

| Query | Purpose |
|-------|---------|
| `CreateAuditLogEntry` | Insert one audit row (no `RETURNING` needed beyond `id`) |
| `ListAuditLogEntries` | Paginated list; filter by `event_type`, `user_id`, `client_id` (all optional) |
| `CountAuditLogEntries` | Count with same optional filters |

**Acceptance Criteria:**
- [x] `CreateAuditLogEntry` parameter type accepts `metadata JSONB` correctly
- [x] Queries compile with `sqlc vet`

#### Sub-task 1.9 — Run `sqlc generate` and reconcile output

1. Run `sqlc generate` from the repository root.
2. Review all changed files in `internal/repository/` for correctness.
3. Ensure `internal/repository/querier.go` interface includes all new methods.

**Acceptance Criteria:**
- [x] `sqlc generate` exits 0 with no warnings
- [x] Generated structs for `RefreshToken` and `AuditLog` reflect all columns

#### Sub-task 1.10 — Update mock `Querier`

In `internal/testutil/mocks/querier.go`, add stub implementations for every new method added to the `Querier` interface (all queries from 1.5–1.8).

**Acceptance Criteria:**
- [x] `go build ./...` passes
- [x] Mock satisfies the `Querier` interface at compile time

#### Sub-task 1.11 — Regenerate `db/schema/schema.sql`

Run `db/scripts/dump_schema.sh` against a migrated local database to refresh the canonical schema dump.

**Acceptance Criteria:**
- [x] `db/schema/schema.sql` reflects all four new migrations
- [x] File committed alongside the migration files

### Task 2 — Configuration

**Dependencies:** None  
**Blocks:** T3, T5, T6, T7, T8

#### Sub-task 2.1 — Add `BootstrapConfig` struct

In `internal/config/config.go`, define:

```go
type BootstrapConfig struct {
    AllowDefaultAdmin         bool   // ALLOW_DEFAULT_ADMIN (default: false)
    DefaultAdminEmail         string // DEFAULT_ADMIN_EMAIL
    DefaultAdminPassword      string // DEFAULT_ADMIN_PASSWORD
    AllowDefaultClient        bool   // ALLOW_DEFAULT_CLIENT (default: false)
    DefaultClientID           string // DEFAULT_CLIENT_ID
    DefaultClientSecret       string // DEFAULT_CLIENT_SECRET
    DefaultClientRedirectURIs string // DEFAULT_CLIENT_REDIRECT_URIS (comma-separated)
    DefaultClientName         string // DEFAULT_CLIENT_NAME (default: "GoAuth Client")
    DefaultClientConfidential bool   // DEFAULT_CLIENT_CONFIDENTIAL (default: true)
}
```

Parse all nine variables in `Load()`. Apply defaults (`DefaultClientName="GoAuth Client"`, `DefaultClientConfidential=true`).

**Acceptance Criteria:**
- [ ] All nine variables read from environment
- [ ] String booleans (`"true"`/`"false"`) parsed correctly
- [ ] Defaults applied when variables are unset

#### Sub-task 2.2 — Add `RefreshTokenConfig` struct

```go
type RefreshTokenConfig struct {
    ExpiryDays      int  // REFRESH_TOKEN_EXPIRY_DAYS (default: 30)
    RotationEnabled bool // REFRESH_TOKEN_ROTATION_ENABLED (default: true)
    MaxLifetimeDays int  // REFRESH_TOKEN_MAX_LIFETIME_DAYS (default: 90)
}
```

Parse and apply defaults in `Load()`.

**Acceptance Criteria:**
- [ ] Integer variables parsed with `strconv.Atoi`; invalid values return an error from `Load()`
- [ ] Defaults applied when variables are unset

#### Sub-task 2.3 — Add `LockoutConfig` struct

```go
type LockoutConfig struct {
    MaxAttempts     int // LOGIN_MAX_ATTEMPTS (default: 5)
    WindowSeconds   int // LOGIN_ATTEMPT_WINDOW_SECONDS (default: 600)
    DurationSeconds int // LOGIN_LOCKOUT_DURATION_SECONDS (default: 900)
}
```

Parse and apply defaults in `Load()`.

**Acceptance Criteria:**
- [ ] All three integer variables parsed; zero/negative values return a validation error
- [ ] Defaults applied when variables are unset

#### Sub-task 2.4 — Wire new structs into top-level `Config`

Add `Bootstrap BootstrapConfig`, `RefreshToken RefreshTokenConfig`, and `Lockout LockoutConfig` fields to the top-level `Config` struct. Populate them in `Load()` after all existing fields.

**Acceptance Criteria:**
- [ ] `Config` struct compiles
- [ ] All existing call sites that read `cfg.Server`, `cfg.DB`, etc. are unaffected

#### Sub-task 2.5 — Early validation in `Load()`

After parsing `BootstrapConfig`, add validation:
- If `DefaultAdminEmail` is non-empty, it must be a valid email address (use `net/mail.ParseAddress`).
- If `DefaultAdminPassword` is non-empty and `DefaultAdminEmail` is also non-empty, apply the shared password policy (import `internal/util/password`; this creates a compile-time dependency — stub the call if the password package has not been written yet and revisit during T7).
- If `DefaultClientRedirectURIs` is non-empty, each URI must parse without error.

**Acceptance Criteria:**
- [ ] Invalid email in `DEFAULT_ADMIN_EMAIL` causes `Load()` to return an error
- [ ] Invalid redirect URI in `DEFAULT_CLIENT_REDIRECT_URIS` causes `Load()` to return an error

#### Sub-task 2.6 — Update `config_test.go`

Add test cases covering:
- All new environment variables with their defaults.
- `BootstrapConfig` parsing with valid and invalid email / redirect URIs.
- `LockoutConfig` and `RefreshTokenConfig` integer parsing (valid, zero, negative, non-numeric).
- Verify existing tests still pass.

**Acceptance Criteria:**
- [ ] New test cases added for all three new structs
- [ ] `go test ./internal/config/...` passes

### Task 3 — Audit Log Service

**Dependencies:** T1, T2  
**Blocks:** T4 (partial), T5, T6, T7, T8

#### Sub-task 3.1 — Create `internal/service/audit/events.go`

Define a `EventType` string type and all 15 constants from System Design §2.3.2:

```go
type EventType string

const (
    EventDefaultAdminCreated          EventType = "default_admin_created"
    EventDefaultClientCreated         EventType = "default_client_created"
    EventUserPasswordChanged          EventType = "user_password_changed"
    EventForcePasswordChangeSatisfied EventType = "force_password_change_satisfied"
    EventRefreshTokenIssued           EventType = "refresh_token_issued"
    EventRefreshTokenRotated          EventType = "refresh_token_rotated"
    EventRefreshTokenRevoked          EventType = "refresh_token_revoked"
    EventRefreshTokenFamilyRevoked    EventType = "refresh_token_family_revoked"
    EventReplayDetected               EventType = "replay_detected"
    EventAccessTokenRevoked           EventType = "access_token_revoked"
    EventAdminSessionRevoked          EventType = "admin_session_revoked"
    EventLoginFailed                  EventType = "login_failed"
    EventAccountLocked                EventType = "account_locked"
    EventAccountUnlocked              EventType = "account_unlocked"
    EventClientSecretRegenerated      EventType = "client_secret_regenerated"
)
```

**Acceptance Criteria:**
- [ ] All 15 constants defined using the exact string values from System Design
- [ ] File compiles with no imports needed (pure type definitions)

#### Sub-task 3.2 — Create `internal/service/audit/audit.go`

Define `AuditEntry` and `Service`:

```go
type AuditEntry struct {
    EventType EventType
    UserID    *uuid.UUID
    ClientID  *uuid.UUID
    ActorID   *uuid.UUID
    IPAddress *string
    Metadata  map[string]any  // serialised to JSONB; must never contain secrets
}

type Service struct { repo repository.Querier }

func New(repo repository.Querier) *Service
func (s *Service) LogEvent(ctx context.Context, entry AuditEntry) error
```

`LogEvent` marshals `Metadata` to `[]byte` (JSON) and calls `s.repo.CreateAuditLogEntry(...)`. On error it logs at `WARN` level but does **not** panic — audit failures must never block the primary flow.

**Acceptance Criteria:**
- [ ] `LogEvent` does not return an error when the DB call succeeds
- [ ] Non-nil DB errors are returned to caller (caller decides to log/ignore)
- [ ] `Metadata` marshalling failure returns a wrapped error immediately without calling DB

#### Sub-task 3.3 — Unit tests for the audit package

Write `internal/service/audit/audit_test.go` using the mock `Querier`:
- Happy path: `LogEvent` calls `CreateAuditLogEntry` with correct params.
- DB error: returned error is propagated.
- Nil optional fields: `UserID`, `ClientID`, etc. map to SQL `NULL` correctly.
- Empty `Metadata`: marshals to `{}` not `null`.

**Acceptance Criteria:**
- [ ] All four cases covered
- [ ] `go test ./internal/service/audit/...` passes

### Task 4 — Client Secret Hashing Migration (bcrypt → SHA-256)

**Dependencies:** T1, T3  
**Blocks:** T5 (bootstrap creates a client)

Per SRS RC-001: client secrets are now hashed with SHA-256 instead of bcrypt.

#### Sub-task 4.1 — Replace hashing in `CreateClient`

In `internal/service/client/client.go`, replace the `bcrypt.GenerateFromPassword` call with:

```go
h := sha256.Sum256([]byte(plainSecret))
hashedSecret := hex.EncodeToString(h[:])
```

Remove the `golang.org/x/crypto/bcrypt` import; add `crypto/sha256` and `encoding/hex` (both stdlib).

**Acceptance Criteria:**
- [ ] `CreateClient` persists `hex(sha256(secret))` in the database
- [ ] No bcrypt import remains in the file

#### Sub-task 4.2 — Replace hashing in `RegenerateClientSecret`

Apply the same SHA-256 hashing pattern in `RegenerateClientSecret`. After successful persistence, call `auditSvc.LogEvent(ctx, AuditEntry{EventType: EventClientSecretRegenerated, ClientID: &clientID})` — this requires injecting the `audit.Service` into the client `Service` struct.

**Acceptance Criteria:**
- [ ] Regenerated secret stored as SHA-256 hex hash
- [ ] Audit event written on every successful regeneration

#### Sub-task 4.3 — Update `ValidateClientSecret`

Replace `bcrypt.CompareHashAndPassword` with:

```go
h := sha256.Sum256([]byte(suppliedSecret))
supplied := hex.EncodeToString(h[:])
return subtle.ConstantTimeCompare([]byte(storedHash), []byte(supplied)) == 1
```

Import `crypto/subtle` (stdlib).

**Acceptance Criteria:**
- [ ] Comparison is constant-time (no early exit on first differing byte)
- [ ] Returns `false` for a mismatched secret; `true` for a matching one

#### Sub-task 4.4 — Update existing client service unit tests

In `internal/service/client/client_test.go` (and any related test files):
- Replace test helper calls that set up bcrypt-hashed secrets with SHA-256 hex values.
- Add a test asserting `ValidateClientSecret` rejects a bcrypt-format hash string.

**Acceptance Criteria:**
- [ ] `go test ./internal/service/client/...` passes
- [ ] No test still sets up bcrypt-hashed secrets as "correct" values

#### Sub-task 4.5 — Document the breaking change

Add a "Breaking Changes" entry to `RELEASE_NOTES.md` under the v0.3.0 section:
- State that existing client secrets hashed with bcrypt are no longer valid after upgrade.
- Instruct operators to regenerate all client secrets using `POST /api/v1/admin/clients/{id}/secret` after migration.

**Acceptance Criteria:**
- [ ] `RELEASE_NOTES.md` entry present and accurate
- [ ] Entry references the `RegenerateClientSecret` endpoint

### Task 5 — Default Admin & Client Bootstrap

**Dependencies:** T1, T2, T3, T4  
**Blocks:** nothing (terminal feature task)

#### Sub-task 5.1 — Create `internal/app/auth-server/bootstrap.go` skeleton

Create the file with package declaration, imports, and the two exported function signatures:

```go
func BootstrapDefaultAdmin(ctx context.Context, cfg config.BootstrapConfig, serverCfg config.ServerConfig, repo repository.Querier, auditSvc *audit.Service) error
func BootstrapDefaultClient(ctx context.Context, cfg config.BootstrapConfig, serverCfg config.ServerConfig, repo repository.Querier, auditSvc *audit.Service) error
```

Both functions return `nil` immediately (stubs); later sub-tasks fill in the logic.

**Acceptance Criteria:**
- [ ] File compiles with no errors
- [ ] Function signatures match what `server.go` will call

#### Sub-task 5.2 — Implement `BootstrapDefaultAdmin`

Fill in the function body:

1. If `serverCfg.Env == "production"` AND `!cfg.AllowDefaultAdmin` → `return nil`.
2. If `cfg.DefaultAdminEmail == ""` OR `cfg.DefaultAdminPassword == ""` → `return nil`.
3. Validate email (`net/mail.ParseAddress`) and password complexity (`password.Validate`). Return descriptive `error` on failure.
4. `count, err := repo.CountAdminUsers(ctx)`; if `count > 0` → `return nil`.
5. Hash password with Argon2id (reuse existing `hashPassword` helper or equivalent).
6. `repo.CreateUser(ctx, ...)` with `IsAdmin=true`, `ForcePasswordChange=true`, `PasswordHash=hash`.
7. `auditSvc.LogEvent(ctx, AuditEntry{EventType: audit.EventDefaultAdminCreated, UserID: &newUser.ID, Metadata: map[string]any{"email": cfg.DefaultAdminEmail}})`.
8. `log.Warn("Default admin account created — rotate credentials immediately", "email", cfg.DefaultAdminEmail)`.

**Acceptance Criteria:**
- [ ] Admin not created when `ENV=production` and `ALLOW_DEFAULT_ADMIN=false`
- [ ] Admin not created when one already exists (`CountAdminUsers > 0`)
- [ ] `force_password_change=true` in persisted record
- [ ] Audit entry written without password value
- [ ] Invalid email or weak password returns an error (does not create the user)

#### Sub-task 5.3 — Implement `BootstrapDefaultClient`

Fill in the function body:

1. If `serverCfg.Env == "production"` AND `!cfg.AllowDefaultClient` → `return nil`.
2. If `cfg.DefaultClientID == ""` OR `cfg.DefaultClientSecret == ""` → `return nil`.
3. Parse and validate redirect URIs from `cfg.DefaultClientRedirectURIs` (comma-split, validate each with `client.ValidateRedirectURIs`). Return descriptive error on failure.
4. `count, err := repo.CountClients(ctx)`; if `count > 0` → `return nil`.
5. Hash client secret with SHA-256 (`crypto/sha256`).
6. `repo.CreateClient(ctx, ...)` with all metadata fields; `IsConfidential = cfg.DefaultClientConfidential`.
7. `auditSvc.LogEvent(ctx, AuditEntry{EventType: audit.EventDefaultClientCreated, ClientID: &newClient.ID, Metadata: map[string]any{"client_id": cfg.DefaultClientID, "name": cfg.DefaultClientName}})`.
8. `log.Warn("Default client created — rotate credentials immediately", "client_id", cfg.DefaultClientID)`.

**Acceptance Criteria:**
- [ ] Client not created when `ENV=production` and `ALLOW_DEFAULT_CLIENT=false`
- [ ] Client not created when clients already exist
- [ ] Plaintext secret never in logs or audit metadata
- [ ] Invalid redirect URI returns a descriptive error

#### Sub-task 5.4 — Wire bootstrap into `server.go` startup sequence

In `internal/app/auth-server/server.go`, after the database migrations step and before `gin.Engine` creation:

```go
if err := BootstrapDefaultAdmin(ctx, cfg.Bootstrap, cfg.Server, repo, auditSvc); err != nil {
    return nil, fmt.Errorf("bootstrap default admin: %w", err)
}
if err := BootstrapDefaultClient(ctx, cfg.Bootstrap, cfg.Server, repo, auditSvc); err != nil {
    return nil, fmt.Errorf("bootstrap default client: %w", err)
}
```

Errors must propagate to `main()` which calls `log.Fatal` / `os.Exit(1)`.

**Acceptance Criteria:**
- [ ] Bootstrap functions called in the correct position in startup sequence
- [ ] Startup aborts on non-nil error with a readable message

#### Sub-task 5.5 — Unit tests for bootstrap functions

Write `internal/app/auth-server/bootstrap_test.go` using the mock `Querier`:

| Test case | Expected behaviour |
|-----------|-------------------|
| `AllowDefaultAdmin=false`, `ENV=production` | Returns nil, no DB calls |
| Admin already exists (`CountAdminUsers=1`) | Returns nil, no `CreateUser` call |
| Invalid email | Returns error, no `CreateUser` call |
| Weak password | Returns error, no `CreateUser` call |
| Valid inputs, no existing admin | Creates user, writes audit, emits warn log |
| `AllowDefaultClient=false`, `ENV=production` | Returns nil, no DB calls |
| Client already exists (`CountClients=1`) | Returns nil, no `CreateClient` call |
| Invalid redirect URI | Returns error, no `CreateClient` call |
| Valid inputs, no existing clients | Creates client, writes audit, emits warn log |

**Acceptance Criteria:**
- [ ] All nine cases covered
- [ ] `go test ./internal/app/auth-server/...` passes

### Task 6 — Account Lockout

**Dependencies:** T1, T2, T3  
**Blocks:** nothing (terminal feature task)

#### Sub-task 6.1 — Add `VerifyCredentials` function to auth service

Add a new method to `internal/service/auth/auth.go` (or a new `login.go` file in the same package):

```go
type VerifyCredentialsResult struct {
    User                *repository.User
    ForcePasswordChange bool
    LockedUntil         *time.Time
}

func (s *Service) VerifyCredentials(ctx context.Context, email, password, sourceIP string) (*VerifyCredentialsResult, error)
```

Add sentinel errors:
```go
var ErrAccountLocked      = errors.New("account locked")
var ErrInvalidCredentials = errors.New("invalid credentials")
```

**Acceptance Criteria:**
- [ ] Function signature compiles
- [ ] Sentinel errors declared at package level

#### Sub-task 6.2 — Implement lockout check

Inside `VerifyCredentials`:

1. `user, err := s.repo.GetUserByEmailForAuth(ctx, email)`; on row-not-found return `ErrInvalidCredentials` (do not distinguish unknown email).
2. If `user.LockedUntil != nil` AND `user.LockedUntil.After(time.Now())` → return `ErrAccountLocked` with `LockedUntil` populated in result.
3. If `user.LockedUntil != nil` AND it is in the past → `s.repo.ResetLoginAttempts(ctx, user.ID)` to clear stale lockout, then continue.

**Acceptance Criteria:**
- [ ] Active lockout returns `ErrAccountLocked` immediately without password check
- [ ] Expired lockout is cleared before proceeding

#### Sub-task 6.3 — Implement password verification and failed-attempt tracking

Continuing in `VerifyCredentials` after the lockout check:

4. Verify `user.PasswordHash` with Argon2id (`argon2.IDKey` or equivalent). On failure:
   a. `s.repo.IncrementFailedLoginAttempts(ctx, user.ID)` — DB function sets `last_failed_login_at = now()`.
   b. Re-read `failed_login_attempts` and `last_failed_login_at` from the updated row.
   c. Determine if the attempts fall within `WindowSeconds` (compare `last_failed_login_at` to `now() - WindowSeconds`).
   d. If `attempts >= s.cfg.Lockout.MaxAttempts` within window:
      - Compute `lockedUntil = time.Now().Add(DurationSeconds)`.
      - `s.repo.LockUserAccount(ctx, user.ID, lockedUntil)`.
      - `s.auditSvc.LogEvent(ctx, AuditEntry{EventType: EventAccountLocked, UserID: &user.ID, IPAddress: &sourceIP, Metadata: {"email": email}})`.
      - Return `ErrAccountLocked`.
   e. `s.auditSvc.LogEvent(ctx, AuditEntry{EventType: EventLoginFailed, UserID: &user.ID, IPAddress: &sourceIP, Metadata: {"email": email}})`.
   f. Return `ErrInvalidCredentials`.
5. On success: `s.repo.ResetLoginAttempts(ctx, user.ID)`, `s.repo.UpdateLastLogin(ctx, user.ID)`. Return result with `User` populated.

**Acceptance Criteria:**
- [ ] `failed_login_attempts` incremented on each failure
- [ ] `account_locked` audit event written exactly once (at transition), not on every failure
- [ ] `login_failed` audit event written on each non-locking failure
- [ ] Successful login resets attempt counter

#### Sub-task 6.4 — Create `POST /api/v1/auth/login` handler and route

`POST /api/v1/auth/login` does not exist yet — v0.2.0 uses an OAuth provider-based web flow only. Create a new handler and register its route.

**Handler:** Create `internal/transport/http/api/v1/handler/login.go` (or add `Login` to the existing auth handler file).

Request (JSON):
```json
{ "email": "user@example.com", "password": "<plaintext>" }
```

Handler logic:
- Validate that `email` is non-empty and well-formed (`net/mail.ParseAddress`); return `400` on failure.
- Extract source IP: check `X-Forwarded-For` header first; fall back to `c.Request.RemoteAddr`.
- Call `authSvc.VerifyCredentials(ctx, req.Email, req.Password, sourceIP)`.
- On `ErrAccountLocked`:
  - Set `Retry-After` header to `lockedUntil.UTC().Format(http.TimeFormat)`.
  - Return `429 Too Many Requests` with `{"error": "account_locked", "retry_after": "<RFC 1123>"}`.
- On `ErrInvalidCredentials`: return `401 Unauthorized` with generic `{"error": "invalid_credentials"}`.
- On success: continue to force-password-change branching (T7.4) or issue access token.

**Route registration:** In `internal/transport/http/api/v1/router.go`, add to the `publicAuth` group (alongside `POST /token`):

```go
publicAuth.POST("/login", middleware.RateLimitByIP(middleware.LoginRatePerMin, middleware.LoginRatePerMin), h.Login)
```

**Acceptance Criteria:**
- [ ] Route `POST /api/v1/auth/login` is newly created and reachable (does not exist in v0.2.0)
- [ ] `400` returned for malformed or missing email
- [ ] `429` response includes `Retry-After` header with correct UTC timestamp
- [ ] `401` response does not distinguish wrong password from unknown email
- [ ] Source IP extracted and passed through correctly
- [ ] Rate limiting applied (reuse existing `LoginRatePerMin` constant or define one)

#### Sub-task 6.5 — Implement admin unlock handler

Create `internal/transport/http/api/v1/handler/admin_lockout.go` (or add to existing admin user handler):

```
DELETE /api/v1/admin/users/:id/lockout
```

- Gated by existing `AdminRequired` middleware.
- Parse `:id` as UUID; return `404` if invalid.
- `repo.UnlockUserAccount(ctx, userID)`; return `404` if user not found.
- `auditSvc.LogEvent(ctx, AuditEntry{EventType: EventAccountUnlocked, UserID: &userID, ActorID: &adminID, Metadata: {"reason": "admin_unlock"}})`.
- Return `204 No Content`.

**Acceptance Criteria:**
- [ ] Non-admin JWT returns `403`
- [ ] Unknown user ID returns `404`
- [ ] Valid request clears `locked_until` and writes `account_unlocked` audit entry

#### Sub-task 6.6 — Register new admin route

In `internal/transport/http/api/router.go` (or wherever admin routes are registered), add the `DELETE /api/v1/admin/users/:id/lockout` route pointing to the new handler.

**Acceptance Criteria:**
- [ ] Route registered and reachable
- [ ] Existing admin routes unaffected

### Task 7 — Force Password Change

**Dependencies:** T1, T3  
**Blocks:** nothing (terminal feature task)

#### Sub-task 7.1 — Create `internal/util/password/validator.go`

Define `Validate(password, userEmail string) error` enforcing the full SRS password policy:

| Rule | Check |
|------|-------|
| Minimum length 12 | `len([]rune(password)) >= 12` |
| At least 1 uppercase (A–Z) | regexp or `unicode.IsUpper` scan |
| At least 1 lowercase (a–z) | `unicode.IsLower` scan |
| At least 1 digit (0–9) | `unicode.IsDigit` scan |
| At least 1 special character | match against allowed special charset |
| Not in deny-list | case-insensitive lookup in embedded OWASP/NIST top-1000 list |
| Does not contain email substring | `strings.Contains(strings.ToLower(password), localPart)` |

Embed the deny-list as a `//go:embed` file (`internal/util/password/denylist.txt`) so it has no runtime external dependency.

**Acceptance Criteria:**
- [ ] Each rule independently blocks non-compliant passwords
- [ ] Deny-list file present and embedded at compile time
- [ ] `Validate` returns a descriptive multi-error (or single error naming the failed rule)

#### Sub-task 7.2 — Unit tests for `validator.go`

Write `internal/util/password/validator_test.go` with table-driven tests covering:
- Password shorter than 12 characters → error
- Password missing uppercase → error
- Password missing lowercase → error
- Password missing digit → error
- Password missing special character → error
- Password on deny-list (e.g., `"Password1!"`) → error
- Password containing email local-part → error
- Valid password meeting all rules → nil

**Acceptance Criteria:**
- [ ] All eight cases pass
- [ ] `go test ./internal/util/password/...` passes

#### Sub-task 7.3 — Add challenge token helpers to auth service

Add to `internal/service/auth/token.go`:

```go
func (s *Service) GenerateChallengeToken(userID uuid.UUID) (string, error)
func (s *Service) ValidateChallengeToken(tokenStr string) (uuid.UUID, error)
```

Implementation:
- Use `github.com/golang-jwt/jwt/v5` with `HS256` signing method and the `SessionSigningKey`.
- Claims: `sub = userID.String()`, `typ = "password_change"`, `exp = now + 15min`.
- `ValidateChallengeToken` must reject tokens with `typ != "password_change"` and expired tokens.
- Tokens are single-use conceptually — the handler (7.5) must not accept the same token after the password is changed (enforced by `force_password_change=false` check: if the DB flag is already false when the challenge arrives, reject with `409 Conflict`).

**Acceptance Criteria:**
- [ ] Generated token parses correctly in `ValidateChallengeToken`
- [ ] Expired token returns an error
- [ ] Token with wrong `typ` returns an error

#### Sub-task 7.4 — Update login handler for `force_password_change` branch

In the login handler (after calling `VerifyCredentials` from T6):

- If `result.ForcePasswordChange == true`:
  - Call `authSvc.GenerateChallengeToken(result.User.ID)`.
  - Return `200 OK` with `{"challenge_token": "<token>", "require": "password_change"}`.
  - Do **not** issue an access token or refresh token.
- If `false`: proceed with normal access token issuance.

**Acceptance Criteria:**
- [ ] Flagged user receives challenge token response, not an access token
- [ ] Normal user login flow unchanged

#### Sub-task 7.5 — Implement `POST /api/v1/auth/change-password` handler

Create `internal/transport/http/api/v1/handler/change_password.go`.

Request (JSON):
```json
{ "challenge_token": "...", "new_password": "..." }
```

Handler logic:
1. `authSvc.ValidateChallengeToken(req.ChallengeToken)` → extract `userID`; `400` on error.
2. Fetch user by ID; if `force_password_change == false` → `409 Conflict` (token already consumed).
3. `password.Validate(req.NewPassword, user.Email)` → `400` with validation error message on failure.
4. Hash new password with Argon2id.
5. `repo.UpdatePasswordHash(ctx, userID, hash)`.
6. `repo.SetForcePasswordChange(ctx, userID, false)`.
7. Call refresh token revocation stub (concrete implementation wired in T8.6).
8. `auditSvc.LogEvent(EventUserPasswordChanged, ...)`.
9. `auditSvc.LogEvent(EventForcePasswordChangeSatisfied, ...)`.
10. Issue a new access token; return `200` with token response.

**Acceptance Criteria:**
- [ ] Invalid challenge token → `400`
- [ ] Already-cleared `force_password_change` flag → `409`
- [ ] Weak new password → `400` with policy description
- [ ] Success → `force_password_change=false` in DB, both audit entries written, access token returned

#### Sub-task 7.6 — Register `change-password` route

In the API router, add `POST /api/v1/auth/change-password` (no auth middleware required — the challenge token is the credential).

**Acceptance Criteria:**
- [ ] Route registered and reachable
- [ ] Endpoint does not appear in JWT-protected route group

### Task 8 — Refresh Token System

**Dependencies:** T1, T2, T3  
**Blocks:** nothing (terminal feature task)

This task covers the full lifecycle: issuance, rotation, replay detection, and revocation.

#### Sub-task 8.1 — Token generation helpers (`internal/service/auth/refresh.go`)

Create `internal/service/auth/refresh.go` with package-private helpers:

```go
// generateRefreshTokenValue returns a cryptographically random 32-byte base64url string.
func generateRefreshTokenValue() (string, error)

// hashRefreshToken returns hex(sha256(value)).
func hashRefreshToken(value string) string
```

**Acceptance Criteria:**
- [ ] `generateRefreshTokenValue` uses `crypto/rand`; panics or errors if entropy unavailable
- [ ] `hashRefreshToken` output is deterministic and constant-time-comparable
- [ ] Unit tests verify that two distinct calls produce different values

#### Sub-task 8.2 — Extend `ExchangeAuthorizationCode` to issue refresh tokens

In `internal/service/auth/authorization.go`, after the access token is stored:

1. Check `client.AllowRefreshTokens == true` AND the granted scopes contain `"offline_access"`.
2. If yes:
   a. `tokenValue, _ := generateRefreshTokenValue()`
   b. `tokenHash := hashRefreshToken(tokenValue)`
   c. `familyID := uuid.New()`
   d. Compute `expiresAt = now.Add(cfg.RefreshToken.ExpiryDays * 24h)`.
   e. `repo.CreateRefreshToken(ctx, CreateRefreshTokenParams{TokenHash: tokenHash, FamilyID: familyID, ClientID: client.ID, UserID: user.ID, AccessTokenID: &accessToken.ID, Scope: grantedScope, ExpiresAt: expiresAt})`.
   f. `auditSvc.LogEvent(ctx, AuditEntry{EventType: EventRefreshTokenIssued, UserID: &user.ID, ClientID: &client.ID, Metadata: {"scope": grantedScope, "expires_at": expiresAt}})`.
3. Return `tokenValue` in the response `refresh_token` field (or empty string if not issued).

**Acceptance Criteria:**
- [ ] Refresh token issued only when both conditions are met
- [ ] Token value in response != token hash in DB
- [ ] Audit entry written without token value

#### Sub-task 8.3 — Add `grant_type=refresh_token` branch to token handler

In the token endpoint handler (or create `internal/service/auth/rotation.go` for the service logic):

**Service method:**
```go
func (s *Service) RotateRefreshToken(ctx context.Context, rawToken, clientID, clientSecret string) (*TokenResponse, error)
```

Logic:
1. Authenticate client with SHA-256 secret comparison.
2. `tokenHash := hashRefreshToken(rawToken)`; `record, err := repo.GetRefreshTokenByHash(ctx, tokenHash)`.
3. If not found → return `ErrInvalidGrant`.
4. If `record.IsRevoked` → **replay**: go to sub-task 8.4. Return `ErrInvalidGrant`.
5. If `record.ExpiresAt.Before(now)` → return `ErrTokenExpired`.
6. If `record.ClientID != clientID` → return `ErrInvalidGrant` (client mismatch).
7. `repo.MarkRefreshTokenUsed(ctx, record.ID, now)`.
8. Issue new access token (existing `GenerateAccessToken`).
9. Issue new refresh token (`generateRefreshTokenValue`, store with `FamilyID = record.FamilyID`, `PreviousTokenID = &record.ID`).
10. `auditSvc.LogEvent(EventRefreshTokenRotated, ...)`.
11. Return new access + refresh token values.

**Handler:** Add `grant_type=refresh_token` case to existing `POST /api/v1/auth/token` handler. Parse `refresh_token` from form body, call `RotateRefreshToken`, map errors to `400 invalid_grant` / `401`.

**Acceptance Criteria:**
- [ ] New access token is returned on valid rotation
- [ ] Previous token hash rejected on second use (is_revoked=true after first use)
- [ ] Wrong client ID returns `400 invalid_grant`
- [ ] Expired token returns `400 invalid_grant`

#### Sub-task 8.4 — Implement replay detection

Inside `RotateRefreshToken` (called from 8.3 when `record.IsRevoked == true`):

1. `repo.RevokeRefreshTokenFamily(ctx, record.FamilyID, "replay_detected")`.
2. `auditSvc.LogEvent(EventReplayDetected, UserID: &record.UserID, ClientID: &record.ClientID, Metadata: {"family_id": record.FamilyID})`.
3. `auditSvc.LogEvent(EventRefreshTokenFamilyRevoked, ...)`.
4. Return `ErrInvalidGrant`.

**Acceptance Criteria:**
- [ ] All tokens in the family are revoked in a single DB statement
- [ ] Both audit events written
- [ ] Subsequent use of any token in the same family also triggers replay detection (because all are now `is_revoked=true`)

#### Sub-task 8.5 — Implement `POST /api/v1/auth/revoke` (RFC 7009)

Create `internal/transport/http/api/v1/handler/revoke.go`.

```
POST /api/v1/auth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <client_id:client_secret>  OR  Bearer <access_token>

Body: token=<value>&token_type_hint=refresh_token|access_token
```

Handler logic:
1. Authenticate caller: extract HTTP Basic credentials OR Bearer JWT; reject unauthenticated with `401`.
2. Hash `token` value and attempt `repo.GetRefreshTokenByHash`.
3. If found (and not already revoked):
   a. `repo.RevokeRefreshToken(ctx, record.ID, "client_revoked")`.
   b. If `record.AccessTokenID != nil`: `repo.RevokeAccessToken(ctx, *record.AccessTokenID)`.
   c. `auditSvc.LogEvent(EventRefreshTokenRevoked, ...)`.
4. Else, attempt `repo.GetAccessToken(ctx, token)` (existing hash lookup).
5. If found and not revoked: `repo.RevokeAccessToken(...)`, `auditSvc.LogEvent(EventAccessTokenRevoked, ...)`.
6. Return `200 OK` in all cases (including token not found), per RFC 7009.

**Acceptance Criteria:**
- [ ] Unknown token returns `200 OK` (not an error)
- [ ] Valid refresh token is revoked; linked access token also revoked
- [ ] Valid access token-only revocation works
- [ ] Unauthenticated request returns `401` (the only error RFC 7009 specifies)

#### Sub-task 8.6 — Wire refresh token revocation into sensitive events

Add `RevokeRefreshTokensByUser(ctx, userID, reason)` calls (a helper wrapping `repo.RevokeRefreshTokenFamily` per-user OR `repo.RevokeRefreshToken` for all user tokens) at three existing/new call sites:

| Call site | Reason value |
|-----------|--------------|
| `change-password` handler (T7.5 stub becomes real) | `"password_change"` |
| Existing logout path in auth service | `"logout"` |
| Admin session-revoke endpoint | `"admin_revoked"` |

Query to add in `db/queries/refresh_tokens.sql`:
```sql
-- name: RevokeRefreshTokensByUser :exec
UPDATE refresh_tokens
SET is_revoked = true, revoked_at = now(), revoke_reason = $2
WHERE user_id = $1 AND is_revoked = false;
```

**Acceptance Criteria:**
- [ ] Password change revokes all user refresh tokens
- [ ] Logout revokes all user refresh tokens
- [ ] Admin session revoke writes `admin_revoked` reason

#### Sub-task 8.7 — Optional cleanup endpoint

Add `DELETE /ops/maintenance/cleanup-tokens` to the ops router (ops handler under `internal/transport/http/ops/handler/`):

- No auth in non-production; restrict to internal network or add ops secret header in production.
- Calls `repo.DeleteExpiredRefreshTokens(ctx)` and returns `200` with `{"deleted": <n>}`.

**Acceptance Criteria:**
- [ ] Endpoint callable and returns count of deleted rows
- [ ] Does not delete non-expired tokens

### Task 9 — Tests

**Dependencies:** T1–T8  
**Blocks:** Release

#### Sub-task 9.1 — Repository integration tests: `refresh_tokens`

In a new or extended `internal/repository/refresh_tokens_test.go`, write integration tests against a real test database (using the existing test helper pattern):

- `CreateRefreshToken` → `GetRefreshTokenByHash` round-trip
- `MarkRefreshTokenUsed` sets `is_revoked=true`, `used_at`, `revoke_reason="used"`
- `RevokeRefreshTokenFamily` revokes all rows with shared `token_family_id`
- `DeleteExpiredRefreshTokens` removes only expired rows

**Acceptance Criteria:**
- [ ] All four cases pass against a real PostgreSQL instance
- [ ] Tests are isolated (each test creates its own data, cleans up)

#### Sub-task 9.2 — Repository integration tests: `audit_log`

In `internal/repository/audit_log_test.go`:

- `CreateAuditLogEntry` with all optional fields nil → row created
- `CreateAuditLogEntry` with full metadata JSONB → metadata round-trips correctly
- `ListAuditLogEntries` with `event_type` filter returns only matching rows
- `CountAuditLogEntries` matches `ListAuditLogEntries` total

**Acceptance Criteria:**
- [ ] All four cases pass
- [ ] JSONB metadata preserved exactly

#### Sub-task 9.3 — Repository integration tests: updated `users` and `clients` queries

Extend existing test files to cover:
- `GetUserByEmailForAuth` returns all new lockout/force-change fields
- `IncrementFailedLoginAttempts` + `LockUserAccount` + `ResetLoginAttempts` sequence
- `UpdatePasswordHash` and `SetForcePasswordChange`
- `CreateClient` includes `is_confidential` and `allow_refresh_tokens`

**Acceptance Criteria:**
- [ ] All new user queries tested end-to-end
- [ ] Existing passing tests unaffected

#### Sub-task 9.4 — Service unit tests: bootstrap (using mock Querier)

Referenced in T5.5. Confirm all nine test cases in T5.5 are implemented and green.

**Acceptance Criteria:**
- [ ] `go test ./internal/app/auth-server/...` passes, coverage ≥ 80% for bootstrap.go

#### Sub-task 9.5 — Service unit tests: account lockout state machine

In `internal/service/auth/login_test.go` (or `authorization_test.go`), use mock Querier to test:

- Active lockout: `VerifyCredentials` returns `ErrAccountLocked` without checking password
- Expired lockout: `ResetLoginAttempts` called, login proceeds
- N-1 failures: counter incremented but not locked
- Nth failure: `LockUserAccount` called, `EventAccountLocked` audit entry written
- Successful login: counter reset, `last_login_at` updated

**Acceptance Criteria:**
- [ ] All five cases covered
- [ ] Audit event written on lockout transition, not on every failure

#### Sub-task 9.6 — Service unit tests: challenge token lifecycle

In `internal/service/auth/token_test.go`:

- `GenerateChallengeToken` → `ValidateChallengeToken` round-trip
- Expired challenge token rejected
- Token with wrong `typ` claim rejected
- Access token not accepted by `ValidateChallengeToken`

**Acceptance Criteria:**
- [ ] All four cases pass

#### Sub-task 9.7 — Service unit tests: refresh token rotation and replay

In `internal/service/auth/refresh_test.go` (or `rotation_test.go`):

- Valid rotation: old token marked used, new token returned
- Replay: revoked token presented → family revoked, both audit entries written
- Expired token: `ErrTokenExpired` returned
- Client mismatch: `ErrInvalidGrant` returned
- `AllowRefreshTokens=false`: no refresh token issued during code exchange

**Acceptance Criteria:**
- [ ] All five cases covered

#### Sub-task 9.8 — Handler integration tests: `POST /api/v1/auth/login`

Extend or create handler-level tests:

- Normal login → access token in response
- `force_password_change=true` → challenge token in response, no access token
- Wrong password (no lockout yet) → `401`
- Nth wrong password → `429` with `Retry-After` header
- Login during active lockout → `429` with `Retry-After` header

**Acceptance Criteria:**
- [ ] All five paths return the correct HTTP status and response body

#### Sub-task 9.9 — Handler integration tests: `POST /api/v1/auth/token`

- Existing authorization code grant still works (regression)
- `grant_type=refresh_token` with valid token → rotated access + refresh token
- `grant_type=refresh_token` with expired token → `400 invalid_grant`
- `grant_type=refresh_token` with replayed token → `400 invalid_grant`, family revoked

**Acceptance Criteria:**
- [ ] All four paths covered
- [ ] Existing authorization code grant tests still pass

#### Sub-task 9.10 — Handler integration tests: `POST /api/v1/auth/revoke`

- Valid refresh token → `200`, token and linked access token revoked in DB
- Valid access token → `200`, token revoked
- Unknown token → `200` (RFC 7009)
- Unauthenticated request → `401`

**Acceptance Criteria:**
- [ ] All four cases return correct HTTP status
- [ ] DB state verified after revocation

#### Sub-task 9.11 — Handler integration tests: `POST /api/v1/auth/change-password`

- Valid challenge token + compliant password → `200`, `force_password_change=false` in DB
- Invalid challenge token → `400`
- Already cleared flag → `409`
- Weak new password → `400` with policy error message

**Acceptance Criteria:**
- [ ] All four cases covered
- [ ] Both audit entries written on success

#### Sub-task 9.12 — Handler integration tests: `DELETE /api/v1/admin/users/:id/lockout`

- Admin JWT + locked user → `204`, `locked_until` cleared, audit entry written
- Admin JWT + unlocked/unknown user → `404`
- Non-admin JWT → `403`

**Acceptance Criteria:**
- [ ] All three cases covered

#### Sub-task 9.13 — Password validator unit tests

Referenced in T7.2. Confirm all eight policy cases are implemented and green.

**Acceptance Criteria:**
- [ ] `go test ./internal/util/password/...` passes, 100% coverage of `validator.go`

#### Sub-task 9.14 — Update load test

In `internal/loadtest/load_test.go`, add a scenario that:
1. Obtains an authorization code and exchanges it for an access token + refresh token.
2. Uses the refresh token to rotate and obtain a new access token three times.
3. Revokes the final refresh token.

**Acceptance Criteria:**
- [ ] Load test compiles and runs without errors
- [ ] Refresh rotation steps included in the VU script

#### Sub-task 9.15 — Full test suite validation

Run the complete test suite:
```
go test -race ./...
```

Fix any data races or failures. Confirm coverage targets.

**Acceptance Criteria:**
- [ ] `go test -race ./...` exits 0
- [ ] Coverage ≥ 80% for all new packages (`audit`, `refresh`, `bootstrap`, `password`)
- [ ] No pre-existing tests regressed

## 3. Task Tracing

### Requirements → Tasks

| Requirement (SRS / System Design) | Task(s) |
|-----------------------------------|---------|
| Default admin bootstrap (env vars, hash password, audit, production guard) | T2, T5 |
| Default client bootstrap (env vars, SHA-256 secret, audit, production guard) | T2, T4, T5 |
| `force_password_change=true` on bootstrapped admin | T1, T5, T7 |
| Password complexity policy (12 chars, upper, lower, digit, special, deny-list) | T7 |
| `POST /api/v1/auth/login` — normal flow with lockout + force-change branching | T1, T2, T6, T7 |
| `POST /api/v1/auth/change-password` — challenge token exchange | T1, T3, T7 |
| Account lockout (sliding window, `locked_until`, `Retry-After`) | T1, T2, T3, T6 |
| `DELETE /api/v1/admin/users/{id}/lockout` — admin unlock | T6 |
| `account_locked` / `account_unlocked` audit events | T3, T6 |
| Client secret hashing changed bcrypt → SHA-256 (SRS RC-001) | T1, T4 |
| `is_confidential`, `allow_refresh_tokens` columns on clients | T1 |
| Refresh token issuance on `offline_access` scope | T1, T2, T3, T8 |
| Refresh token rotation (each use issues new token, invalidates old) | T1, T3, T8 |
| Replay detection → family revocation + audit event | T1, T3, T8 |
| `POST /api/v1/auth/token` — `grant_type=refresh_token` | T1, T8 |
| `POST /api/v1/auth/revoke` — RFC 7009 revocation | T1, T3, T8 |
| Refresh token revocation on password change, logout, admin action | T7, T8 |
| `REFRESH_TOKEN_EXPIRY_DAYS`, `ROTATION_ENABLED`, `MAX_LIFETIME_DAYS` config | T2, T8 |
| `LOGIN_MAX_ATTEMPTS`, `LOGIN_ATTEMPT_WINDOW_SECONDS`, `LOGIN_LOCKOUT_DURATION_SECONDS` config | T2, T6 |
| Audit log table + append-only service | T1, T3 |
| All 15 audit event types written at correct call sites | T3, T4, T5, T6, T7, T8 |
| Bootstrap + refresh token config structs | T2 |
| Database migrations (users, clients, refresh_tokens, audit_log) | T1 |
| sqlc queries and regenerated repository layer | T1 |
| Test coverage ≥ 80 %, `-race` clean, load test updated | T9 |

### Tasks → Deliverables

| Task | Key Deliverables |
|------|------------------|
| T1 | 4 migration pairs, `db/queries/refresh_tokens.sql`, `db/queries/audit_log.sql`, updated `db/queries/users.sql` + `clients.sql`, regenerated `internal/repository/`, updated mock |
| T2 | Updated `internal/config/config.go` + `config_test.go` |
| T3 | `internal/service/audit/audit.go`, `internal/service/audit/events.go` |
| T4 | Updated `internal/service/client/client.go` (SHA-256 hashing), `RELEASE_NOTES.md` entry |
| T5 | `internal/app/auth-server/bootstrap.go`, updated `server.go` startup sequence |
| T6 | Updated `internal/service/auth/authorization.go`, new admin unlock handler, updated login handler |
| T7 | `internal/util/password/validator.go`, updated login handler response, new `change-password` handler |
| T8 | Updated `internal/service/auth/authorization.go` (issuance + rotation), new `internal/service/auth/refresh.go`, new `revoke` handler, updated logout/admin-revoke paths |
| T9 | Test files for all new packages, updated `internal/loadtest/load_test.go` |
