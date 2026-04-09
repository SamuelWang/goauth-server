# Release Notes

## v0.3.0 — April 9, 2026

### Overview

v0.3.0 builds on the OAuth 2.0 Authorization Code Grant foundation from v0.2.0 and adds direct email/password authentication, account lockout, force-password-change enforcement, a full refresh token system, audit logging, and environment-driven first-run bootstrap for operators. All client secrets are migrated from bcrypt to SHA-256 in this release.

---

### Breaking Changes

- **Client secret hashing algorithm changed (bcrypt → SHA-256).** Client secrets are now stored as `hex(sha256(secret))` instead of bcrypt hashes. Existing client secrets hashed with bcrypt are **no longer valid** after upgrading to v0.3.0. After running the database migrations, all client application secrets must be regenerated using the `POST /api/v1/admin/clients/{id}/secret` endpoint. The new plaintext secret returned by that endpoint must be distributed to the corresponding client application before it can authenticate again.
- **Database schema expanded.** Four new migrations extend the schema (see Database section below). Run all migrations in order before upgrading.

---

### New Features

#### Default Admin & Client Bootstrap
- At startup, the server can automatically create a first administrator account and a first OAuth client when none exist.
- Credentials are supplied via environment variables (`DEFAULT_ADMIN_EMAIL`, `DEFAULT_ADMIN_PASSWORD`, `DEFAULT_CLIENT_ID`, `DEFAULT_CLIENT_SECRET`, `DEFAULT_CLIENT_REDIRECT_URIS`, and optional metadata variables).
- Bootstrap is **disabled by default in production** and requires explicit opt-in via `ALLOW_DEFAULT_ADMIN=true` / `ALLOW_DEFAULT_CLIENT=true`. A prominent warning is emitted in logs whenever a default credential is created.
- Bootstrap-created admin accounts are automatically flagged with `force_password_change=true` and an audit entry is written (without password material).
- Startup aborts with a descriptive error if bootstrap environment variables fail validation (invalid email, weak password, or invalid redirect URIs).

#### Email & Password Login
- New `POST /api/v1/auth/login` endpoint accepts `{"email": "...", "password": "..."}` and issues a JWT access token (and refresh token when applicable).
- Passwords are verified against an Argon2id hash.
- **Password complexity policy** enforced at all password-setting flows: minimum 12 characters; at least one uppercase letter, lowercase letter, digit, and special character; must not appear in the OWASP/NIST top-1000 deny-list; must not contain the user's email address as a substring.
- If `force_password_change=true` on the account, the endpoint returns a short-lived challenge token (`{"challenge_token": "...", "require": "password_change"}`) instead of an access token.
- Rate limiting applied at `POST /api/v1/auth/login`.

#### Account Lockout
- After **5 consecutive failed login attempts within a 10-minute sliding window**, the account is locked for **15 minutes**.
- Locked accounts receive `429 Too Many Requests` with a `Retry-After` header indicating when the lockout expires.
- Lockout state (`locked_until`, `failed_login_attempts`, `last_failed_login_at`) is persisted in the database and survives restarts and horizontal scaling.
- `account_locked` and `account_unlocked` audit entries are written on state transitions.
- Configurable via `LOGIN_MAX_ATTEMPTS` (default: 5), `LOGIN_ATTEMPT_WINDOW_SECONDS` (default: 600), and `LOGIN_LOCKOUT_DURATION_SECONDS` (default: 900).
- Administrators can manually unlock an account via the new `DELETE /api/v1/admin/users/:id/lockout` endpoint.

#### Force Password Change
- New `POST /api/v1/auth/change-password` endpoint accepts a `challenge_token` (issued by the login endpoint) and a compliant `new_password`.
- Challenge tokens are HS256-signed JWTs with a `typ=password_change` claim and expire in 15 minutes. They are single-use: if `force_password_change` is already `false` when the endpoint is called, a `409 Conflict` is returned.
- On success: password hash is updated, `force_password_change` is cleared, all existing refresh tokens for the user are revoked, both `user_password_changed` and `force_password_change_satisfied` audit entries are written, and a new access token is returned.

#### Refresh Token System
- Refresh tokens are issued during the Authorization Code Grant when the client has `allow_refresh_tokens=true` and the granted scopes include `offline_access`.
- Refresh tokens use a **token family model**: each token stores a `token_family_id` linking it to its rotation lineage.
- **Rotation on use**: `POST /api/v1/auth/token` with `grant_type=refresh_token` invalidates the presented token and returns a new access token + refresh token. The old token hash is marked used in the database.
- **Replay detection**: if a previously rotated (revoked) refresh token is presented, the entire token family is immediately revoked, an `replay_detected` audit entry is written, and `400 invalid_grant` is returned.
- Configurable expiry via `REFRESH_TOKEN_EXPIRY_DAYS` (default: 30) and `REFRESH_TOKEN_MAX_LIFETIME_DAYS` (default: 90). Rotation can be disabled with `REFRESH_TOKEN_ROTATION_ENABLED=false`.
- Refresh tokens are identified in the database by a SHA-256 hash of the raw token value; the plaintext value is never stored.
- New `is_confidential` and `allow_refresh_tokens` columns on the `clients` table gate refresh token issuance.

#### RFC 7009 Token Revocation
- New `POST /api/v1/auth/revoke` endpoint accepts a token and an optional `token_type_hint` (form-encoded body).
- Caller authenticates via HTTP Basic credentials (client ID + secret) or a Bearer access token.
- Revoking a refresh token also revokes its linked access token. Per RFC 7009, unknown tokens return `200 OK`.
- Refresh tokens are revoked automatically on user logout, password change, and admin-initiated session revocation.

#### Audit Log
- New append-only `audit_log` table records security-relevant events. No secrets or token values are ever written.
- New `internal/service/audit` package with `LogEvent(ctx, AuditEntry)`. Audit failures are non-blocking — they never interrupt the primary flow.
- 15 structured event types: `default_admin_created`, `default_client_created`, `user_password_changed`, `force_password_change_satisfied`, `refresh_token_issued`, `refresh_token_rotated`, `refresh_token_revoked`, `refresh_token_family_revoked`, `replay_detected`, `access_token_revoked`, `admin_session_revoked`, `login_failed`, `account_locked`, `account_unlocked`, `client_secret_regenerated`.
- New admin endpoint `GET /api/v1/audit-log` (paginated, filterable by `event_type`, `user_id`, `client_id`).
- New session management endpoints for refresh tokens: `GET /api/v1/sessions/refresh-tokens` and `DELETE /api/v1/sessions/refresh-tokens/:id`.

---

### Database

Four new migrations (all dated 2026-03-26):

| Migration | Description |
|---|---|
| `add_lockout_force_password_to_users` | Adds `password_hash`, `force_password_change`, `failed_login_attempts`, `last_failed_login_at`, `locked_until` columns to `users`; adds `idx_users_locked_until` index |
| `add_confidential_refresh_tokens_to_clients` | Adds `is_confidential` (default `true`) and `allow_refresh_tokens` (default `false`) columns to `clients` |
| `create_refresh_tokens_table` | Token family model with rotation/replay support; FKs to `clients`, `users`, `access_tokens` (self-referential for `previous_token_id`); 6 indexes |
| `create_audit_log_table` | Append-only log; no `updated_at` trigger; 4 indexes on `event_type`, `user_id`, `client_id`, `created_at` |

Migration order: apply after all existing v0.2.0 migrations.

---

### Configuration

15 new environment variables:

| Variable | Default | Description |
|---|---|---|
| `ALLOW_DEFAULT_ADMIN` | `false` | Enable default admin bootstrap in production |
| `DEFAULT_ADMIN_EMAIL` | — | Email for the bootstrap admin account |
| `DEFAULT_ADMIN_PASSWORD` | — | Password for the bootstrap admin account (hashed before storage) |
| `ALLOW_DEFAULT_CLIENT` | `false` | Enable default client bootstrap in production |
| `DEFAULT_CLIENT_ID` | — | Client ID for the bootstrap client |
| `DEFAULT_CLIENT_SECRET` | — | Client secret for the bootstrap client (SHA-256 hashed before storage) |
| `DEFAULT_CLIENT_REDIRECT_URIS` | — | Comma-separated redirect URIs for the bootstrap client |
| `DEFAULT_CLIENT_NAME` | `GoAuth Client` | Display name for the bootstrap client |
| `DEFAULT_CLIENT_CONFIDENTIAL` | `true` | Whether the bootstrap client is a confidential client |
| `LOGIN_MAX_ATTEMPTS` | `5` | Failed attempts before account lockout |
| `LOGIN_ATTEMPT_WINDOW_SECONDS` | `600` | Sliding window for failed attempt counting (seconds) |
| `LOGIN_LOCKOUT_DURATION_SECONDS` | `900` | Account lockout duration (seconds) |
| `REFRESH_TOKEN_EXPIRY_DAYS` | `30` | Refresh token lifetime in days |
| `REFRESH_TOKEN_ROTATION_ENABLED` | `true` | Enable rotate-on-use for refresh tokens |
| `REFRESH_TOKEN_MAX_LIFETIME_DAYS` | `90` | Absolute maximum lifetime for any token in a family |

---

### API Changes

New public endpoints:

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/auth/login` | Authenticate with email and password |
| `POST` | `/api/v1/auth/change-password` | Exchange a challenge token for a compliant new password and access token |
| `POST` | `/api/v1/auth/revoke` | RFC 7009 token revocation (refresh token or access token) |

Updated public endpoint:

| Method | Path | Change |
|---|---|---|
| `POST` | `/api/v1/auth/token` | Now accepts `grant_type=refresh_token` in addition to `grant_type=authorization_code` |

New admin endpoints:

| Method | Path | Description |
|---|---|---|
| `DELETE` | `/api/v1/admin/users/:id/lockout` | Manually unlock a locked user account |
| `GET` | `/api/v1/sessions/refresh-tokens` | List refresh tokens (paginated) |
| `DELETE` | `/api/v1/sessions/refresh-tokens/:id` | Revoke a refresh token by record ID |
| `GET` | `/api/v1/audit-log` | Query the audit log (paginated, filterable) |

---

### Testing

| Layer | Coverage |
|---|---|
| Repository integration (`refresh_tokens`, `audit_log`, updated `users`/`clients` queries) | Testcontainers-based |
| Auth service — login & lockout state machine | 5 cases |
| Auth service — challenge token lifecycle | 4 cases |
| Auth service — refresh token rotation & replay | 5 cases |
| Audit service | 4 cases |
| Bootstrap | 9 cases |
| Password validator | 8 cases (100% coverage) |
| API handlers — login | 5 cases |
| API handlers — change-password | 4 cases |
| API handlers — token (refresh grant) | 4 cases |
| API handlers — revoke | 4 cases |
| API handlers — admin lockout | 3 cases |

All tests pass. Project-wide coverage exceeds the 80% gate enforced by CI.

---

### Documentation

- **Administrator Guide** (`docs/AdministratorGuide.md`) — Updated to v0.3.0: all 15 new environment variables documented; bootstrap configuration and production guard explained; admin unlock endpoint with examples; refresh token session management; audit log event type reference; SHA-256 migration notice; updated production checklist.
- **Client Integration Guide** (`docs/ClientIntegrationGuide.md`) — Updated to v0.3.0: email/password login flow with lockout and force-password-change handling; refresh token grant and rotation; RFC 7009 revocation; updated code examples (TypeScript and Python).
- **Frontend Integration Guide** (`docs/FrontendIntegrationGuide.md`) — New document targeting web and mobile developers: decision diagram for auth flows; token storage guidance; silent refresh pattern; complete TypeScript code examples for login, password change, token refresh, logout, and an `AuthClient` class.
- **Database Documentation** (`docs/DatabaseDocumentation.md`) — Updated to v0.3.0: ERD extended with `refresh_tokens` and `audit_log`; all new columns, indexes, and foreign keys documented; four new migrations in migration history.
- **Service Layer Documentation** (`docs/ServiceLayerDocumentation.md`) — Updated to v0.3.0: `VerifyCredentials`, challenge token helpers, `RotateRefreshToken`, and `ExchangeAuthorizationCode` (refresh token path) documented; new `audit.Service` package with all 15 event type constants; SHA-256 constant-time comparison documented for `ValidateClientSecret`.

---

## v0.2.0 — March 12, 2026

### Overview

v0.2.0 is a major feature release that transforms goauth-server from a single-provider Google login system into a full-featured, production-ready **OAuth 2.0 Authorization Code Grant server** with a client-scoped provider architecture. This release delivers multi-tenant support, a complete admin management API, comprehensive security hardening, observability tooling, and full documentation.

---

### Breaking Changes

- **OAuth flow endpoints restructured.** The previous Google-specific handlers (`/web/auth/google/login`, `/web/auth/google/callback`) have been removed and replaced with generic client-scoped routes:
  - `GET /web/auth/:client_id/:provider/login`
  - `GET /web/auth/:client_id/:provider/callback`
- **Token exchange is now explicit.** Clients must call `POST /api/v1/auth/token` with `grant_type`, `code`, `client_id`, `client_secret`, and `redirect_uri` to receive a JWT access token. Tokens are no longer written directly to the browser cookie after the callback.
- **`Authorization` header supported alongside cookie.** `AuthMiddleware` now accepts both the `access_token` cookie and an `Authorization: Bearer <token>` header. The header takes precedence when both are present.
- **Database schema expanded.** Four new tables are required (`clients`, `oauth_providers`, `authorization_codes`, `access_tokens`). Run all migrations in order before upgrading.

---

### New Features

#### Client-Scoped OAuth Provider Architecture
- Each registered **client application** independently configures its own set of OAuth providers (e.g. Google, GitHub, Microsoft Entra ID).
- Provider credentials are **fully isolated** between clients — one client cannot view, modify, or invoke another client's providers. Attempts to access a mismatched provider are surfaced as `404 Not Found` to prevent cross-client information leakage.
- The same provider type (e.g. `"google"`) may be configured with different credentials by multiple clients simultaneously.
- A unique constraint on `(client_id, name)` prevents duplicate provider names within a single client.

#### OAuth 2.0 Authorization Code Grant Flow
- Full end-to-end flow: provider login redirect → provider callback → authorization code issuance → code-for-token exchange → token revocation.
- Authorization codes expire in **5 minutes** and are **single-use**.
- JWT access tokens are ES256-signed and expire in **60 minutes** (configurable via `ACCESS_TOKEN_EXPIRY_MINUTES`).
- Redirect URI validation is enforced at both the initiation and exchange steps.

#### Admin Management API
All admin endpoints require administrator-level authentication (`AuthMiddleware` + `AdminMiddleware`).

| Resource | Endpoints |
|---|---|
| Clients | `GET/POST /api/v1/clients`, `GET/PATCH/DELETE /api/v1/clients/:id`, `POST /api/v1/clients/:id/regenerate-secret` |
| Providers | `GET/POST /api/v1/clients/:client_id/providers`, `GET/PATCH/DELETE /api/v1/clients/:client_id/providers/:id` |
| Users | `GET /api/v1/users`, `PATCH /api/v1/users/:id` |
| Sessions | `GET/DELETE /api/v1/sessions/codes`, `GET/DELETE /api/v1/sessions/tokens` |

- Client secrets are generated as 32 cryptographically random bytes (base64url) and **bcrypt-hashed (cost 12)** before storage. The plain secret is returned **only once** at creation or regeneration.
- Provider credentials (`provider_client_id`, `provider_client_secret`) are **AES-256-GCM encrypted at rest** and are never returned in any API response.
- Soft delete is used for clients (`is_active = false`) to preserve the audit trail.
- All list endpoints support `limit` and `offset` pagination, bounded to `limit ∈ [1, 100]`.

#### Public Authentication Endpoints
- `GET /api/v1/clients/:client_id/auth/providers` — Returns only `name` and `display_name` for enabled providers of a client. No credentials or internal URLs are exposed.
- `POST /api/v1/auth/token` — OAuth 2.0 compliant token exchange. Returns `access_token`, `token_type`, `expires_in`, and `scope`.
- `POST /api/v1/auth/logout` — Revokes the token in the database before clearing the session cookie to prevent token replay attacks.

---

### Security Hardening

#### Middleware Suite
- **Rate limiting** (`internal/middleware/ratelimit.go`) — Token exchange: 10 req/min per IP; OAuth login: 20 req/min per IP; Admin endpoints: 30 req/min per authenticated user. Stale entries evicted after 5 minutes. Responses include a `Retry-After` header.
- **CORS** (`internal/middleware/cors.go`) — Configurable via `CORS_ALLOWED_ORIGINS` (comma-separated). In production, only listed origins are permitted with `credentials: true`; wildcard is never used in production.
- **CSRF** (`internal/middleware/csrf.go`) — Double-submit cookie pattern with `X-CSRF-Token` header validation (constant-time comparison). Applied to all state-changing admin and auth routes. OAuth callbacks (GET, protected by `state` parameter) and the token exchange (`client_secret` prevents forgery) are intentionally exempt.
- **Security headers** (`internal/middleware/security.go`) — Applied globally on every response:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
  - `Referrer-Policy: no-referrer`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains` (production only)
- **Request body size limit** — `MaxBodySizeMiddleware` enforces a 1 MiB maximum; returns `413 Request Entity Too Large` on violation.
- **Read header timeout** — `http.Server.ReadHeaderTimeout` set to 10 seconds to mitigate Slowloris-style denial-of-service attacks.

#### Security Audit Findings (all resolved)
All five issues identified during an internal security audit were remediated prior to release:

| Severity | Finding | Resolution |
|---|---|---|
| High | Information leakage in token exchange error responses | Generic RFC 6749–compliant `invalid_grant` message for all error variants |
| Medium | Unbounded pagination parameters (DoS vector) | `parsePaginationParams()` enforces `limit ∈ [1, 100]`, `offset ≥ 0`; returns HTTP 400 |
| Medium | Provider OAuth URLs allowed HTTP in production | `validateURL` now enforces HTTPS for non-loopback hosts in production |
| Medium | Log injection via `X-Request-ID` header | Values validated against `/^[a-zA-Z0-9\-_]{1,64}$/`; non-conforming values replaced with a generated UUID |
| Low | Missing `Referrer-Policy` header | Added `Referrer-Policy: no-referrer` to `SecurityHeadersMiddleware` |

#### Penetration Testing
A dedicated penetration test suite (`security_test.go`) with 60+ tests covers: JWT algorithm confusion, tampered payload, token replay after revocation, authorization code replay/mismatch/expiry, CSRF bypass attempts, cross-client isolation, pagination injection, UUID path parameter injection, information leakage scenarios, and request body size enforcement.

#### Security Event Logging
Structured JSON security events (`log/slog`, `os.Stderr`, `WARN` level) emitted with `event`, `ip`, `request_id`, `user_id`, and `time` fields for: `auth_failure`, `rate_limit_exceeded`, `csrf_violation`, `admin_access_denied`, `token_revoked`, `token_exchange_failure`, `oauth_callback_error`.

---

### Database

Six-table schema (up from one):

| Table | Description |
|---|---|
| `users` | Extended with `is_admin BOOLEAN DEFAULT false` |
| `clients` | Registered OAuth client applications |
| `oauth_providers` | Client-scoped OAuth provider configurations (encrypted credentials) |
| `authorization_codes` | Issued auth codes with `provider_id` FK |
| `access_tokens` | Token records by SHA-256 hash for revocation tracking |
| `schema_migrations` | Migration state |

Migration order: `users` → `clients` → `oauth_providers` → `authorization_codes` / `access_tokens`.

All tables include `updated_at` triggers. Foreign keys use `ON DELETE CASCADE` except on `clients` (soft delete preserves audit trail).

---

### Observability

- **Prometheus metrics** (`/ops/metrics`) — Request rates, error rates, latency percentiles, token issuance counters, and security event counters.
- **Grafana dashboards** — Pre-built dashboards included in `monitoring/grafana/`.
- **Request ID tracing** — Every request receives a UUID `X-Request-ID` (accepted from a trusted upstream proxy when present and valid; generated otherwise); echoed in the response header for end-to-end correlation.
- **Health endpoint** — `GET /ops/health` returns service status.

---

### Documentation

- **Swagger UI** — Auto-generated OpenAPI 3.0 spec available at `/api/docs/index.html`; all 22 endpoints annotated with request/response schemas, authentication requirements, and error codes.
- **Administrator Guide** (`docs/AdministratorGuide.md`) — Environment variable reference, key generation, migration order, curl examples for all admin operations, common provider configurations (Google, GitHub, Microsoft Entra ID), production deployment checklist, and troubleshooting guide.
- **Client Integration Guide** (`docs/ClientIntegrationGuide.md`) — Step-by-step OAuth 2.0 Authorization Code Grant integration walkthrough for client applications.
- **Database Documentation** (`docs/DatabaseDocumentation.md`) — Schema reference, indexes, foreign keys, and cascade behavior.
- **Service Layer Documentation** (`docs/ServiceLayerDocumentation.md`) — Architecture and implementation notes for each service.

---

### Testing

| Layer | Coverage |
|---|---|
| Repository | 90% (testcontainers-based integration tests) |
| Auth service | 80.7% |
| Client service | 89.1% |
| Provider service | 87.6% |
| Session service | 86.2% |
| User service | 95.7% |
| Middleware (22 tests) | Auth, admin, rate limit, CORS, CSRF, security headers, context |
| API handlers (79 tests) | Mock-router integration tests for all endpoints |
| Security / pen tests (60+ tests) | Attack simulation suite |

All tests pass. Project-wide coverage exceeds the 80% gate enforced by CI.

---

### CI/CD

- GitHub Actions pipeline: lint → unit tests → integration tests → coverage gate (≥ 80%) → binary build.
- Multi-stage Dockerfile producing a minimal production image.
- Docker Compose stack: PostgreSQL + auto-migration + API server + Prometheus + Grafana.
- Full Kubernetes manifests in `k8s/` (Namespace, ConfigMap, Secret, Deployment, Service, Ingress, migration Job).

---

## v0.1.0 — Initial Release

### Overview

The initial release established project infrastructure and delivered Google Identity login support.

### Features

- **Google Identity login** — Sign-in and automatic account creation on first login.
- **JWT access tokens** — Issued as a cookie after successful Google OAuth authentication.
- **CSRF protection** — Initial protection against cross-site request forgery attacks.
- **Project infrastructure** — Go module, PostgreSQL database, Docker setup, and CI pipeline scaffolding.
