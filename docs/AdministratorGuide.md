# Administrator Guide — Goauth Server v0.3.0

## Document Information

* **Version:** 0.3.0
* **Created:** March 11, 2026
* **Updated:** April 1, 2026
* **Project:** Goauth Server

## Table of Contents

1. [Overview](#1-overview)
2. [Initial Setup and Configuration](#2-initial-setup-and-configuration)
   - [Prerequisites](#21-prerequisites)
   - [Environment Variables](#22-environment-variables)
   - [Bootstrap Configuration](#23-bootstrap-configuration)
   - [Lockout Configuration](#24-lockout-configuration)
   - [Generating Cryptographic Keys](#25-generating-cryptographic-keys)
   - [Database Setup and Migrations](#26-database-setup-and-migrations)
   - [Starting the Server](#27-starting-the-server)
3. [Creating the First Admin User](#3-creating-the-first-admin-user)
   - [Automated Bootstrap (Recommended)](#31-automated-bootstrap-recommended)
   - [Manual SQL Bootstrap (Advanced Fallback)](#32-manual-sql-bootstrap-advanced-fallback)
4. [Managing Client Applications](#4-managing-client-applications)
   - [Listing Clients](#41-listing-clients)
   - [Creating a Client](#42-creating-a-client)
   - [Updating a Client](#43-updating-a-client)
   - [Regenerating a Client Secret](#44-regenerating-a-client-secret)
   - [Deactivating a Client](#45-deactivating-a-client)
5. [Managing OAuth Providers for Clients](#5-managing-oauth-providers-for-clients)
   - [Client-Scoped Provider Architecture](#51-client-scoped-provider-architecture)
   - [Listing Providers](#52-listing-providers)
   - [Creating a Provider](#53-creating-a-provider)
   - [Updating a Provider](#54-updating-a-provider)
   - [Enabling and Disabling a Provider](#55-enabling-and-disabling-a-provider)
   - [Deleting a Provider](#56-deleting-a-provider)
6. [Managing Users](#6-managing-users)
   - [Listing Users](#61-listing-users)
   - [Updating a User's Status](#62-updating-a-users-status)
   - [Account Lockout Management](#63-account-lockout-management)
7. [Managing Sessions](#7-managing-sessions)
   - [Listing Authorization Codes](#71-listing-authorization-codes)
   - [Revoking an Authorization Code](#72-revoking-an-authorization-code)
   - [Listing Access Tokens](#73-listing-access-tokens)
   - [Revoking an Access Token](#74-revoking-an-access-token)
   - [Listing Refresh Tokens](#75-listing-refresh-tokens)
   - [Revoking a Refresh Token](#76-revoking-a-refresh-token)
   - [Audit Log](#77-audit-log)
8. [Security Best Practices](#8-security-best-practices)
9. [Troubleshooting](#9-troubleshooting)

## 1. Overview

Goauth Server is a standalone OAuth 2.0 Authorization Code Grant service. It issues short-lived JWT access tokens to end users via OAuth providers (e.g. Google, GitHub) configured by administrators. Each client application registers with the server, and each client independently configures its own set of OAuth providers — this is the **client-scoped provider model** described throughout this guide.

Key architectural properties:

| Concept | Description |
|---|---|
| **Client** | A registered application (web app, SPA, mobile app) that uses Goauth to authenticate its users. |
| **OAuth Provider** | An external identity provider (e.g. Google) configured for a specific client. Providers are always scoped to one client. |
| **Authorization Code** | A short-lived, single-use token issued after a user authenticates via a provider. Exchanged for an access token. |
| **Access Token** | A signed JWT that a client uses to identify an authenticated user. Expires in 60 minutes (configurable). |

The API surface is split across three route groups:

| Group | Base Path | Purpose |
|---|---|---|
| **API v1** | `/api/v1/` | Token exchange, admin management endpoints |
| **Web** | `/web/` | Browser-facing OAuth login and callback flows |
| **Ops** | `/ops/` | Health and readiness probes |

All admin endpoints require a valid Bearer JWT and the `is_admin` flag to be set on the authenticated user.

## 2. Initial Setup and Configuration

### 2.1 Prerequisites

| Requirement | Minimum Version |
|---|---|
| Go | 1.22+ |
| PostgreSQL | 14+ |
| `golang-migrate` CLI | latest |

Install `golang-migrate`:

```bash
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
```

### 2.2 Environment Variables

Copy the example file and fill in the required values:

```bash
cp .env.example .env
```

All configuration is driven by environment variables. The table below documents every variable.

| Variable | Required | Default | Description |
|---|---|---|---|
| `APP_NAME` | No | `goauth-server` | Human-readable application name. |
| `VERSION` | No | `0.0.1` | Application version string. |
| `ENV` | No | `development` | Runtime environment: `development`, `production`, or `test`. Controls HSTS, CORS wildcards, HTTPS enforcement. |
| `SCHEME` | No | `http` | Public scheme used when constructing callback URLs: `http` or `https`. |
| `HOST` | No | `localhost` | Public hostname of this server. |
| `PORT` | No | `8080` | TCP port the HTTP server listens on. |
| `DB_HOST` | Yes | `localhost` | PostgreSQL host. |
| `DB_PORT` | Yes | `5432` | PostgreSQL port. |
| `DB_USER` | Yes | — | PostgreSQL user. |
| `DB_PASSWORD` | Yes | — | PostgreSQL password. |
| `DB_NAME` | Yes | — | PostgreSQL database name. |
| `DB_SSLMODE` | Yes | `disable` | PostgreSQL SSL mode: `disable`, `require`, `verify-ca`, `verify-full`. |
| `ACCESS_TOKEN_PRIVATE_KEY` | Yes | — | PEM-encoded ES256 (ECDSA P-256) private key for signing JWTs. Multi-line. |
| `ACCESS_TOKEN_PUBLIC_KEY` | Yes | — | PEM-encoded ES256 public key for verifying JWTs. Multi-line. |
| `ACCESS_TOKEN_EXPIRY_MINUTES` | No | `60` | JWT lifetime in minutes. |
| `PROVIDER_ENCRYPTION_KEY` | Yes | — | 64 hex characters (32 bytes). Used for AES-256-GCM encryption of OAuth provider client secrets at rest. |
| `SESSION_SIGNING_KEY` | Yes | — | 64 hex characters (32 bytes). Used for HMAC-SHA256 signing of OAuth session cookies. Must differ from `PROVIDER_ENCRYPTION_KEY`. |
| `CORS_ALLOWED_ORIGINS` | Prod: Yes | — | Comma-separated list of allowed cross-origin request origins (e.g. `https://app.example.com,https://admin.example.com`). Empty value in production rejects all cross-origin requests. Empty value in development enables `*` wildcard. |

**Bootstrap Configuration**

| Variable | Required | Default | Description |
|---|---|---|---|
| `ALLOW_DEFAULT_ADMIN` | No | `false` | Set to `true` to enable automatic first-run admin creation. Must be explicitly enabled in production. |
| `DEFAULT_ADMIN_EMAIL` | No | — | Email address for the bootstrapped admin account. Required if `ALLOW_DEFAULT_ADMIN=true`. |
| `DEFAULT_ADMIN_PASSWORD` | No | — | Plaintext password for the bootstrapped admin account. Must meet password complexity requirements. |
| `ALLOW_DEFAULT_CLIENT` | No | `false` | Set to `true` to enable automatic first-run client creation. Must be explicitly enabled in production. |
| `DEFAULT_CLIENT_ID` | No | — | Client ID (UUID) for the bootstrapped client. Required if `ALLOW_DEFAULT_CLIENT=true`. |
| `DEFAULT_CLIENT_SECRET` | No | — | Plaintext secret for the bootstrapped client. SHA-256 hashed before storage. |
| `DEFAULT_CLIENT_REDIRECT_URIS` | No | — | Comma-separated list of allowed redirect URIs for the bootstrapped client. |
| `DEFAULT_CLIENT_NAME` | No | `GoAuth Client` | Display name for the bootstrapped client. |
| `DEFAULT_CLIENT_CONFIDENTIAL` | No | `true` | Whether the bootstrapped client is confidential (requires secret for token exchange). |

**Lockout Configuration**

| Variable | Required | Default | Description |
|---|---|---|---|
| `LOGIN_MAX_ATTEMPTS` | No | `5` | Number of consecutive failed login attempts before an account is locked. Must be a positive integer. |
| `LOGIN_ATTEMPT_WINDOW_SECONDS` | No | `600` | Sliding-window duration in seconds within which failed attempts are counted. Must be a positive integer. |
| `LOGIN_LOCKOUT_DURATION_SECONDS` | No | `900` | Duration in seconds for which an account remains locked after exceeding `LOGIN_MAX_ATTEMPTS`. Must be a positive integer. |

**Refresh Token Configuration**

| Variable | Required | Default | Description |
|---|---|---|---|
| `REFRESH_TOKEN_EXPIRY_DAYS` | No | `30` | Absolute lifetime of a refresh token in days. Must be a positive integer. |
| `REFRESH_TOKEN_ROTATION_ENABLED` | No | `true` | Whether each use of a refresh token issues a new token and invalidates the old one (rotate-on-use). |
| `REFRESH_TOKEN_MAX_LIFETIME_DAYS` | No | `90` | Maximum total lifetime of a refresh token chain (including rotations), in days. Must be a positive integer. |

### 2.3 Bootstrap Configuration

The bootstrap system enables automatic creation of a default admin account and a default client application on first run. This eliminates the need for direct database SQL on initial setup.

**How it works:**

1. On every startup, the server checks whether any admin users (`CountAdminUsers > 0`) or clients (`CountClients > 0`) already exist.
2. If none exist **and** the bootstrap variables are set, the server creates the configured entities, emits a `WARN`-level log message, and writes audit log entries.
3. Bootstrap is **idempotent** — running it multiple times with a populated database has no effect.

**Production guard:**

| Scenario | Behaviour |
|---|---|
| `ENV=production` and `ALLOW_DEFAULT_ADMIN=false` | Bootstrap skipped silently |
| `ENV=production` and `ALLOW_DEFAULT_ADMIN=true` | Bootstrap runs (operator explicitly opted in) |
| Any non-production environment | Bootstrap runs when variables are set |

> **Critical:** After bootstrap, immediately rotate both the admin password and client secret via the API. Remove or unset the `DEFAULT_ADMIN_PASSWORD` and `DEFAULT_CLIENT_SECRET` variables from your environment — they serve no purpose after first run and represent a security risk if left in place.

**Force-password-change on bootstrap admin:**

Accounts created via bootstrap automatically have `force_password_change=true`. The bootstrapped admin must set a new password using the challenge-token flow before they can obtain an access token for administrative operations.

**Post-bootstrap checklist:**

- [ ] Admin logs in and completes the force-password-change flow.
- [ ] Admin password has been changed to a strong, unique value.
- [ ] Client secret has been regenerated via `POST /api/v1/admin/clients/{id}/secret`.
- [ ] `DEFAULT_ADMIN_PASSWORD` and `DEFAULT_CLIENT_SECRET` are removed from the environment.
- [ ] `ALLOW_DEFAULT_ADMIN` and `ALLOW_DEFAULT_CLIENT` are set to `false` (or removed) in production.

### 2.4 Lockout Configuration

Account lockout protects against brute-force password attacks using a sliding-window counter.

**Mechanism:**

1. Each failed login increments `failed_login_attempts` and records `last_failed_login_at`.
2. When `failed_login_attempts >= LOGIN_MAX_ATTEMPTS` within the `LOGIN_ATTEMPT_WINDOW_SECONDS` window, the account is locked: `locked_until = now() + LOGIN_LOCKOUT_DURATION_SECONDS`.
3. Login attempts during an active lockout immediately return `429 Too Many Requests` with a `Retry-After` header — the password is **not** checked.
4. When the lockout period expires, the next login attempt automatically clears the lockout state before proceeding.
5. A successful login resets `failed_login_attempts`, `last_failed_login_at`, and `locked_until` to their default states.

Administrators can manually clear a lockout via `DELETE /api/v1/admin/users/:id/lockout` (see §6.3).

### 2.5 Generating Cryptographic Keys

> *(Section renumbered from v0.2.0 §2.3)*

**Access token signing keys (ES256):**

```bash
chmod +x scripts/credentials/generate_access_token_keys.sh
./scripts/credentials/generate_access_token_keys.sh
```

Copy the printed private key into `ACCESS_TOKEN_PRIVATE_KEY` and the public key into `ACCESS_TOKEN_PUBLIC_KEY` in `.env`. Include the `-----BEGIN ...-----` and `-----END ...-----` markers.

Alternatively, generate the keys manually:

```bash
# Generate private key
openssl ecparam -name prime256v1 -genkey -noout -out ec-private.pem

# Derive public key
openssl ec -in ec-private.pem -pubout -out ec-public.pem

cat ec-private.pem   # → ACCESS_TOKEN_PRIVATE_KEY
cat ec-public.pem    # → ACCESS_TOKEN_PUBLIC_KEY
```

**AES-256 provider encryption key and session signing key:**

```bash
# PROVIDER_ENCRYPTION_KEY
openssl rand -hex 32

# SESSION_SIGNING_KEY (must be a different value)
openssl rand -hex 32
```

> **Important:** `PROVIDER_ENCRYPTION_KEY` and `SESSION_SIGNING_KEY` must be different 64-character hex strings. They serve distinct cryptographic purposes; reusing the same key violates key-separation principles.

### 2.6 Database Setup and Migrations

Create the PostgreSQL database:

```sql
CREATE DATABASE goauth;
```

Apply all migrations:

```bash
chmod +x db/scripts/run_migrations.sh
./db/scripts/run_migrations.sh
```

The script reads the database connection from `.env` and applies the following migrations in order:

| Order | Migration | Creates |
|---|---|---|
| 1 | `20260109145607_create_users_table` | `users` table with indexes and `updated_at` trigger |
| 2 | `20260213095938_add_is_admin_to_users` | `is_admin` column on `users` |
| 3 | `20260213100111_create_clients_table` | `clients` table |
| 4 | `20260216155147_create_oauth_providers_table` | `oauth_providers` table with `(client_id, name)` unique constraint |
| 5 | `20260216155730_create_authorization_codes_table` | `authorization_codes` table |
| 6 | `20260301120000_create_access_tokens_table` | `access_tokens` table |

The script now applies four additional migrations for v0.3.0:

| Order | Migration | Creates |
|---|---|---|
| 7 | `20260326090601_add_lockout_force_password_to_users` | Five new columns on `users`: `password_hash`, `force_password_change`, `failed_login_attempts`, `last_failed_login_at`, `locked_until` |
| 8 | `20260326092318_add_confidential_refresh_tokens_to_clients` | `is_confidential` and `allow_refresh_tokens` columns on `clients` |
| 9 | `20260326092900_create_refresh_tokens_table` | `refresh_tokens` table with all indexes and foreign keys |
| 10 | `20260326093100_create_audit_log_table` | `audit_log` table with four indexes |

To roll back all migrations:

```bash
chmod +x db/scripts/rollback_migrations.sh
./db/scripts/rollback_migrations.sh
```

### 2.7 Starting the Server

```bash
go run ./cmd/auth-server
```

Or build and run the binary:

```bash
go build -o bin/auth-service ./cmd/auth-server
./bin/auth-service
```

Verify the server is healthy:

```bash
curl http://localhost:8080/ops/health
# → {"status":"healthy"}
```

The Swagger UI is available at:

```
http://localhost:8080/api/docs/index.html
```

## 3. Creating the First Admin User

v0.3.0 adds an **automated bootstrap path** (§3.1) that replaces the manual SQL procedure for most deployments. The manual approach (§3.2) is retained as an advanced fallback.

### 3.1 Automated Bootstrap (Recommended)

Set the following environment variables **before** starting the server:

```bash
ALLOW_DEFAULT_ADMIN=true
DEFAULT_ADMIN_EMAIL=admin@example.com
DEFAULT_ADMIN_PASSWORD=ChangeMe@2026!Secure
```

On startup, the server will:
1. Check that no admin accounts exist yet (`CountAdminUsers == 0`).
2. Validate the email and password against policy.
3. Create the user with `is_admin=true` and `force_password_change=true`.
4. Emit a `WARN`-level log: *"Default admin account created — rotate credentials immediately"*.
5. Write a `default_admin_created` audit log entry.

**Completing first login:**

Because `force_password_change=true`, the bootstrapped admin cannot immediately obtain an access token. The login flow returns a challenge token:

```http
POST /api/v1/auth/login
Content-Type: application/json

{ "email": "admin@example.com", "password": "ChangeMe@2026!Secure" }
```

Response:
```json
{
  "challenge_token": "<15-minute JWT>",
  "require": "password_change"
}
```

Use the challenge token to set a new password:

```http
POST /api/v1/auth/change-password
Content-Type: application/json

{
  "challenge_token": "<challenge_token>",
  "new_password": "MyNewStrong@Pass2026"
}
```

On success, an access token is returned and `force_password_change` is cleared.

> **Security:** Remove `DEFAULT_ADMIN_PASSWORD` from your environment after first login. Set `ALLOW_DEFAULT_ADMIN=false` in production once the admin account is established.

### 3.2 Manual SQL Bootstrap (Advanced Fallback)

Use this approach when automated bootstrap is not suitable (e.g. environments where environment variable injection is restricted, or when the admin must be created from a pre-existing OAuth provider user).

**Step 1 — A user must first log in through the OAuth flow** to have a row in the `users` table. Have the intended admin authenticate at least once via any OAuth provider.

**Step 2 — Identify the user's UUID:**

```sql
SELECT id, email, is_admin FROM users WHERE email = 'admin@example.com';
```

**Step 3 — Grant admin privileges:**

```sql
UPDATE users SET is_admin = true WHERE email = 'admin@example.com';
```

**Step 4 — Verify:**

```sql
SELECT id, email, is_admin FROM users WHERE email = 'admin@example.com';
-- is_admin should be true
```

From this point on, the user will pass `AdminMiddleware` checks after authenticating and receiving a valid JWT. The admin status is checked live against the database on every request.

> **Note:** To bootstrap an initial OAuth provider so the first user can log in, you must first create a client and a provider directly in the database (see the example below), then use the web OAuth flow to authenticate.

**Bootstrap example (direct SQL):**

```sql
-- 1. Create a placeholder admin user row to satisfy the clients.created_by FK
INSERT INTO users (email, email_verified, is_admin)
VALUES ('bootstrap@internal', false, true)
RETURNING id;
-- Note the returned UUID, e.g. 'aaaaaaaa-0000-0000-0000-000000000001'

-- 2. Create the first client (replace <user_uuid> with the value above)
INSERT INTO clients (name, client_secret_hash, redirect_uris, grant_types, created_by)
VALUES (
  'My App',
  'placeholder_hash',  -- will be replaced via API once an admin is available
  ARRAY['https://myapp.example.com/callback'],
  ARRAY['authorization_code'],
  '<user_uuid>'
)
RETURNING id;
-- Note the returned client UUID, e.g. 'bbbbbbbb-0000-0000-0000-000000000001'

-- 3. Create a Google provider for that client (replace <client_uuid>)
INSERT INTO oauth_providers (
  client_id, name, display_name,
  provider_client_id, provider_client_secret,
  auth_url, token_url, user_info_url,
  scopes, is_enabled
) VALUES (
  '<client_uuid>',
  'google', 'Google',
  '<google_client_id>', '<google_client_secret>',
  'https://accounts.google.com/o/oauth2/v2/auth',
  'https://oauth2.googleapis.com/token',
  'https://www.googleapis.com/oauth2/v3/userinfo',
  ARRAY['openid', 'email', 'profile'],
  true
);
```

Once the real admin has logged in and their `is_admin` flag is set, use the API to manage clients and providers going forward.

## 4. Managing Client Applications

All client management endpoints require authentication with an admin token. Include the token in the `Authorization` header and the CSRF token in `X-CSRF-Token`.

### 4.1 Listing Clients

```
GET /api/v1/clients
```

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | integer (1–100) | Items per page. Default: 20. |
| `offset` | integer (≥0) | Zero-based offset for pagination. Default: 0. |
| `is_active` | boolean | Filter by active status (`true` or `false`). Omit to return all statuses. |

**Example:**

```bash
curl -H "Authorization: Bearer <token>" \
     -H "X-CSRF-Token: <csrf_token>" \
     "http://localhost:8080/api/v1/clients?limit=10&offset=0&is_active=true"
```

**Response:**

```json
{
  "clients": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "My App",
      "description": "Production web application",
      "redirect_uris": ["https://myapp.example.com/callback"],
      "grant_types": ["authorization_code"],
      "is_active": true,
      "created_by": "aaaaaaaa-0000-0000-0000-000000000001",
      "created_at": "2026-01-15T10:00:00Z",
      "updated_at": "2026-01-15T10:00:00Z"
    }
  ],
  "total": 1
}
```

### 4.2 Creating a Client

```
POST /api/v1/clients
```

**Request body:**

```json
{
  "name": "My App",
  "description": "Production web application",
  "redirect_uris": ["https://myapp.example.com/callback"],
  "grant_types": ["authorization_code"],
  "is_active": true,
  "is_confidential": true,
  "allow_refresh_tokens": false
}
```

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Unique display name for the client. |
| `description` | No | Optional description. |
| `redirect_uris` | Yes | At least one allowed redirect URI. In production, only HTTPS URIs are accepted (loopback addresses are exempt). |
| `grant_types` | Yes | At least one grant type. Currently `authorization_code` and `refresh_token` are supported. |
| `is_active` | No | Defaults to `true`. Set to `false` for staged rollouts. |
| `is_confidential` | No | Defaults to `true`. A confidential client must supply `client_secret` on token exchange. Set to `false` for public clients (SPAs, mobile apps) that cannot keep a secret. |
| `allow_refresh_tokens` | No | Defaults to `false`. Set to `true` to allow the client to request refresh tokens when the `offline_access` scope is included. |

**Response (201 Created):**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "My App",
  "redirect_uris": ["https://myapp.example.com/callback"],
  "grant_types": ["authorization_code"],
  "is_active": true,
  "is_confidential": true,
  "allow_refresh_tokens": false,
  "created_by": "aaaaaaaa-...",
  "created_at": "2026-03-11T12:00:00Z",
  "updated_at": "2026-03-11T12:00:00Z",
  "client_secret": "rAnDoMbAsE64UrLsAfEsTrInG_43ChArS"
}
```

> **Important:** The `client_secret` field is only present in the creation response. Store it securely — it cannot be retrieved again. If lost, use the [Regenerate Client Secret](#44-regenerating-a-client-secret) endpoint.

### 4.3 Updating a Client

```
PATCH /api/v1/clients/:client_id
```

**Request body:**

```json
{
  "name": "My App (v2)",
  "description": "Updated description",
  "redirect_uris": ["https://myapp.example.com/callback", "https://myapp.example.com/auth/callback"],
  "grant_types": ["authorization_code"],
  "is_confidential": true,
  "allow_refresh_tokens": true
}
```

All fields are required. Returns the updated `ClientResponse` (no secret). Setting `allow_refresh_tokens=true` enables refresh token issuance for this client when the `offline_access` scope is requested.

### 4.4 Regenerating a Client Secret

```
POST /api/v1/admin/clients/:client_id/secret
```

No request body required. A new cryptographically secure secret (32 random bytes, base64url-encoded) is generated, **SHA-256 hashed**, and stored. The plain secret is returned **once** in the response:

```json
{
  "id": "550e8400-...",
  "name": "My App",
  ...
  "client_secret": "nEwRaNdOmSeCrEtHeRe_43ChArS"
}
```

> **Breaking change (v0.3.0):** Client secrets are now hashed with SHA-256 (hex-encoded) instead of bcrypt. Existing secrets hashed with bcrypt are no longer valid after upgrading to v0.3.0. All client secrets must be regenerated using this endpoint after migration.

> **Warning:** All existing integrations using the old secret will immediately start receiving `invalid_client` errors. Rotate the secret in the client application before calling this endpoint in production.

### 4.5 Deactivating a Client

```
DELETE /api/v1/clients/:client_id
```

This performs a **soft delete** — `is_active` is set to `false`. The client record, its providers, and its sessions are preserved for audit purposes. No cascade delete occurs. The client can be re-activated by updating it via `PATCH`.

## 5. Managing OAuth Providers for Clients

### 5.1 Client-Scoped Provider Architecture

OAuth providers are **always scoped to a specific client**. This means:

- Client A and Client B can both have a `google` provider, each with independent credentials and scopes.
- Providers are isolated: changing Client A's Google provider has no effect on Client B.
- The same provider `name` can be reused across clients — the uniqueness constraint is `(client_id, name)`.
- Deleting a client cascades to delete all its providers.
- Provider client secrets are AES-256-GCM encrypted at rest. They are never returned in API responses.

This architecture enables true multi-tenancy: each application manages its own identity providers independently.

### 5.2 Listing Providers

**Admin view (all providers, includes URLs):**

```
GET /api/v1/clients/:client_id/providers
```

```bash
curl -H "Authorization: Bearer <token>" \
     -H "X-CSRF-Token: <csrf_token>" \
     "http://localhost:8080/api/v1/clients/550e8400-.../providers"
```

**Response:**

```json
{
  "providers": [
    {
      "id": "660e8400-...",
      "client_id": "550e8400-...",
      "name": "google",
      "display_name": "Google",
      "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
      "token_url": "https://oauth2.googleapis.com/token",
      "user_info_url": "https://www.googleapis.com/oauth2/v3/userinfo",
      "scopes": ["openid", "email", "profile"],
      "is_enabled": true,
      "created_at": "2026-03-11T12:00:00Z",
      "updated_at": "2026-03-11T12:00:00Z"
    }
  ]
}
```

**Public view (only name and display_name, no credentials):**

```
GET /api/v1/clients/:client_id/auth/providers
```

This endpoint is public (no authentication required) and is intended to be called by the client application to discover which providers are available for login. Only **enabled** providers appear here. Provider `provider_client_id`, `provider_client_secret`, URLs, and scopes are excluded.

### 5.3 Creating a Provider

```
POST /api/v1/clients/:client_id/providers
```

**Request body:**

```json
{
  "name": "google",
  "display_name": "Sign in with Google",
  "provider_client_id": "123456-abc.apps.googleusercontent.com",
  "provider_client_secret": "GOCSPX-...",
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_url": "https://oauth2.googleapis.com/token",
  "user_info_url": "https://www.googleapis.com/oauth2/v3/userinfo",
  "scopes": ["openid", "email", "profile"],
  "is_enabled": true
}
```

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Internal identifier used in URLs (e.g. `"google"`). Must be unique within the client. |
| `display_name` | Yes | User-facing label (e.g. `"Sign in with Google"`). |
| `provider_client_id` | Yes | OAuth client ID issued by the identity provider. |
| `provider_client_secret` | Yes | OAuth client secret issued by the identity provider. Encrypted at rest. |
| `auth_url` | Yes | Provider's authorization endpoint URL. Must be HTTPS in production. |
| `token_url` | Yes | Provider's token exchange endpoint URL. Must be HTTPS in production. |
| `user_info_url` | Yes | Provider's user-info endpoint URL. Must be HTTPS in production. |
| `scopes` | Yes | At least one scope. Include `openid`, `email`, and `profile` for OIDC providers. |
| `is_enabled` | No | Defaults to `false`. Set to `true` to make the provider available for login. |

**Common provider configurations:**

<details>
<summary>Google</summary>

```json
{
  "name": "google",
  "display_name": "Google",
  "provider_client_id": "<from Google Cloud Console>",
  "provider_client_secret": "<from Google Cloud Console>",
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_url": "https://oauth2.googleapis.com/token",
  "user_info_url": "https://www.googleapis.com/oauth2/v3/userinfo",
  "scopes": ["openid", "email", "profile"],
  "is_enabled": true
}
```

</details>

<details>
<summary>GitHub</summary>

```json
{
  "name": "github",
  "display_name": "GitHub",
  "provider_client_id": "<from GitHub OAuth App settings>",
  "provider_client_secret": "<from GitHub OAuth App settings>",
  "auth_url": "https://github.com/login/oauth/authorize",
  "token_url": "https://github.com/login/oauth/access_token",
  "user_info_url": "https://api.github.com/user",
  "scopes": ["read:user", "user:email"],
  "is_enabled": true
}
```

</details>

<details>
<summary>Microsoft Entra ID (Azure AD)</summary>

```json
{
  "name": "microsoft",
  "display_name": "Microsoft",
  "provider_client_id": "<Application (client) ID>",
  "provider_client_secret": "<Client secret value>",
  "auth_url": "https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/authorize",
  "token_url": "https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token",
  "user_info_url": "https://graph.microsoft.com/v1.0/me",
  "scopes": ["openid", "email", "profile"],
  "is_enabled": true
}
```

</details>

### 5.4 Updating a Provider

```
PATCH /api/v1/clients/:client_id/providers/:id
```

**Request body:**

```json
{
  "display_name": "Sign in with Google",
  "provider_client_id": "123456-abc.apps.googleusercontent.com",
  "provider_client_secret": "",
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_url": "https://oauth2.googleapis.com/token",
  "user_info_url": "https://www.googleapis.com/oauth2/v3/userinfo",
  "scopes": ["openid", "email", "profile"],
  "is_enabled": true
}
```

> If `provider_client_secret` is left empty (`""`), the existing encrypted secret is retained. Supply a non-empty value only when rotating the secret.

### 5.5 Enabling and Disabling a Provider

Use the `PATCH` endpoint with `"is_enabled": false` to disable a provider without deleting it. Disabled providers still appear in the admin list but are excluded from the public provider list and cannot be used to initiate an OAuth login flow.

### 5.6 Deleting a Provider

```
DELETE /api/v1/clients/:client_id/providers/:id
```

Returns `204 No Content` on success. Cascades to delete all authorization codes and access tokens issued via this provider.

> **Warning:** Deleting a provider immediately invalidates all existing sessions and tokens that were obtained through it.

## 6. Managing Users

Users are created automatically when they first authenticate via an OAuth provider. Administrators cannot create users directly.

### 6.1 Listing Users

```
GET /api/v1/users
```

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | integer (1–100) | Items per page. Default: 20. |
| `offset` | integer (≥0) | Zero-based offset. Default: 0. |
| `is_active` | boolean | Filter by active status. |
| `is_admin` | boolean | Filter by admin status. |

**Example — list all admin users:**

```bash
curl -H "Authorization: Bearer <token>" \
     -H "X-CSRF-Token: <csrf_token>" \
     "http://localhost:8080/api/v1/users?is_admin=true"
```

**Response:**

```json
{
  "users": [
    {
      "id": "aaaaaaaa-...",
      "email": "admin@example.com",
      "email_verified": true,
      "first_name": "Alice",
      "last_name": "Smith",
      "is_active": true,
      "is_admin": true,
      "locale": "en-US",
      "last_login_at": "2026-03-11T09:00:00Z",
      "locked_until": null,
      "force_password_change": false,
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-03-11T09:00:00Z"
    }
  ],
  "total": 1
}
```

The `locked_until` field is non-null when the account is currently locked. The `force_password_change` field indicates that the user must complete a password change before they can receive an access token.

### 6.2 Updating a User's Status

```
PATCH /api/v1/users/:id
```

**Request body:**

```json
{
  "is_active": false
}
```

Setting `is_active` to `false` prevents the user from logging in and causes all future authentication attempts to fail. Existing valid tokens for the user are not immediately revoked — use the session management endpoints to revoke them explicitly.

### 6.3 Account Lockout Management

When a user exceeds the configured `LOGIN_MAX_ATTEMPTS` within the `LOGIN_ATTEMPT_WINDOW_SECONDS` window, their account is automatically locked until `locked_until`. A locked user's login attempts return `429 Too Many Requests` with a `Retry-After` HTTP-date header.

Administrators can clear a lockout immediately without waiting for the lockout period to expire.

**Unlock a user account:**

```
DELETE /api/v1/admin/users/:id/lockout
```

- Required role: `is_admin = true`.
- Returns `204 No Content` on success.
- Returns `404 Not Found` if the user ID is invalid or the user does not exist.
- Returns `403 Forbidden` if the caller is not an admin.

**Example:**

```bash
curl -X DELETE \
     -H "Authorization: Bearer <admin_token>" \
     -H "X-CSRF-Token: <csrf_token>" \
     "http://localhost:8080/api/v1/admin/users/aaaaaaaa-.../lockout"
# → 204 No Content
```

An `account_unlocked` audit entry is written with `reason: "admin_unlock"` and the admin's user ID as `actor_id`.

## 7. Managing Sessions

Session management endpoints allow administrators to inspect and revoke active authorization codes and access tokens.

### 7.1 Listing Authorization Codes

```
GET /api/v1/sessions/codes
```

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | integer (1–100) | Items per page. Default: 20. |
| `offset` | integer (≥0) | Zero-based offset. Default: 0. |
| `client_id` | UUID string | Filter by client. |
| `user_id` | UUID string | Filter by user. |
| `is_revoked` | boolean | Filter by revocation status. |

**Response:**

```json
{
  "codes": [
    {
      "id": "770e8400-...",
      "client_id": "550e8400-...",
      "user_id": "aaaaaaaa-...",
      "provider_id": "660e8400-...",
      "redirect_uri": "https://myapp.example.com/callback",
      "scope": "openid email profile",
      "expires_at": "2026-03-11T12:05:00Z",
      "used_at": "2026-03-11T12:00:30Z",
      "is_revoked": false,
      "created_at": "2026-03-11T12:00:00Z"
    }
  ],
  "total": 1
}
```

### 7.2 Revoking an Authorization Code

```
DELETE /api/v1/sessions/codes/:id
```

Returns `204 No Content` on success, `404` if the code is not found.

### 7.3 Listing Access Tokens

```
GET /api/v1/sessions/tokens
```

Accepts the same query parameters as the authorization codes endpoint (`limit`, `offset`, `client_id`, `user_id`, `is_revoked`).

**Response:**

```json
{
  "tokens": [
    {
      "id": "880e8400-...",
      "client_id": "550e8400-...",
      "user_id": "aaaaaaaa-...",
      "scope": null,
      "expires_at": "2026-03-11T13:00:00Z",
      "is_revoked": false,
      "created_at": "2026-03-11T12:00:00Z"
    }
  ],
  "total": 1
}
```

> The `token_hash` is intentionally excluded from the response to prevent exposure of sensitive material.

### 7.4 Revoking an Access Token

```
DELETE /api/v1/sessions/tokens/:id
```

Returns `204 No Content` on success, `404` if the token is not found.

After revocation, any request using the revoked token returns `401 Unauthorized`. The revocation check is performed on every authenticated request.

### 7.5 Listing Refresh Tokens

```
GET /api/v1/sessions/refresh-tokens
```

Accepts the same query parameters as access tokens (`limit`, `offset`, `client_id`, `user_id`). Also supports `is_revoked` filter.

**Response:**

```json
{
  "refresh_tokens": [
    {
      "id": "990e8400-...",
      "client_id": "550e8400-...",
      "user_id": "aaaaaaaa-...",
      "scope": "openid email offline_access",
      "expires_at": "2026-04-10T12:00:00Z",
      "is_revoked": false,
      "revoke_reason": null,
      "created_at": "2026-03-11T12:00:00Z"
    }
  ],
  "total": 1
}
```

> The `token_hash` is intentionally excluded from the response to prevent exposure of sensitive material. The `revoke_reason` field contains values such as `"used"`, `"client_revoked"`, `"replay_detected"`, `"password_change"`, `"logout"`, or `"admin_revoked"`.

### 7.6 Revoking a Refresh Token

```
DELETE /api/v1/sessions/refresh-tokens/:id
```

Revokes a single refresh token by its database record ID (UUID). Does NOT revoke the entire token family — to revoke all sessions for a user, use `RevokeUserSessions`.

Returns `204 No Content` on success, `404` if not found.

An `admin_session_revoked` audit entry is written with the admin's user ID as `actor_id`.

### 7.7 Audit Log

The audit log provides an immutable record of security-relevant events. It is append-only — no rows are ever updated or deleted.

```
GET /api/v1/audit-log
```

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | integer (1–100) | Items per page. Default: 20. |
| `offset` | integer (≥0) | Zero-based offset. Default: 0. |
| `event_type` | string | Filter by event type (see table below). |
| `user_id` | UUID | Filter by user. |
| `client_id` | UUID | Filter by client. |

**Event types:**

| Event Type | Description |
|---|---|
| `default_admin_created` | Automated bootstrap created the first admin account |
| `default_client_created` | Automated bootstrap created the first client |
| `user_password_changed` | A user changed their password |
| `force_password_change_satisfied` | A user completed the force-password-change flow |
| `refresh_token_issued` | A refresh token was issued after authorization code exchange |
| `refresh_token_rotated` | A refresh token was rotated (used and replaced with a new one) |
| `refresh_token_revoked` | A single refresh token was explicitly revoked |
| `refresh_token_family_revoked` | An entire token family was revoked (on replay or admin action) |
| `replay_detected` | A previously-used refresh token was presented (replay attack) |
| `access_token_revoked` | An access token was explicitly revoked |
| `admin_session_revoked` | An admin revoked a user's session record |
| `login_failed` | A login attempt failed due to wrong credentials |
| `account_locked` | An account was locked after exceeding the failed-attempt threshold |
| `account_unlocked` | An admin manually cleared an account lockout |
| `client_secret_regenerated` | A client secret was regenerated |

**Example response:**

```json
{
  "entries": [
    {
      "id": "aab08400-...",
      "event_type": "account_locked",
      "user_id": "aaaaaaaa-...",
      "client_id": null,
      "actor_id": null,
      "ip_address": "203.0.113.42",
      "metadata": { "email": "user@example.com" },
      "created_at": "2026-03-25T08:15:30Z"
    }
  ],
  "total": 1
}
```

> **Security note:** The audit log never contains plaintext passwords, token values, or client secrets. The `metadata` JSONB field may contain email addresses and event-context data but nothing sensitive.

## 8. Security Best Practices

### Cryptographic Keys

- **Rotate** `PROVIDER_ENCRYPTION_KEY` and `SESSION_SIGNING_KEY` on a scheduled basis (e.g. annually). Key rotation requires re-encrypting all stored provider secrets — plan for a maintenance window.
- **Rotate** the ECDSA access token key pair periodically. Existing tokens remain valid until expiry since old tokens are verified against the database.
- **Never commit** `.env` or any file containing private keys to version control. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.) in production.
- **Store** the ECDSA private key with `600` file permissions if written to disk.

### Production Checklist

- [ ] Set `ENV=production`.
- [ ] Set `SCHEME=https` and use a valid TLS certificate.
- [ ] Set `DB_SSLMODE=verify-full` and provide a CA certificate.
- [ ] Set `CORS_ALLOWED_ORIGINS` to an explicit list; never leave it empty in production.
- [ ] All provider `auth_url`, `token_url`, and `user_info_url` values must use HTTPS (enforced by the server for non-loopback hosts).
- [ ] All client `redirect_uris` must use HTTPS (enforced by the server for non-loopback hosts).
- [ ] Disable or remove the Swagger UI endpoint in production if not required.
- [ ] Set `ALLOW_DEFAULT_ADMIN=false` (or remove the variable) once the first admin account is established.
- [ ] Set `ALLOW_DEFAULT_CLIENT=false` (or remove the variable) once the first client is established.
- [ ] Regenerate all client secrets using `POST /api/v1/admin/clients/{id}/secret` after upgrading from v0.2.0 — existing bcrypt-hashed secrets are no longer valid.
- [ ] Remove `DEFAULT_ADMIN_PASSWORD` and `DEFAULT_CLIENT_SECRET` from the environment after first run.

### Default Credential Handling

Bootstrap environment variables (`DEFAULT_ADMIN_PASSWORD`, `DEFAULT_CLIENT_SECRET`) are temporary scaffolding for first run. After the first admin has logged in and changed their password:

1. Unset or remove these variables from `.env` and any secret managers.
2. Regenerate the client secret via the admin API.
3. Confirm the audit log contains `default_admin_created` and `default_client_created` entries from the expected startup time.

Leaving bootstrap credentials in the environment beyond first run represents an unnecessary risk — the bootstrap code will not re-use them (idempotency guard), but the values are still visible in process environment lists and log outputs.

### Refresh Token Security

- Refresh tokens are stored as SHA-256 hashes; the plaintext is never persisted.
- Each use rotates the token (old token invalidated, new token issued). If a client presents a previously-used token, the entire token family is revoked and a `replay_detected` audit event is written.
- Set `REFRESH_TOKEN_EXPIRY_DAYS` to the shortest value your application can tolerate. 30 days is the default; consider 7 days for security-sensitive applications.
- Users should revoke refresh tokens on logout via `POST /api/v1/auth/revoke` (RFC 7009). The server also automatically revokes all refresh tokens on password change.

### Password Complexity Policy

All passwords set through the server (admin bootstrap, `POST /api/v1/auth/change-password`) must meet:

| Rule | Requirement |
|---|---|
| Minimum length | 12 characters |
| Uppercase | At least 1 character (A–Z) |
| Lowercase | At least 1 character (a–z) |
| Digit | At least 1 digit (0–9) |
| Special character | At least 1 from the allowed set |
| Deny-list | Must not appear in the OWASP/NIST top common-passwords list |
| Email substring | Must not contain the user's email local-part |

### Admin Account Security

- Grant `is_admin = true` only to named individuals who need it. There is no role hierarchy — every admin has full access to all admin endpoints.
- Use a strong, unique password for the PostgreSQL account used by the service. The service requires `SELECT`, `INSERT`, `UPDATE`, `DELETE` on all application tables and `USAGE` on sequences.
- Revoke any admin session promptly if an admin account is compromised: use `DELETE /api/v1/sessions/tokens?user_id=<id>` to revoke all tokens, then set `is_active = false` on the user.

### Rate Limits

The following rate limits are enforced and cannot be overridden via the API:

| Endpoint | Limit |
|---|---|
| `POST /api/v1/auth/token` | 10 req/min per IP |
| `GET /web/auth/:client_id/:provider/login` | 20 req/min per IP |
| All admin endpoints (`/clients`, `/users`, `/sessions`, etc.) | 30 req/min per authenticated user |

A `429 Too Many Requests` response includes a `Retry-After` header indicating the wait time in seconds.

### CSRF Protection

All state-changing API endpoints (POST, PATCH, DELETE) outside the public OAuth flow require the double-submit cookie pattern:

1. Make any GET request to a protected route. The server sets a `csrf_token` cookie.
2. Read the cookie value from JavaScript (the cookie is not `HttpOnly`).
3. Include the value in the `X-CSRF-Token` request header on all subsequent state-changing requests.

The public token exchange endpoint (`POST /api/v1/auth/token`) is exempt because it requires `client_secret`.

## 9. Troubleshooting

### Server fails to start

**Symptom:** `decoding provider encryption key: ...` or `initializing provider service: ...`

**Cause:** `PROVIDER_ENCRYPTION_KEY` is not 64 hex characters, or `SESSION_SIGNING_KEY` is missing.

**Fix:** Generate both keys with `openssl rand -hex 32` and verify they are each 64 characters.

**Symptom:** `ACCESS_TOKEN_PRIVATE_KEY is required`

**Cause:** The `ACCESS_TOKEN_PRIVATE_KEY` environment variable is empty or not set.

**Fix:** Run `./scripts/credentials/generate_access_token_keys.sh` and copy the output into `.env`.

### `401 Unauthorized` on admin endpoints

**Symptom:** API returns `{"error": "unauthorized"}` even with a valid token.

**Possible causes:**

1. **Token expired.** Default expiry is 60 minutes. Re-authenticate to obtain a new token.
2. **Token revoked.** The token was explicitly revoked via logout or the session management API.
3. **Missing or wrong `Authorization` header.** The header must be `Authorization: Bearer <token>`. The cookie `access_token` is also accepted.

### `403 Forbidden` on admin endpoints

**Symptom:** API returns `{"error": "forbidden"}`.

**Cause:** The authenticated user does not have `is_admin = true` in the database.

**Fix:** Use the SQL command to grant admin:

```sql
UPDATE users SET is_admin = true WHERE email = 'user@example.com';
```

### `403 Forbidden` with CSRF error

**Symptom:** State-changing requests return `{"error": "forbidden"}` — or the server logs show `csrf_violation`.

**Cause:** The `X-CSRF-Token` header is missing, mismatched, or the `csrf_token` cookie is absent.

**Fix:**
1. Ensure the `csrf_token` cookie is present (make a GET request first if needed).
2. Read the cookie value and send it in each state-changing request as `X-CSRF-Token: <value>`.

### `404` when accessing a provider

**Symptom:** `GET /api/v1/clients/:client_id/providers/:id` returns `{"error": "provider not found"}` even though the provider exists.

**Cause:** The provider was created under a different `client_id` than the one in the path. Providers are strictly scoped to their client — cross-client access returns 404 (not 403) to prevent information leakage.

**Fix:** Verify the `client_id` in the URL matches the client the provider belongs to.

### OAuth login fails: `invalid_grant`

**Symptom:** `POST /api/v1/auth/token` returns `{"error": "invalid_grant", ...}`.

**Possible causes:**

1. **Code expired.** Authorization codes expire in 5 minutes.
2. **Code already used.** Codes are single-use. The user must complete the flow again.
3. **`redirect_uri` mismatch.** The URI in the token request must exactly match the URI used when initiating the authorization flow and the registered `redirect_uris` on the client.
4. **`client_id` mismatch.** The code was issued for a different client.
5. **Expired or revoked refresh token (`grant_type=refresh_token`).** The refresh token has exceeded `REFRESH_TOKEN_EXPIRY_DAYS`, been used once already (rotation), or been revoked. The client must re-authenticate via the authorization code flow.
6. **Replayed refresh token.** A previously-consumed refresh token was presented. The entire token family has been revoked. The user must re-authenticate.

### `429 Too Many Requests` on login

**Symptom:** `POST /api/v1/auth/login` returns 429 with a `Retry-After` header.

**Cause:** The user's account is locked after too many failed login attempts.

**Fix (as admin):**

```bash
curl -X DELETE \
     -H "Authorization: Bearer <admin_token>" \
     -H "X-CSRF-Token: <csrf_token>" \
     "http://localhost:8080/api/v1/admin/users/<user_id>/lockout"
# → 204 No Content
```

The `Retry-After` header value is an HTTP-date string indicating when the lockout automatically expires. If the user can wait, no admin action is needed.

### Bootstrap startup failure

**Symptom:** Server exits on startup with an error like `bootstrap default admin: invalid email address` or `bootstrap default admin: password does not meet complexity requirements`.

**Cause:** The `DEFAULT_ADMIN_EMAIL` value is not a valid email address, or `DEFAULT_ADMIN_PASSWORD` does not meet the password policy.

**Fix:**
1. Correct the environment variable value.
2. Ensure the password has at least 12 characters, uppercase, lowercase, digit, and special character.
3. Restart the server.

### `invalid_grant` after upgrading from v0.2.0

**Symptom:** Existing client applications receive `invalid_client` immediately after upgrading.

**Cause:** Client secrets were previously bcrypt-hashed. v0.3.0 uses SHA-256. Existing clients must regenerate their secrets.

**Fix:**

For each client application:
1. Call `POST /api/v1/admin/clients/{id}/secret` using an admin token.
2. Update the `client_secret` in the client application's configuration.
3. Redeploy the client application.

### Provider secret encryption errors after key rotation

**Symptom:** After rotating `PROVIDER_ENCRYPTION_KEY`, the server returns `500 Internal Server Error` when decrypting provider secrets for the OAuth flow.

**Cause:** Existing provider secrets are encrypted with the old key. The new key cannot decrypt them.

**Fix:** Before rotating the key, update all provider secrets via `PATCH /api/v1/clients/:client_id/providers/:id` with the current plaintext credentials (which re-encrypts them under the current key). Once all providers are re-encrypted, rotate the key in `.env` and restart the server.

### High memory or CPU usage

**Symptom:** Gradual memory growth or CPU spikes under load.

**Possible causes:**

1. **No expired token cleanup.** Call `DELETE /api/v1/sessions/tokens` with `is_revoked=true` filters periodically, or run the cleanup SQL directly:

   ```sql
   DELETE FROM access_tokens WHERE expires_at < now();
   DELETE FROM authorization_codes WHERE expires_at < now();
   ```

2. **Rate limiter memory.** The in-memory rate limiter stores one entry per unique IP/user. Entries are purged after 5 minutes of inactivity. Under a DDoS with many unique IPs, memory may grow. Consider deploying behind a load balancer with connection limits.
