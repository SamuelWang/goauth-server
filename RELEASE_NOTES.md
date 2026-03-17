# Release Notes

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
