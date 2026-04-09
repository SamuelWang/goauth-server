# goauth-server

[![CI](https://github.com/SamuelWang/goauth-server/actions/workflows/ci.yml/badge.svg)](https://github.com/SamuelWang/goauth-server/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.25-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/github/license/SamuelWang/goauth-server)](LICENSE)

**goauth-server** is a production-ready OAuth 2.0 Authorization Code Grant server written in Go. It implements a **client-scoped OAuth provider architecture** that lets each registered client application configure its own set of OAuth providers (Google, GitHub, Microsoft, etc.) independently — enabling multi-tenant deployments where different applications maintain separate, isolated OAuth integrations.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start (Docker)](#quick-start-docker)
- [Manual Setup](#manual-setup)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Development](#development)
- [Testing](#testing)
- [Deployment](#deployment)
- [Monitoring](#monitoring)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Features

- **OAuth 2.0 Authorization Code Grant** — Full end-to-end flow: provider login, callback handling, code-for-token exchange, and token revocation.
- **Refresh Tokens with Rotation** — Rotate-on-use refresh tokens with replay detection and RFC 7009 revocation support.
- **Client-scoped OAuth providers** — Each client application can configure its own set of OAuth providers. Provider credentials are isolated per client and encrypted at rest with AES-256-GCM.
- **Email & Password Login** — Native login endpoint with Argon2id password hashing and strict complexity policies.
- **Account Lockout & Security Gating** — Sliding-window failed-attempt tracking with configurable thresholds and force-password-change challenge flows.
- **Automated Bootstrap** — Environment-driven first-run creation of administrator accounts and OAuth clients for CI/CD and rapid deployment.
- **Structured Audit Logging** — Append-only security audit log tracking 15+ event types (logins, lockouts, token lifecycle, admin actions).
- **JWT access tokens** — ECDSA ES256-signed JWTs with configurable expiry. Tokens are validated and revocation-checked on every request.
- **Admin management API** — Full CRUD for clients, client-scoped providers, users, sessions, and audit logs.
- **Security hardening** — Rate limiting (per IP and per user), CORS, CSRF double-submit cookie protection, and security headers (CSP, HSTS, X-Frame-Options).
- **Prometheus metrics + Grafana dashboards** — Request rates, error rates, latency percentiles, token issuance, and security event counters.
- **Docker & Kubernetes ready** — Multi-stage Dockerfile, Docker Compose stack with auto-migration, and full Kubernetes manifests.
- **CI pipeline** — GitHub Actions with lint, unit tests, integration tests, coverage gate (≥ 80%), and binary build.
- **OpenAPI / Swagger UI** — Auto-generated documentation available at `/api/docs/index.html`.

## Architecture

### Client-Scoped OAuth Provider Model

```
Client A ──┬── Google provider  (Client A's Google credentials)
           └── GitHub provider  (Client A's GitHub credentials)

Client B ──┬── Google provider  (Client B's own Google credentials)
           └── Microsoft provider
```

- Providers belong to a specific client — `Client A`'s Google config is completely independent of `Client B`'s.
- A client's providers are invisible to other clients (`ErrProviderClientMismatch` is surfaced as 404 to prevent cross-client information leakage).
- Provider client secrets are encrypted with AES-256-GCM before storage and never returned in API responses.

### Request Flow

```
Browser / App
    │
    ├─ GET /web/auth/:client_id/:provider/login   ← Initiate OAuth, redirect to provider
    │
    ├─ GET /web/auth/:client_id/:provider/callback ← Provider returns code; issue auth code; redirect to app
    │
    └─ POST /api/v1/auth/token                    ← App exchanges auth code for JWT access token
```

### Router Groups

| Prefix | Description |
|--------|-------------|
| `/web/auth/...` | Browser-facing OAuth login and callback endpoints |
| `/api/v1/...` | JSON API: token exchange, admin management |
| `/ops/...` | Health check and Prometheus metrics |

## Quick Start (Docker)

The fastest way to run the full stack (PostgreSQL + auto-migration + API server + Prometheus + Grafana):

**1. Clone and configure**

```bash
git clone https://github.com/SamuelWang/goauth-server.git
cd goauth-server
cp .env.example .env
```

**2. Generate required secret keys and bootstrap credentials**

Configure the required cryptographic keys and (optional) initial admin/client credentials in your `.env` file:

```bash
# --- 1. JWT keys (ES256 key pair for signing access tokens) ---
chmod +x scripts/credentials/generate_access_token_keys.sh
./scripts/credentials/generate_access_token_keys.sh
# Copy the printed keys into .env (ACCESS_TOKEN_PRIVATE_KEY / ACCESS_TOKEN_PUBLIC_KEY)

# --- 2. Security keys (32-byte hex strings) ---
# AES-256 encryption key for provider secrets at rest
openssl rand -hex 32   # → paste as PROVIDER_ENCRYPTION_KEY in .env
# HMAC key for OAuth session cookies
openssl rand -hex 32   # → paste as SESSION_SIGNING_KEY in .env

# --- 3. Database password ---
# → set as DB_PASSWORD in .env

# --- 4. Bootstrap Configuration (Optional but recommended) ---
# Set ALLOW_DEFAULT_ADMIN=true and ALLOW_DEFAULT_CLIENT=true, then fill in 
# your desired email, password, and client ID/secret. This allows you to 
# log in and start using the API immediately.
```

**3. Start the stack**

```bash
docker compose up --build
```

The `migrate` service automatically applies all pending database migrations before the API server starts. Once running, the server will automatically seed the default admin and client if configured.

**Service endpoints once running:**

| Endpoint | Description |
|----------|-------------|
| `http://localhost:8080/ops/health` | Health check |
| `http://localhost:8080/api/docs/index.html` | Swagger UI |
| `http://localhost:8080/metrics` | Prometheus metrics |
| `http://localhost:9090` | Prometheus UI |
| `http://localhost:3000` | Grafana dashboards (admin / see `.env`) |

## Manual Setup

### Prerequisites

- Go 1.25+
- PostgreSQL 16+
- [`golang-migrate`](https://github.com/golang-migrate/migrate) CLI
- [`sqlc`](https://sqlc.dev/) (only needed when modifying SQL queries)

### Steps

**1. Clone and install dependencies**

```bash
git clone https://github.com/SamuelWang/goauth-server.git
cd goauth-server
go mod download
```

**2. Create a PostgreSQL database**

```bash
createdb goauth
```

**3. Configure environment variables**

```bash
cp .env.example .env
# Edit .env — see the Configuration section below
```

**4. Generate required secret keys**

Configure the required cryptographic keys and (optional) bootstrap credentials in your `.env` file. Follow step 2 of the [Quick Start (Docker)](#quick-start-docker) section for the specific commands to generate JWT keys, the `PROVIDER_ENCRYPTION_KEY`, and the `SESSION_SIGNING_KEY`.

**5. Run database migrations**

```bash
chmod +x db/scripts/run_migrations.sh
./db/scripts/run_migrations.sh
```

**6. Start the server**

```bash
go run ./cmd/auth-server
```

The server starts on `http://localhost:8080` by default. If you configured the [Bootstrap Configuration](#configuration), the default administrator account and OAuth client will be created automatically on the first run.

## Configuration

All configuration is read from environment variables (or a `.env` file in the project root). Copy `.env.example` to `.env` and fill in the required values.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENV` | No | `development` | Runtime environment: `development`, `production`, or `test` |
| `SCHEME` | No | `http` | `http` or `https` — used to construct OAuth callback URLs |
| `HOST` | No | `localhost` | Server hostname |
| `PORT` | No | `8080` | HTTP listen port |
| `DB_HOST` | Yes | — | PostgreSQL host |
| `DB_PORT` | No | `5432` | PostgreSQL port |
| `DB_USER` | Yes | — | PostgreSQL user |
| `DB_PASSWORD` | Yes | — | PostgreSQL password |
| `DB_NAME` | Yes | — | PostgreSQL database name |
| `DB_SSLMODE` | No | `disable` | `disable`, `require`, `verify-ca`, or `verify-full` |
| `ACCESS_TOKEN_PRIVATE_KEY` | Yes | — | PEM-encoded ES256 (ECDSA P-256) private key |
| `ACCESS_TOKEN_PUBLIC_KEY` | Yes | — | PEM-encoded ES256 public key |
| `ACCESS_TOKEN_EXPIRY_MINUTES` | No | `60` | JWT access token lifetime in minutes |
| `PROVIDER_ENCRYPTION_KEY` | Yes | — | 64 hex chars (32 bytes) — AES-256-GCM key for provider secrets |
| `SESSION_SIGNING_KEY` | Yes | — | 64 hex chars (32 bytes) — HMAC-SHA256 key for OAuth session cookies |
| `CORS_ALLOWED_ORIGINS` | No | `""` | Comma-separated allowed CORS origins (empty = wildcard in dev, block all in prod) |
| `ALLOW_DEFAULT_ADMIN` | No | `false` | Enable automated first-run admin creation |
| `ALLOW_DEFAULT_CLIENT` | No | `false` | Enable automated first-run OAuth client creation |
| `REFRESH_TOKEN_EXPIRY_DAYS` | No | `30` | Refresh token lifetime in days |
| `LOGIN_MAX_ATTEMPTS` | No | `5` | Failed attempts before account lockout |
| `GRAFANA_ADMIN_USER` | No | `admin` | Grafana admin username (Docker Compose only) |
| `GRAFANA_ADMIN_PASSWORD` | No | — | Grafana admin password (Docker Compose only) |

> **Production note:** Set `ENV=production` to enable HTTPS enforcement on OAuth provider URLs, HSTS headers, and strict CORS origin checking.

## API Reference

Interactive documentation is available at `/api/docs/index.html` when the server is running.

### Public endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/ops/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/api/v1/clients/:client_id/auth/providers` | List enabled OAuth providers for a client |
| `GET` | `/web/auth/:client_id/:provider/login` | Initiate OAuth login flow |
| `GET` | `/web/auth/:client_id/:provider/callback` | OAuth provider callback |
| `POST` | `/api/v1/auth/login` | Email & password login |
| `POST` | `/api/v1/auth/change-password` | Complete force-password-change challenge |
| `POST` | `/api/v1/auth/token` | Exchange authorization code or refresh token |
| `POST` | `/api/v1/auth/revoke` | Revoke an access or refresh token (RFC 7009) |

### Authenticated endpoints (Bearer token required)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/auth/me` | Get current user info |
| `POST` | `/api/v1/auth/logout` | Revoke access token and clear session |

### Admin endpoints (Bearer token + `is_admin = true` required)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/clients` | List clients |
| `POST` | `/api/v1/clients` | Create client |
| `GET` | `/api/v1/clients/:client_id` | Get client |
| `PATCH` | `/api/v1/clients/:client_id` | Update client |
| `DELETE` | `/api/v1/clients/:client_id` | Soft-delete client |
| `POST` | `/api/v1/clients/:client_id/regenerate-secret` | Regenerate client secret |
| `GET` | `/api/v1/clients/:client_id/providers` | List providers for client |
| `POST` | `/api/v1/clients/:client_id/providers` | Create provider for client |
| `GET` | `/api/v1/clients/:client_id/providers/:id` | Get provider |
| `PATCH` | `/api/v1/clients/:client_id/providers/:id` | Update provider |
| `DELETE` | `/api/v1/clients/:client_id/providers/:id` | Delete provider |
| `GET` | `/api/v1/users` | List users |
| `PATCH` | `/api/v1/users/:id` | Update user status |
| `DELETE` | `/api/v1/users/:id/lockout` | Unlock a user account |
| `GET` | `/api/v1/sessions/codes` | List authorization codes |
| `DELETE` | `/api/v1/sessions/codes/:id` | Revoke authorization code |
| `GET` | `/api/v1/sessions/tokens` | List access tokens |
| `DELETE` | `/api/v1/sessions/tokens/:id` | Revoke access token |

All state-changing admin requests require both an `Authorization: Bearer <token>` header and an `X-CSRF-Token` header (double-submit cookie pattern).

### Rate limits

| Endpoint | Limit |
|----------|-------|
| `POST /api/v1/auth/token` | 10 req/min per IP |
| `GET /web/auth/.../login` | 20 req/min per IP |
| Admin endpoints | 30 req/min per user |

## Development

### Technologies

| Component | Library / Tool |
|-----------|---------------|
| Web framework | [Gin](https://github.com/gin-gonic/gin) |
| Database | PostgreSQL 16+ via [pgx/v5](https://github.com/jackc/pgx) |
| Query codegen | [sqlc](https://sqlc.dev/) |
| Migrations | [golang-migrate](https://github.com/golang-migrate/migrate) |
| JWT | [golang-jwt/jwt v5](https://github.com/golang-jwt/jwt) (ES256) |
| Password hashing | Argon2id (golang.org/x/crypto/argon2) |
| Metrics | [Prometheus client_golang](https://github.com/prometheus/client_golang) |
| API docs | [swaggo/swag](https://github.com/swaggo/swag) |
| Linter | [golangci-lint](https://golangci-lint.run/) |

### Recommended IDE

Visual Studio Code with:
- [Go](https://marketplace.visualstudio.com/items?itemName=golang.Go)
- [Prettier SQL VSCode](https://marketplace.visualstudio.com/items?itemName=inferrinizzard.prettier-sql-vscode)

### Project Structure

```
goauth-server/
├── cmd/auth-server/          # Main application entry point and Swagger annotations
├── db/
│   ├── migrations/           # golang-migrate SQL migration files
│   ├── queries/              # sqlc SQL query definitions
│   └── schema/               # Dumped database schema
├── docs/                     # Project documentation (guides, design docs)
├── docs-planning/            # Documentation planning files
├── docs-swagger/             # Auto-generated OpenAPI spec (swag init output)
├── internal/
│   ├── app/auth-server/      # Server bootstrapping (dependency wiring, Gin setup)
│   ├── config/               # Environment variable parsing
│   ├── metrics/              # Prometheus registry and metric definitions
│   ├── middleware/           # Gin middleware (auth, admin, CORS, CSRF, rate limit, security headers)
│   ├── models/               # Shared domain models
│   ├── repository/           # sqlc-generated data access layer
│   ├── service/              # Business logic
│   │   ├── audit/            # Business-level structured audit logging (DB persisted)
│   │   ├── auth/             # OAuth flow, token issuance, and revocation
│   │   ├── client/           # Client application management
│   │   ├── provider/         # OAuth provider management (with secret encryption)
│   │   ├── session/          # Authorization code and access token management
│   │   └── user/             # User management
│   ├── testutil/             # Shared test utilities
│   ├── transport/http/
│   │   ├── api/              # JSON API routes and handlers
│   │   ├── ops/              # Health and metrics endpoints
│   │   └── web/              # Browser OAuth flow handlers
│   └── util/                 # Security logging and other utilities
├── k8s/                      # Kubernetes manifests
├── monitoring/               # Prometheus and Grafana configuration
├── scripts/
│   ├── credentials/          # Key generation scripts
│   └── deploy/               # Docker and Kubernetes deployment scripts
└── docker-compose.yml
```

### Coding Style

- **Standard Go Formatting:** Use `gofmt` or `goimports` to maintain consistent formatting.
- **Linter Compliance:** Ensure all code passes `golangci-lint run`. Configuration is provided in `.golangci.yml`.
- **Error Handling:** Follow the Go 1.13+ error wrapping pattern. Use `fmt.Errorf("...: %w", err)` to wrap errors for better context.
- **Dependency Injection:** Use interfaces and constructor functions (`New`) to inject dependencies, facilitating mock-based testing.
- **Context Management:** Pass `context.Context` as the first argument to methods performing I/O or long-running operations.
- **Testing Standards:**
  - Use [testify](https://github.com/stretchr/testify) for assertions.
  - Use [testcontainers-go](https://golang.testcontainers.org/) for integration tests involving PostgreSQL.
  - Maintain at least 80% code coverage (enforced by CI).
- **Documentation:** Use standard Go doc comments for exported symbols. Keep Swagger/OpenAPI annotations updated in handler functions and `cmd/auth-server/docs.go`.
- **Security First:** Never log sensitive information (tokens, secrets). Use `internal/util/security_log.go` for real-time security event alerting and `internal/service/audit/` for persistent business-level audit trails.

### Utility Packages

Before implementing common functionality, please review the shared utilities in `internal/util/` to avoid duplication:

| Package | Purpose | Key Utilities |
|---------|---------|---------------|
| `util` | General helpers | `SHA256Hex`, `GenerateSecureToken`, `StrPtr` |
| `util` | Security Audit | Structured logging for security events (Auth failures, CSRF, etc.) via `Log*` functions |
| `util/password` | Password Policy | `Validate` function for length, complexity, and common-password denylist |

**Mandatory:** Review these utilities before implementing new helper functions or security logging logic.

### Database Migrations

```bash
# Create a new migration
migrate create -ext sql -dir ./db/migrations <migration_name>

# Apply all pending migrations
chmod +x db/scripts/run_migrations.sh
./db/scripts/run_migrations.sh

# Apply N migrations
./db/scripts/run_migrations.sh 2

# Roll back N migrations (default: all)
chmod +x db/scripts/rollback_migrations.sh
./db/scripts/rollback_migrations.sh [N]

# Dump schema after migrations
chmod +x db/scripts/dump_schema.sh
./db/scripts/dump_schema.sh
```

### Regenerating sqlc Code

After modifying files under `db/queries/`:

```bash
sqlc generate
```

### Regenerating Swagger Docs

After modifying handler annotation comments:

```bash
swag init -g cmd/auth-server/docs.go -o docs-swagger/ --parseDependency --parseInternal
```

## Testing

The project uses Go's standard testing framework with [testify](https://github.com/stretchr/testify) for assertions and [testcontainers-go](https://golang.testcontainers.org/) for PostgreSQL integration tests.

### Prerequisites

Docker must be running on your machine (required by testcontainers for repository integration tests).

**Linux:** ensure your user is in the `docker` group:

```bash
sudo usermod -aG docker $USER
newgrp docker   # apply without logging out
docker ps       # verify access
```

### Running Tests

```bash
# All tests
go test ./...

# Skip integration tests (no Docker required)
go test -short ./...

# With verbose output
go test -v ./...

# With coverage summary
go test -cover ./...

# Generate HTML coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Single package
go test ./internal/service/auth/...

# Single test function
go test -run TestExchangeCode ./internal/service/auth/...
```

### Test Layers

| Layer | Location | Requires Docker |
|-------|----------|----------------|
| Middleware | `internal/middleware/*_test.go` | No |
| Service (unit) | `internal/service/**/*_test.go` | No |
| Handler (integration) | `internal/transport/http/api/v1/handler/*_test.go` | No |
| Repository (integration) | `internal/repository/*_test.go` | **Yes** |
| Penetration tests | `internal/transport/http/api/v1/handler/security_test.go` | No |

> Coverage gate: ≥ 80% required across the codebase (enforced by CI).

## Deployment

### Docker Compose (recommended for local / staging)

```bash
cp .env.example .env
# Fill in required secrets (see Configuration section)
docker compose up --build
```

The stack starts PostgreSQL, runs all pending migrations automatically, then starts the API server.

For a scripted deployment with pre-flight validation and health-check polling:

```bash
chmod +x scripts/deploy/deploy-docker.sh
./scripts/deploy/deploy-docker.sh
```

### Kubernetes

```bash
chmod +x scripts/deploy/deploy-k8s.sh
./scripts/deploy/deploy-k8s.sh [--image-tag <tag>] [--dry-run]
```

Manifests are located in `k8s/`. Key resources:

| File | Description |
|------|-------------|
| `k8s/namespace.yaml` | `goauth` namespace |
| `k8s/configmap.yaml` | Non-sensitive runtime config |
| `k8s/secret.yaml` | Secret template (populate out-of-band) |
| `k8s/deployment.yaml` | 2-replica Deployment with liveness/readiness probes |
| `k8s/service.yaml` | ClusterIP Service (port 80 → 8080) |
| `k8s/ingress.yaml` | nginx Ingress with TLS / cert-manager annotations |
| `k8s/migrate-job.yaml` | One-off migration Job |

### Database Backup and Restore

```bash
# Backup (creates a .dump.gz archive)
chmod +x scripts/deploy/backup-database.sh
./scripts/deploy/backup-database.sh [--docker] [--retain <days>]

# Restore
chmod +x scripts/deploy/restore-database.sh
./scripts/deploy/restore-database.sh <backup-file.dump.gz> [--drop-existing]
```

## Monitoring

The Docker Compose stack starts Prometheus (port 9090) and Grafana (port 3000) alongside the API server.

Prometheus scrapes `/metrics` every 15 s. The Grafana dashboard (auto-provisioned on startup) provides:

- **Overview:** request rate, error rate, p95 latency, active goroutines
- **HTTP Traffic:** per-route request rates, error rates, latency percentiles
- **Token Issuance:** tokens issued vs revoked
- **Security Events:** auth failures, rate-limit violations, CSRF violations, admin access denials

Alert rules (in `monitoring/prometheus/alerts.yml`) fire on: server down, high 5xx rate (> 5%), high 4xx rate (> 20%), high latency (p95 > 1 s), high rate-limit violations, high auth failure rate, and high memory usage.

## Documentation

| Document | Description |
|----------|-------------|
| [Administrator Guide](docs/AdministratorGuide.md) | Setup, key generation, client and provider management, troubleshooting |
| [Client Integration Guide](docs/ClientIntegrationGuide.md) | OAuth flow walkthrough with TypeScript, Python, and Go examples |
| [Frontend Integration Guide](docs/FrontendIntegrationGuide.md) | Guide for SPA and mobile developers: login, tokens, and error handling |
| [Database Documentation](docs/DatabaseDocumentation.md) | Schema, indexes, foreign keys, and migration order |
| [Service Layer Documentation](docs/ServiceLayerDocumentation.md) | Business logic layer architecture and service contracts |
| [Repository Documentation](docs/RepositoryDocumentation.md) | Data access layer and sqlc query reference |
| [API Docs (Swagger UI)](http://localhost:8080/api/docs/index.html) | Interactive OpenAPI documentation (requires running server) |
| [System Design v0.3.0](docs-planning/v0.3.0/SystemDesign.md) | Architecture decisions and component design |

## Contributing

1. Fork the repository and create a feature branch.
2. Write tests for new functionality — the CI coverage gate requires ≥ 80%.
3. Run `golangci-lint run` locally before pushing (configuration is in `.golangci.yml`).
4. Open a pull request against `develop`. The CI pipeline must pass before merge.

## License

This project is licensed under the terms of the [LICENSE](LICENSE) file.
