# System Design Document - v0.2.0

## 1. System Analysis

### 1.1 Overview
"Goauth" v0.2.0 extends the authentication and authorization service with administrator capabilities, client application management, and OAuth 2.0 Authorization Code Grant flow. It serves as a centralized identity provider and OAuth2 authorization server, enabling users to sign in via configurable OAuth providers (currently Google only) and allowing administrators to manage users, client applications, OAuth providers, and sessions.

### 1.2 Actors
* **User:** An end-user who authenticates via a selected OAuth provider to access client applications secured by Goauth.
* **Administrator:** A privileged user with additional permissions to:
  * Manage OAuth providers (enable/disable, configure)
  * Manage client applications (CRUD operations)
  * Manage user accounts (list, disable)
  * Manage sessions (list and revoke tokens and codes)
* **Client Application:** External applications that use Goauth as an OAuth2 authorization server via the Authorization Code Grant flow. Clients select which OAuth provider to use during authentication.
* **OAuth Provider:** External identity providers (e.g., Google) used for user authentication. Providers must be enabled by administrators before use.

### 1.3 Functional Requirements
Based on the Software Requirements Specification (SRS) v0.2.0:

#### Client Management
* Administrators can register new client applications (OAuth 2.0 Authorization Code Grant only)
* Administrators can list, view, update, and delete client applications
* Administrators can regenerate client secrets
* Client applications must have registered redirect URIs for security

#### User Management
* User data model includes an administrator flag
* Administrators can list all users
* Administrators can disable user accounts

#### Authentication & Authorization
* OAuth providers use OAuth 2.0 Authorization Code Grant flow exclusively
* Clients select an OAuth provider (currently Google only) during authorization request
* Only enabled OAuth providers can be used for authentication
* System redirects to client callback URL with authorization code
* System validates redirect URIs against registered callbacks
* Clients exchange authorization codes for access tokens

#### Session Management
* All issued access tokens are persisted in the database
* All issued authorization codes are tracked in the database
* Administrators can list and revoke authorization codes
* Administrators can list and revoke access tokens

### 1.4 Non-Functional Requirements
* **Security:**
  * CSRF protection for state-changing operations
  * XSS and SQL injection prevention
  * CORS support for web-based clients
  * Access token expiration ≤ 60 minutes
  * Authorization code expiration ≤ 5 minutes
  * Secure storage of client secrets (hashed)
* **Scalability:** Stateless REST API design for horizontal scaling
* **Reliability:** PostgreSQL ACID properties for data integrity
* **Deployment:** Docker container support

## 2. System Design

### 2.1 Architecture
The project follows a **Clean/Layered Architecture** with the following layers:

* **Presentation Layer (Transport):**
  * HTTP handlers for API and web endpoints
  * Request validation and response formatting
  * Located in: `internal/transport/http/`
  * Three router groups:
    * `api/` - RESTful API endpoints (JSON)
    * `web/` - Web-facing endpoints (HTML/redirects)
    * `ops/` - Operational endpoints (health checks)

* **Business Logic Layer (Service):**
  * Core business rules and use cases
  * Located in: `internal/service/`
  * Orchestrates data flow between transport and repository layers

* **Data Access Layer (Repository):**
  * Database interactions via sqlc-generated code
  * Located in: `internal/repository/`
  * Type-safe queries and transactions

* **Infrastructure:**
  * Middleware: Authentication, context management, CORS
  * Configuration: Environment-based settings
  * Utilities: Helper functions and common code

### 2.2 Technology Stack
* **Language:** Go 1.25+
* **Web Framework:** Gin (`github.com/gin-gonic/gin`)
* **Database:** PostgreSQL 16+
* **Database Tooling:**
  * `sqlc` for type-safe code generation
  * `pgx` as the PostgreSQL driver
  * `golang-migrate` for schema migrations
* **Configuration:** `godotenv` for environment variables
* **Authentication:** 
  * Google OAuth2 (`golang.org/x/oauth2`)
  * JWT with ES256 signing
* **Security:**
  * `bcrypt` for client secret hashing
  * `crypto/rand` for secure random generation

### 2.3 Database Design

#### Schema Overview
PostgreSQL database with `pgcrypto` extension for UUID generation and secure random functions.

#### Tables

**1. `oauth_providers`**
Stores available OAuth provider configurations.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PK, Default: `gen_random_uuid()` | Unique provider identifier |
| `name` | TEXT | Unique, Not Null | Provider name (e.g., 'google') |
| `display_name` | TEXT | Not Null | Human-readable name |
| `client_id` | TEXT | Not Null | OAuth client ID |
| `client_secret` | TEXT | Not Null | OAuth client secret (encrypted) |
| `auth_url` | TEXT | Not Null | Authorization endpoint URL |
| `token_url` | TEXT | Not Null | Token exchange endpoint URL |
| `user_info_url` | TEXT | Not Null | User info endpoint URL |
| `scopes` | TEXT[] | Not Null | Default scopes to request |
| `is_enabled` | BOOLEAN | Default: false | Provider enabled status |
| `created_at` | TIMESTAMPTZ | Default: now() | Record creation time |
| `updated_at` | TIMESTAMPTZ | Default: now() | Last update time |

*Indexes:*
* `oauth_providers_pkey` PRIMARY KEY on `id`
* `oauth_providers_name_key` UNIQUE on `name`
* `idx_oauth_providers_is_enabled` on `is_enabled`

**2. `users`**
Stores user profiles and authentication information.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PK, Default: `gen_random_uuid()` | Unique identifier |
| `email` | TEXT | Unique, Not Null | User's email address |
| `email_verified` | BOOLEAN | Default: false | Email verification status |
| `first_name` | TEXT | Nullable | User's first name |
| `last_name` | TEXT | Nullable | User's last name |
| `is_active` | BOOLEAN | Default: true | Account active status |
| `is_admin` | BOOLEAN | Default: false | Administrator flag |
| `locale` | VARCHAR(10) | Default: 'en-US' | Preferred locale |
| `provider` | TEXT | Nullable | OAuth provider name |
| `provider_id` | TEXT | Nullable | Provider-specific user ID |
| `provider_data` | JSONB | Default: '{}' | Additional provider data |
| `last_login_at` | TIMESTAMPTZ | Nullable | Last successful login |
| `created_at` | TIMESTAMPTZ | Default: now() | Record creation time |
| `updated_at` | TIMESTAMPTZ | Default: now() | Last update time |

*Indexes:*
* `users_email_key` UNIQUE on `email`
* `users_provider_provider_id_key` UNIQUE on `(provider, provider_id)`
* `idx_users_is_admin` on `is_admin` for fast admin queries

**3. `clients`**
Stores registered OAuth2 client applications.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PK, Default: `gen_random_uuid()` | Unique client identifier |
| `name` | TEXT | Not Null | Client application name |
| `description` | TEXT | Nullable | Client description |
| `client_secret_hash` | TEXT | Not Null | Bcrypt hash of client secret |
| `redirect_uris` | TEXT[] | Not Null | Allowed redirect URIs |
| `grant_types` | TEXT[] | Not Null, Default: {'authorization_code'} | Allowed grant types |
| `is_active` | BOOLEAN | Default: true | Client active status |
| `created_by` | UUID | FK -> users(id), Not Null | Admin who created the client |
| `created_at` | TIMESTAMPTZ | Default: now() | Record creation time |
| `updated_at` | TIMESTAMPTZ | Default: now() | Last update time |

*Indexes:*
* `clients_pkey` PRIMARY KEY on `id`
* `idx_clients_is_active` on `is_active`
* Foreign key: `clients_created_by_fkey` references `users(id)`

**4. `authorization_codes`**
Tracks issued authorization codes for the Authorization Code Grant flow.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PK, Default: `gen_random_uuid()` | Unique code identifier |
| `code` | TEXT | Unique, Not Null | The authorization code |
| `client_id` | UUID | FK -> clients(id), Not Null | Associated client |
| `user_id` | UUID | FK -> users(id), Not Null | Authorized user |
| `provider_id` | UUID | FK -> oauth_providers(id), Not Null | OAuth provider used |
| `redirect_uri` | TEXT | Not Null | Redirect URI for this code |
| `scope` | TEXT | Default: '' | Requested scopes |
| `state` | TEXT | Nullable | Client-provided state |
| `code_challenge` | TEXT | Nullable | PKCE code challenge |
| `code_challenge_method` | VARCHAR(10) | Nullable | PKCE method (S256/plain) |
| `expires_at` | TIMESTAMPTZ | Not Null | Code expiration (≤ 5 minutes) |
| `used_at` | TIMESTAMPTZ | Nullable | When code was exchanged |
| `is_revoked` | BOOLEAN | Default: false | Revocation status |
| `created_at` | TIMESTAMPTZ | Default: now() | Record creation time |

*Indexes:*
* `authorization_codes_pkey` PRIMARY KEY on `id`
* `authorization_codes_code_key` UNIQUE on `code`
* `idx_authorization_codes_expires_at` on `expires_at`
* `idx_authorization_codes_user_id` on `user_id`
* `idx_authorization_codes_client_id` on `client_id`
* `idx_authorization_codes_provider_id` on `provider_id`
* Foreign keys:
  * `authorization_codes_client_id_fkey` references `clients(id) ON DELETE CASCADE`
  * `authorization_codes_user_id_fkey` references `users(id) ON DELETE CASCADE`
  * `authorization_codes_provider_id_fkey` references `oauth_providers(id) ON DELETE CASCADE`

**5. `access_tokens`**
Stores issued access tokens for auditing and revocation.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | UUID | PK, Default: `gen_random_uuid()` | Unique token identifier |
| `token_hash` | TEXT | Unique, Not Null | SHA-256 hash of the token |
| `client_id` | UUID | FK -> clients(id), Not Null | Associated client |
| `user_id` | UUID | FK -> users(id), Not Null | Token owner |
| `scope` | TEXT | Default: '' | Granted scopes |
| `expires_at` | TIMESTAMPTZ | Not Null | Token expiration (≤ 60 minutes) |
| `is_revoked` | BOOLEAN | Default: false | Revocation status |
| `created_at` | TIMESTAMPTZ | Default: now() | Token issuance time |

*Indexes:*
* `access_tokens_pkey` PRIMARY KEY on `id`
* `access_tokens_token_hash_key` UNIQUE on `token_hash`
* `idx_access_tokens_expires_at` on `expires_at`
* `idx_access_tokens_user_id` on `user_id`
* `idx_access_tokens_client_id` on `client_id`
* Foreign keys:
  * `access_tokens_client_id_fkey` references `clients(id) ON DELETE CASCADE`
  * `access_tokens_user_id_fkey` references `users(id) ON DELETE CASCADE`

**6. `schema_migrations`**
Tracks database migration state (managed by golang-migrate).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `version` | BIGINT | PK | Migration version number |
| `dirty` | BOOLEAN | Not Null | Migration state |

#### Database Triggers
* `set_updated_at` trigger on `oauth_providers`, `users`, `clients` tables to automatically update `updated_at` timestamp

### 2.4 API Design

The API follows RESTful principles and is organized into three main groups:

#### 2.4.1 Web Endpoints (`/web`)
User-facing web authentication flows.

**OAuth Provider Authentication Flow:**
* `GET /web/auth/{provider}/login?client_id={client_id}&redirect_uri={uri}&state={state}`
  * Parameters:
    * `provider` - OAuth provider name (e.g., 'google')
    * `client_id` - Client application identifier
    * `redirect_uri` - Client callback URI
    * `state` - CSRF protection token
  * Validates provider is enabled
  * Validates client_id and redirect_uri
  * Redirects to provider's consent screen
  
* `GET /web/auth/{provider}/callback?code={code}&state={state}`
  * Handles OAuth provider callback
  * Exchanges code for provider ID token
  * Creates/updates user account
  * Generates authorization code
  * Redirects to client's redirect_uri with authorization code

#### 2.4.2 API Endpoints (`/api/v1`)
JSON-based RESTful API for programmatic access.

**Authentication:**
* `GET /api/v1/auth/providers`
  * Public endpoint listing enabled OAuth providers
  * Response: `[{ "name": "google", "display_name": "Google" }]`
  * Used by clients to discover available authentication methods

* `POST /api/v1/auth/token`
  * Request Body: `{ "grant_type": "authorization_code", "code": "...", "client_id": "...", "client_secret": "...", "redirect_uri": "..." }`
  * Response: `{ "access_token": "...", "token_type": "Bearer", "expires_in": 3600 }`
  * Exchanges authorization code for access token

* `POST /api/v1/auth/logout`
  * Requires: Bearer token authentication
  * Revokes the current access token

**OAuth Provider Management (Admin Only):**
* `GET /api/v1/providers`
  * Lists all OAuth providers
  * Response: List of providers with configuration (secrets excluded)

* `GET /api/v1/providers/:id`
  * Retrieves provider details by ID
  * Excludes client_secret

* `POST /api/v1/providers`
  * Request Body: `{ "name": "google", "display_name": "Google", "client_id": "...", "client_secret": "...", "auth_url": "...", "token_url": "...", "user_info_url": "...", "scopes": ["openid", "email", "profile"] }`
  * Creates new OAuth provider configuration

* `PATCH /api/v1/providers/:id`
  * Request Body: `{ "is_enabled": true, "client_id": "...", "scopes": [...] }`
  * Updates provider configuration

* `DELETE /api/v1/providers/:id`
  * Disables OAuth provider (sets is_enabled=false)

**Client Management (Admin Only):**
* `GET /api/v1/clients`
  * Query params: `?page=1&limit=20&is_active=true`
  * Lists all registered clients
  * Response: Paginated client list

* `GET /api/v1/clients/:id`
  * Retrieves client details by ID
  * Excludes client_secret_hash

* `POST /api/v1/clients`
  * Request Body: `{ "name": "...", "description": "...", "redirect_uris": ["..."] }`
  * Response: `{ "id": "...", "client_secret": "...", ... }`
  * Note: client_secret is only returned once at creation

* `PATCH /api/v1/clients/:id`
  * Request Body: `{ "name": "...", "description": "...", "redirect_uris": [...], "is_active": true }`
  * Updates client configuration

* `POST /api/v1/clients/:id/regenerate-secret`
  * Generates new client secret
  * Response: `{ "client_secret": "..." }`
  * Note: Old secret is immediately invalidated

* `DELETE /api/v1/clients/:id`
  * Soft deletes client (sets is_active=false)
  * Cascades to revoke all tokens and codes

**User Management (Admin Only):**
* `GET /api/v1/users`
  * Query params: `?page=1&limit=20&is_active=true&is_admin=false`
  * Lists all users
  * Response: Paginated user list

* `PATCH /api/v1/users/:id`
  * Request Body: `{ "is_active": false }`
  * Disables/enables user account

**Session Management (Admin Only):**
* `GET /api/v1/sessions/codes`
  * Query params: `?page=1&limit=20&client_id=...&user_id=...&is_revoked=false`
  * Lists authorization codes
  
* `DELETE /api/v1/sessions/codes/:id`
  * Revokes an authorization code

* `GET /api/v1/sessions/tokens`
  * Query params: `?page=1&limit=20&client_id=...&user_id=...&is_revoked=false`
  * Lists access tokens
  
* `DELETE /api/v1/sessions/tokens/:id`
  * Revokes an access token

#### 2.4.3 Operational Endpoints (`/ops`)
* `GET /ops/health`
  * Returns: `{ "status": "ok", "timestamp": "..." }`
  * Health check endpoint

### 2.5 OAuth 2.0 Authorization Code Grant Flow

#### Flow Diagram
```
User → Client App → Goauth → OAuth Provider → Goauth → Client App → Goauth → Client App
```

#### Detailed Steps:

**1. Authorization Request**
```
Client redirects user to:
GET /web/auth/{provider}/login?
    client_id=<client_id>&
    redirect_uri=<client_redirect_uri>&
    state=<random_state>&
    scope=openid email profile
```

**2. Goauth Validation**
* Validates provider exists and is enabled
* Validates client_id exists and is active
* Validates redirect_uri matches registered URIs
* Retrieves provider configuration from database
* Stores state in session for CSRF protection
* Redirects to OAuth provider's authorization endpoint

**3. OAuth Provider Authentication**
* User authenticates with selected OAuth provider
* User consents to requested scopes
* OAuth provider redirects back to Goauth

**4. Provider Callback**
```
GET /web/auth/{provider}/callback?
    code=<provider_code>&
    state=<state>
```

**5. Goauth Processing**
* Validates state parameter (CSRF check)
* Exchanges provider code for ID token using provider's token endpoint
* Verifies ID token signature
* Extracts user information from provider
* Creates or updates user in database (with provider and provider_id)
* Generates authorization code (valid for 5 minutes)
* Stores code in `authorization_codes` table with provider_id

**6. Redirect to Client**
```
Redirect to: <client_redirect_uri>?
    code=<authorization_code>&
    state=<state>
```

**7. Token Exchange**
```
Client makes backend request:
POST /api/v1/auth/token
{
  "grant_type": "authorization_code",
  "code": "<authorization_code>",
  "client_id": "<client_id>",
  "client_secret": "<client_secret>",
  "redirect_uri": "<same_redirect_uri>"
}
```

**8. Token Issuance**
* Validates client credentials
* Validates authorization code:
  * Not expired (< 5 minutes)
  * Not already used
  * Not revoked
  * Matches client_id
  * Matches redirect_uri
* Marks code as used
* Generates JWT access token (valid for 60 minutes)
* Stores token hash in `access_tokens` table
* Returns access token to client

**9. API Access**
```
Client makes requests with:
Authorization: Bearer <access_token>
```

### 2.6 Security Design

#### 2.6.1 Authentication & Authorization

**User Authentication:**
* OAuth 2.0 providers as the authentication method (currently Google only)
* Provider must be enabled in the system before use
* ID token verification using provider's public keys
* Provider configuration stored securely in database
* Email verification status tracked

**Client Authentication:**
* Client ID and secret for token endpoint
* Client secret stored as bcrypt hash (cost factor 12)
* Secrets are cryptographically random (32 bytes, base64url encoded)

**Administrator Authorization:**
* `is_admin` flag in users table
* Middleware checks admin status for protected routes
* Admin-only endpoints reject non-admin users with 403 Forbidden

**Token-based Authorization:**
* JWT access tokens with ES256 signature
* Token payload includes: user_id, client_id, scope, exp, iat
* Middleware validates token signature and expiration
* Revoked tokens checked against database on each request

#### 2.6.2 CSRF Protection

**State Parameter:**
* Random state parameter generated for each OAuth flow
* Stored in encrypted session cookie
* Validated on callback to prevent CSRF attacks

**SameSite Cookies:**
* Session cookies use `SameSite=Lax` or `Strict`
* Prevents cross-site request forgery

**Double Submit Cookie (Future):**
* For API endpoints, implement double submit cookie pattern
* CSRF token in both cookie and request header

#### 2.6.3 XSS Prevention

* All user input sanitized before storage
* Content-Security-Policy headers configured
* HttpOnly cookies for sensitive data
* Output encoding for any rendered user content

#### 2.6.4 SQL Injection Prevention

* Exclusively use sqlc parameterized queries
* No dynamic SQL construction
* Input validation at transport layer

#### 2.6.5 CORS Configuration

* Whitelist allowed origins per client application
* Preflight request handling
* Credentials support for authorized origins
* Configured in middleware

#### 2.6.6 Rate Limiting

* Token endpoint: 10 requests per minute per IP
* Authorization endpoint: 20 requests per minute per IP
* Failed authentication: exponential backoff
* Implemented via middleware

#### 2.6.7 Secret Management

**OAuth Provider Secrets:**
* Stored encrypted in database using AES-256-GCM
* Encryption key stored in environment variable or secrets manager
* Never returned in API responses
* Updated via admin API with automatic re-encryption

**Client Secrets:**
* Generated using `crypto/rand` (32 bytes)
* Stored as bcrypt hash (never plaintext)
* Only shown once at creation/regeneration
* Rotation supported via regenerate endpoint

**JWT Signing Keys:**
* ES256 (ECDSA P-256) private/public key pair
* Private key stored in environment variable or secrets manager
* Keys rotated periodically (e.g., every 90 days)
* Public key exposed for token verification

**Environment Variables:**
* Database credentials
* Encryption key for provider secrets
* JWT signing keys
* Never committed to version control

#### 2.6.8 Token Security

**Authorization Codes:**
* Single-use only (marked used after exchange)
* Short expiration (5 minutes)
* Cryptographically random (32 bytes)
* Bound to client_id and redirect_uri

**Access Tokens:**
* JWT format with ES256 signature
* Maximum 60-minute expiration
* Stored hash in database for revocation
* No refresh tokens (re-authentication required)

**Token Revocation:**
* Immediate invalidation via database flag
* Middleware checks revocation status
* Admin can revoke individual tokens
* Client deletion cascades to token revocation

### 2.7 Data Flow Diagrams

#### 2.7.1 Client Registration Flow
```
Admin → POST /api/v1/clients → Service Layer
                                     ↓
                              Validate Input
                                     ↓
                              Generate Secret
                                     ↓
                              Hash Secret (bcrypt)
                                     ↓
                              Repository Layer
                                     ↓
                              INSERT INTO clients
                                     ↓
                              Return Client + Secret (one-time)
```

#### 2.7.2 Token Validation Flow
```
Request with Bearer Token → Auth Middleware
                                  ↓
                            Parse JWT
                                  ↓
                            Verify Signature
                                  ↓
                            Check Expiration
                                  ↓
                            Hash Token
                                  ↓
                            Query access_tokens
                                  ↓
                            Check is_revoked
                                  ↓
                      Allow/Deny Request
```

### 2.8 Error Handling

#### Error Response Format
```json
{
  "error": "invalid_request",
  "error_description": "The redirect_uri does not match registered URIs",
  "timestamp": "2026-01-30T12:00:00Z"
}
```

#### HTTP Status Codes
* `200 OK` - Successful request
* `201 Created` - Resource created
* `204 No Content` - Successful deletion
* `400 Bad Request` - Invalid input
* `401 Unauthorized` - Missing or invalid authentication
* `403 Forbidden` - Insufficient permissions
* `404 Not Found` - Resource not found
* `409 Conflict` - Resource conflict (e.g., duplicate)
* `422 Unprocessable Entity` - Validation error
* `429 Too Many Requests` - Rate limit exceeded
* `500 Internal Server Error` - Server error

#### OAuth 2.0 Error Codes
* `invalid_request` - Malformed request
* `invalid_client` - Client authentication failed
* `invalid_grant` - Authorization code invalid/expired
* `unauthorized_client` - Client not authorized
* `unsupported_grant_type` - Grant type not supported
* `invalid_scope` - Invalid scope requested
* `server_error` - Internal server error

### 2.9 Deployment Architecture

#### Container Structure
```
┌─────────────────────────────────────┐
│   Docker Compose / Kubernetes       │
├─────────────────────────────────────┤
│                                     │
│  ┌──────────────┐  ┌─────────────┐ │
│  │  Goauth API  │  │ PostgreSQL  │ │
│  │  Container   │  │  Container  │ │
│  │  (Port 8080) │  │ (Port 5432) │ │
│  └──────────────┘  └─────────────┘ │
│                                     │
└─────────────────────────────────────┘
```

#### Environment Configuration
* Development: `.env` file with `godotenv`
* Production: Kubernetes secrets or cloud secret manager
* Configuration validation on startup

#### Database Migrations
* Automated on container startup
* Version tracking in `schema_migrations`
* Rollback capability for failed migrations

### 2.10 Monitoring and Logging

#### Logging Strategy
* Structured logging (JSON format)
* Log levels: DEBUG, INFO, WARN, ERROR
* Request ID for tracing
* Security events logged:
  * Failed authentication attempts
  * Token revocations
  * Admin actions
  * Client secret regenerations

#### Metrics (Future)
* Request count by endpoint
* Response time percentiles
* Error rates
* Token issuance rate
* Active user count

### 2.11 Testing Strategy

#### Unit Tests
* Service layer business logic
* Middleware functions
* Utility functions
* Target: >80% code coverage

#### Integration Tests
* Repository layer with test database
* End-to-end API flows
* OAuth flow testing
* Database transactions

#### Security Tests
* SQL injection attempts
* XSS payload testing
* CSRF token validation
* Token expiration and revocation
* Rate limiting

#### Test Database
* Docker-based PostgreSQL for tests
* Automatic cleanup between tests
* Seeded test data for consistency

## 3. Implementation Plan

### Phase 1: Database Schema
* Create migrations for new tables:
  * `oauth_providers`
  * `clients`
  * `authorization_codes`
  * `access_tokens`
* Add `is_admin` column to `users` table
* Create indexes and foreign keys
* Seed initial Google OAuth provider configuration
* Update schema dump

### Phase 2: Repository Layer
* Write SQL queries in `db/queries/`:
  * `oauth_providers.sql`
  * `clients.sql`
  * `authorization_codes.sql`
  * `access_tokens.sql`
  * Update `users.sql`
* Generate code with `sqlc generate`
* Write repository tests

### Phase 3: Service Layer
* Implement OAuth provider management service
* Implement client management service
* Implement authorization code flow service (with provider selection)
* Implement token management service
* Add administrator authorization checks
* Write service layer tests

### Phase 4: API Layer
* Implement OAuth provider management endpoints
* Implement client management endpoints
* Implement OAuth 2.0 token endpoint
* Implement session management endpoints
* Update OAuth flow for provider-based Authorization Code Grant
* Add admin middleware
* Write API integration tests

### Phase 5: Security Hardening
* Implement rate limiting
* Add CORS configuration
* Enhance CSRF protection
* Security audit and penetration testing
* Add security logging

### Phase 6: Documentation & Deployment
* API documentation (OpenAPI/Swagger)
* Administrator guide
* Client integration guide
* Docker deployment configuration
* CI/CD pipeline setup

## 4. API Reference Examples

### 4.1 Client Registration

**Request:**
```http
POST /api/v1/clients
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "name": "My Web App",
  "description": "Customer-facing web application",
  "redirect_uris": [
    "https://myapp.com/auth/callback",
    "https://myapp.com/auth/callback/alternate"
  ]
}
```

**Response:**
```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "My Web App",
  "description": "Customer-facing web application",
  "client_secret": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
  "redirect_uris": [
    "https://myapp.com/auth/callback",
    "https://myapp.com/auth/callback/alternate"
  ],
  "grant_types": ["authorization_code"],
  "is_active": true,
  "created_at": "2026-01-30T12:00:00Z"
}
```

**Note:** The `client_secret` is only returned once. Store it securely.

### 4.2 OAuth Provider Configuration (Admin)

**Request:**
```http
POST /api/v1/providers
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "name": "google",
  "display_name": "Google",
  "client_id": "xxx.apps.googleusercontent.com",
  "client_secret": "GOCSPX-xxx",
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_url": "https://oauth2.googleapis.com/token",
  "user_info_url": "https://www.googleapis.com/oauth2/v2/userinfo",
  "scopes": ["openid", "email", "profile"],
  "is_enabled": true
}
```

**Response:**
```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "id": "440e8400-e29b-41d4-a716-446655440000",
  "name": "google",
  "display_name": "Google",
  "client_id": "xxx.apps.googleusercontent.com",
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_url": "https://oauth2.googleapis.com/token",
  "user_info_url": "https://www.googleapis.com/oauth2/v2/userinfo",
  "scopes": ["openid", "email", "profile"],
  "is_enabled": true,
  "created_at": "2026-01-30T10:00:00Z",
  "updated_at": "2026-01-30T10:00:00Z"
}
```

**Note:** The `client_secret` is encrypted and stored securely, never returned in responses.

### 4.3 Authorization Flow

**Step 1: Redirect to Login (using Google provider)**
```http
GET /web/auth/google/login?client_id=550e8400-e29b-41d4-a716-446655440000&redirect_uri=https://myapp.com/auth/callback&state=xyz123&scope=openid%20email%20profile
```

**Step 2: User redirected back to client**
```http
HTTP/1.1 302 Found
Location: https://myapp.com/auth/callback?code=AUTH_CODE_HERE&state=xyz123
```

**Step 3: Exchange code for token**
```http
POST /api/v1/auth/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "code": "AUTH_CODE_HERE",
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_secret": "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
  "redirect_uri": "https://myapp.com/auth/callback"
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid email profile"
}
```

### 4.4 List Users (Admin)

**Request:****
```http
GET /api/v1/users?page=1&limit=20&is_active=true
Authorization: Bearer <admin_token>
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": [
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "email": "user@example.com",
      "email_verified": true,
      "first_name": "John",
      "last_name": "Doe",
      "is_active": true,
      "is_admin": false,
      "last_login_at": "2026-01-30T11:00:00Z",
      "created_at": "2026-01-15T09:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

### 4.5 Revoke Token (Admin)

**Request:****
```http
DELETE /api/v1/sessions/tokens/770e8400-e29b-41d4-a716-446655440002
Authorization: Bearer <admin_token>
```

**Response:**
```http
HTTP/1.1 204 No Content
```

## 5. Appendices

### Appendix A: Database Schema SQL

See `db/migrations/` for detailed migration files.

### Appendix B: Configuration Reference

**Environment Variables:**
```bash
# Server
SERVER_PORT=8080
SERVER_HOST=0.0.0.0

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=goauth
DB_USER=goauth
DB_PASSWORD=secret

# JWT
JWT_PRIVATE_KEY=<base64-encoded-ES256-private-key>
JWT_PUBLIC_KEY=<base64-encoded-ES256-public-key>
JWT_EXPIRATION_MINUTES=60

# Security
ENCRYPTION_KEY=<32-byte-hex-key-for-provider-secrets>
ALLOWED_ORIGINS=https://admin.example.com,https://app.example.com
CSRF_SECRET=<random-32-byte-hex>
```

**Note:** OAuth provider configurations (Google, etc.) are managed through the database and admin API, not environment variables.

### Appendix C: Client Secret Format

Client secrets are generated as follows:
* 32 random bytes from `crypto/rand`
* Base64URL encoded (no padding)
* Example: `aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789`
* Stored as bcrypt hash with cost factor 12

### Appendix D: JWT Token Structure

**Header:**
```json
{
  "alg": "ES256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "sub": "660e8400-e29b-41d4-a716-446655440001",
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "scope": "openid email profile",
  "exp": 1706616000,
  "iat": 1706612400,
  "jti": "770e8400-e29b-41d4-a716-446655440002"
}
```

**Claims:**
* `sub` - User ID (subject)
* `client_id` - Client application ID
* `scope` - Granted scopes
* `exp` - Expiration timestamp
* `iat` - Issued at timestamp
* `jti` - JWT ID (token record ID in database)

### Appendix E: Glossary

* **Authorization Code:** Short-lived code exchanged for access token
* **Access Token:** JWT bearer token for API authentication
* **Client:** Registered OAuth 2.0 client application
* **Grant Type:** OAuth 2.0 flow type (Authorization Code Grant)
* **OAuth Provider:** External identity provider (e.g., Google) that authenticates users
* **PKCE:** Proof Key for Code Exchange (optional extension)
* **Redirect URI:** Client URL where user is redirected after authorization
* **Scope:** Requested permissions (e.g., openid, email, profile)
* **State:** CSRF protection parameter in OAuth flow
