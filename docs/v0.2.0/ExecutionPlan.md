# Execution Plan - v0.2.0

## Document Information
* **Version:** 0.2.0
* **Created:** February 1, 2026
* **Based on:** System Design Document v0.2.0
* **Project:** Goauth Server

## 1. Executive Summary

This document provides a detailed, step-by-step execution plan for implementing version 0.2.0 of the Goauth authentication and authorization service. The implementation is structured into 6 sequential phases, each with specific tasks, deliverables, and acceptance criteria.

### 1.0 Architectural Overview

**Client-Scoped OAuth Provider Model:**

Version 0.2.0 implements a client-scoped OAuth provider architecture where:

- Each OAuth provider belongs to a specific client application
- Clients can configure multiple OAuth providers (e.g., Google, GitHub, Microsoft)
- Providers are isolated between clients - Client A's providers are independent from Client B's providers
- The same provider type (e.g., "google") can be configured differently for each client
- This enables multi-tenancy and allows each client application to maintain its own OAuth integrations

This architecture provides flexibility for SaaS scenarios where different client applications need different OAuth configurations and provider options.

### 1.1 Project Objectives

* Implement OAuth 2.0 Authorization Code Grant flow
* Enable client-scoped OAuth provider management (each client can configure multiple providers)
* Implement administrator capabilities for managing users, clients, and sessions
* Establish secure token and session management
* Deploy containerized solution with PostgreSQL backend

### 1.2 Key Deliverables

* Database schema with 6 tables (users, clients, oauth_providers, authorization_codes, access_tokens, schema_migrations)
* OAuth providers scoped to clients with many-to-one relationship
* Complete API with 3 router groups (web, api, ops)
* Admin management interface for clients, client-scoped providers, users, and sessions
* Security features including rate limiting, CORS, CSRF protection
* Docker deployment configuration
* Comprehensive test coverage (>80%)

## 2. Phase 1: Database Schema

**Duration:** Week 1  
**Dependencies:** None  
**Owner:** Backend Team

### 2.1 Task 1.1: Create clients Table Migration

**Priority:** High  
**Estimated Time:** 4 hours  
**Dependencies:** Task 1.2 complete (users table must exist first)

**Steps:**
1. Create migration file: `migrate create -ext sql -dir ./db/migrations create_clients_table`
2. Implement table with all columns per System Design
3. Create foreign key to users(id) for created_by
4. Create indexes on id and is_active
5. Add updated_at trigger
6. Create rollback migration

**Acceptance Criteria:**
- [x] All columns match specification
- [x] Foreign key constraint works correctly
- [x] Default grant_types array includes 'authorization_code'
- [x] Indexes created
- [x] Cascade delete behavior not set (preserve audit trail)
- [x] Migration and rollback work

**Deliverables:**
- `20260213100111_create_clients_table.up.sql` ✓
- `20260213100111_create_clients_table.down.sql` ✓

### 2.2 Task 1.2: Update users Table Migration

**NOTE:** This task should be completed BEFORE Task 1.1 since clients table depends on users table.

**Priority:** High  
**Estimated Time:** 2 hours  
**Dependencies:** Existing users table

**Steps:**
1. Create migration file: `migrate create -ext sql -dir ./db/migrations add_is_admin_to_users`
2. Add is_admin column:
   ```sql
   ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT false;
   ```
3. Create index:
   ```sql
   CREATE INDEX idx_users_is_admin ON users(is_admin);
   ```
4. Create rollback migration

**Acceptance Criteria:**
- [x] is_admin column added with correct default
- [x] Index created on is_admin column
- [x] Existing users have is_admin = false
- [x] Migration and rollback work correctly

**Deliverables:**
- `20260213095938_add_is_admin_to_users.up.sql` ✓
- `20260213095938_add_is_admin_to_users.down.sql` ✓

### 2.3 Task 1.3: Create oauth_providers Table Migration

**Priority:** High  
**Estimated Time:** 5 hours  
**Dependencies:** Task 1.1 complete (clients table must exist first)

**Steps:**
1. Create migration file: `migrate create -ext sql -dir ./db/migrations create_oauth_providers_table`
2. Implement table schema:
   ```sql
   CREATE TABLE oauth_providers (
       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
       name TEXT NOT NULL,
       display_name TEXT NOT NULL,
       provider_client_id TEXT NOT NULL,
       provider_client_secret TEXT NOT NULL,
       auth_url TEXT NOT NULL,
       token_url TEXT NOT NULL,
       user_info_url TEXT NOT NULL,
       scopes TEXT[] NOT NULL,
       is_enabled BOOLEAN DEFAULT false,
       created_at TIMESTAMPTZ DEFAULT now(),
       updated_at TIMESTAMPTZ DEFAULT now(),
       UNIQUE(client_id, name)
   );
   ```
3. Create indexes:
   ```sql
   CREATE INDEX idx_oauth_providers_client_id ON oauth_providers(client_id);
   CREATE INDEX idx_oauth_providers_is_enabled ON oauth_providers(is_enabled);
   CREATE INDEX idx_oauth_providers_client_enabled ON oauth_providers(client_id, is_enabled);
   ```
4. Add updated_at trigger
5. Create rollback migration

**Acceptance Criteria:**
- [x] Migration file created and executable
- [x] client_id foreign key with CASCADE delete configured
- [x] Unique constraint on (client_id, name) prevents duplicate provider names per client
- [x] Multiple clients can use same provider name (e.g., 'google')
- [x] All indexes created correctly
- [x] Trigger for updated_at column works
- [x] Rollback migration works correctly
- [x] Migration runs successfully after clients table exists

**Deliverables:**
- `20260216155147_create_oauth_providers_table.up.sql` ✓
- `20260216155147_create_oauth_providers_table.down.sql` ✓

### 2.4 Task 1.4: Create authorization_codes Table Migration

**NOTE:** Provider referenced in authorization_codes is now client-scoped via the oauth_providers table.

**Priority:** High  
**Estimated Time:** 5 hours

**Steps:**
1. Create migration file: `migrate create -ext sql -dir ./db/migrations create_authorization_codes_table`
2. Implement complete table schema
3. Create foreign keys:
   - client_id → clients(id) ON DELETE CASCADE
   - user_id → users(id) ON DELETE CASCADE
   - provider_id → oauth_providers(id) ON DELETE CASCADE
4. Create all required indexes
5. Create rollback migration

**Acceptance Criteria:**
- [x] All columns including provider_id present
- [x] All three foreign keys with CASCADE delete
- [x] Unique constraint on code column
- [x] All indexes created (expires_at, user_id, client_id, provider_id)
- [x] Migration and rollback work

**Deliverables:**
- `20260216155730_create_authorization_codes_table.up.sql` ✓
- `20260216155730_create_authorization_codes_table.down.sql` ✓

### 2.5 Task 1.5: Create access_tokens Table Migration

**Priority:** High  
**Estimated Time:** 4 hours

**Steps:**
1. Create migration file: `migrate create -ext sql -dir ./db/migrations create_access_tokens_table`
2. Implement table schema
3. Create foreign keys with CASCADE delete
4. Create indexes on token_hash, expires_at, user_id, client_id
5. Create rollback migration

**Acceptance Criteria:**
- [x] All columns match specification
- [x] token_hash has unique constraint
- [x] Foreign keys with CASCADE delete work
- [x] All indexes created
- [x] Migration and rollback work

**Deliverables:**
- `20260301120000_create_access_tokens_table.up.sql` ✓
- `20260301120000_create_access_tokens_table.down.sql` ✓

### 2.6 Task 1.6: Update Schema Dump

**Priority:** Low  
**Estimated Time:** 1 hour  
**Dependencies:** All migrations complete

**Steps:**
1. Run all migrations on clean database
2. Execute schema dump script: `./db/scripts/dump_schema.sh`
3. Verify `db/schema/schema.sql` is updated
4. Review schema for correctness
5. Commit schema dump

**Acceptance Criteria:**
- [x] Schema dump includes all new tables
- [x] All indexes and foreign keys present
- [x] Triggers included
- [x] Schema is properly formatted

**Deliverables:**
- Updated `db/schema/schema.sql` ✓

### Phase 1 Completion Checklist

- [x] Users table migration with is_admin column created
- [x] Clients table migration created and tested
- [x] OAuth providers table migration created with client_id FK
- [x] Authorization codes table migration created
- [x] Access tokens table migration created
- [x] All indexes created
- [x] All foreign keys configured correctly with proper cascade behavior
- [x] Unique constraint on (client_id, name) for oauth_providers works
- [x] Triggers for updated_at columns work
- [ ] Optional development seed data created (if desired)
- [x] Schema dump updated
- [x] All migrations can be rolled back
- [x] Database documentation updated
- [x] Migration order verified: users -> clients -> oauth_providers -> codes/tokens

## 3. Phase 2: Repository Layer

**Duration:** Week 1-2  
**Dependencies:** Phase 1 complete  
**Owner:** Backend Team

### 3.1 Task 2.1: Create oauth_providers.sql Queries

**Priority:** High  
**Estimated Time:** 6 hours

**Steps:**
1. Create file: `db/queries/oauth_providers.sql`
2. Implement queries:

```sql
-- name: GetOAuthProvider :one
SELECT * FROM oauth_providers
WHERE id = $1 LIMIT 1;

-- name: GetOAuthProviderByClientAndName :one
SELECT * FROM oauth_providers
WHERE client_id = $1 AND name = $2 LIMIT 1;

-- name: ListOAuthProvidersByClient :many
SELECT * FROM oauth_providers
WHERE client_id = $1
ORDER BY display_name;

-- name: ListEnabledOAuthProvidersByClient :many
SELECT * FROM oauth_providers
WHERE client_id = $1 AND is_enabled = true
ORDER BY display_name;

-- name: CreateOAuthProvider :one
INSERT INTO oauth_providers (
    client_id, name, display_name, provider_client_id, provider_client_secret,
    auth_url, token_url, user_info_url, scopes, is_enabled
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
) RETURNING *;

-- name: UpdateOAuthProvider :one
UPDATE oauth_providers
SET display_name = $2,
    provider_client_id = $3,
    provider_client_secret = $4,
    auth_url = $5,
    token_url = $6,
    user_info_url = $7,
    scopes = $8,
    is_enabled = $9,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteOAuthProvider :exec
DELETE FROM oauth_providers
WHERE id = $1;

-- name: DisableOAuthProvider :exec
UPDATE oauth_providers
SET is_enabled = false, updated_at = now()
WHERE id = $1;
```

3. Run `sqlc generate`
4. Verify generated code in `internal/repository/`

**Acceptance Criteria:**
- [x] All CRUD operations implemented
- [x] Queries filtered by client_id where appropriate
- [x] GetOAuthProviderByClientAndName enforces client scope
- [x] Queries use proper parameter binding
- [x] sqlc generates code without errors
- [x] Generated methods have correct signatures

**Deliverables:**
- `db/queries/oauth_providers.sql` ✓
- Generated Go code in `internal/repository/` ✓

### 3.2 Task 2.2: Create clients.sql Queries

**Priority:** High  
**Estimated Time:** 6 hours

**Steps:**
1. Create file: `db/queries/clients.sql`
2. Implement queries for CRUD operations:
   - GetClient
   - ListClients (with pagination and filters)
   - CreateClient
   - UpdateClient
   - DeleteClient (soft delete)
   - RegenerateClientSecret
3. Run `sqlc generate`

**Acceptance Criteria:**
- [x] All queries support required operations
- [x] Pagination implemented with LIMIT/OFFSET
- [x] Filters for is_active status
- [x] Soft delete sets is_active = false
- [x] sqlc generation successful

**Deliverables:**
- `db/queries/clients.sql` ✓
- Generated repository code ✓

### 3.3 Task 2.3: Create authorization_codes.sql Queries

**Priority:** High  
**Estimated Time:** 6 hours

**Steps:**
1. Create file: `db/queries/authorization_codes.sql`
2. Implement queries:
   - GetAuthorizationCode (by code string)
   - GetAuthorizationCodeByID
   - ListAuthorizationCodes (with filters)
   - CreateAuthorizationCode
   - MarkAuthorizationCodeUsed
   - RevokeAuthorizationCode
   - DeleteExpiredAuthorizationCodes (cleanup job)
3. Include provider_id in all relevant queries
4. Run `sqlc generate`

**Acceptance Criteria:**
- [x] All queries include provider_id column
- [x] Filters for client_id, user_id, is_revoked
- [x] Mark as used updates used_at timestamp
- [x] Cleanup query for expired codes
- [x] sqlc generation successful

**Deliverables:**
- `db/queries/authorization_codes.sql` ✓
- Generated repository code ✓

### 3.4 Task 2.4: Create access_tokens.sql Queries

**Priority:** High  
**Estimated Time:** 6 hours

**Steps:**
1. Create file: `db/queries/access_tokens.sql`
2. Implement queries:
   - GetAccessToken (by token_hash)
   - GetAccessTokenByID
   - ListAccessTokens (with filters)
   - CreateAccessToken
   - RevokeAccessToken
   - RevokeAccessTokensByClient
   - RevokeAccessTokensByUser
   - DeleteExpiredAccessTokens (cleanup job)
3. Run `sqlc generate`

**Acceptance Criteria:**
- [x] token_hash used for lookups (not plain token)
- [x] Filters for client_id, user_id, is_revoked
- [x] Bulk revocation by client and user
- [x] Cleanup query for expired tokens
- [x] sqlc generation successful

**Deliverables:**
- `db/queries/access_tokens.sql` ✓
- Generated repository code ✓

### 3.5 Task 2.5: Update users.sql Queries

**Priority:** Medium  
**Estimated Time:** 4 hours  
**Dependencies:** Existing users.sql

**Steps:**
1. Update `db/queries/users.sql`
2. Add queries:
   - ListUsers (with pagination, filters for is_active, is_admin)
   - UpdateUserActiveStatus
   - GetUsersByAdmin (filter is_admin = true/false)
3. Update existing queries to include is_admin column
4. Run `sqlc generate`

**Acceptance Criteria:**
- [x] All existing queries include is_admin
- [x] New admin-related queries implemented
- [x] Pagination support added
- [x] sqlc generation successful

**Deliverables:**
- Updated `db/queries/users.sql` ✓
- Updated repository code ✓

### 3.6 Task 2.6: Write Repository Unit Tests

**Priority:** High  
**Estimated Time:** 12 hours  
**Dependencies:** All query files created

**Steps:**
1. Set up test database using Docker (testcontainers)
2. Create test fixtures and seed data
3. Write tests for `oauth_providers` repository:
   - Test CRUD operations
   - Test unique constraint on name
   - Test enabled/disabled filtering
4. Write tests for `clients` repository
5. Write tests for `authorization_codes` repository
6. Write tests for `access_tokens` repository
7. Update tests for `users` repository
8. Ensure >80% code coverage for repository layer

**Acceptance Criteria:**
- [x] All repository methods have tests
- [x] Tests use isolated test database
- [x] Test database cleaned between tests
- [x] Foreign key constraints tested
- [x] Edge cases covered
- [x] Code coverage >80% (achieved 90%)
- [x] All tests pass

**Deliverables:**
- `internal/repository/oauth_providers_test.go` ✓
- `internal/repository/clients_test.go` ✓
- `internal/repository/authorization_codes_test.go` ✓
- `internal/repository/access_tokens_test.go` ✓
- Updated `internal/repository/users_test.go` ✓
- `internal/repository/testhelpers_test.go` ✓ (shared test fixtures)

**Notes:**
- Fixed `models.go`: `AuthorizationCode.UsedAt` changed from `time.Time` to `*time.Time` to correctly handle NULL values from the database.
- Fixed `runMigrations` to run all 6 migrations in order (previously only ran the initial users migration).
- All tests use transaction-based isolation (rolled back after each test).

### Phase 2 Completion Checklist

- [x] All SQL query files created
- [x] sqlc code generation successful
- [x] All repository methods available
- [x] Unit tests written for all repositories
- [x] Tests pass with >80% coverage (90%)
- [x] Code review completed
- [x] Documentation updated

## 4. Phase 3: Service Layer

**Duration:** Week 2-3  
**Dependencies:** Phase 2 complete  
**Owner:** Backend Team

### 4.1 Task 3.1: Implement OAuth Provider Service

**Priority:** High  
**Estimated Time:** 8 hours

**Steps:**
1. Create `internal/service/provider/provider.go`
2. Implement service struct with repository dependency
3. Implement methods:
   - `ListProvidersByClient(clientID)` - List all providers for a client
   - `ListEnabledProvidersByClient(clientID)` - Public endpoint data for client
   - `GetProvider(id)` - Get provider details (validate client ownership)
   - `GetProviderByClientAndName(clientID, name)` - Get by client and name
   - `CreateProvider(clientID, dto, adminUserID)` - Create with secret encryption
   - `UpdateProvider(id, dto, adminUserID)` - Update with secret re-encryption (validate ownership)
   - `EnableProvider(id, adminUserID)` - Enable provider (validate ownership)
   - `DisableProvider(id, adminUserID)` - Disable provider (validate ownership)
   - `DeleteProvider(id, adminUserID)` - Delete provider (validate ownership)
4. Implement encryption/decryption for provider_client_secret using AES-256-GCM
5. Add input validation
6. Add client ownership validation for all operations

**Acceptance Criteria:**
- [x] All service methods implemented
- [x] Provider client secrets encrypted before storage
- [x] Provider client secrets decrypted when needed for OAuth flow
- [x] Secrets never returned in API responses
- [x] Client ownership validated for all provider operations
- [x] Input validation for all fields
- [x] Error handling for duplicate names within client scope
- [x] URL validation for OAuth endpoints

**Deliverables:**
- `internal/service/provider/provider.go` ✓
- `internal/service/provider/encryption.go` ✓
- `internal/service/provider/validation.go` ✓

### 4.2 Task 3.2: Implement Client Management Service

**Priority:** High  
**Estimated Time:** 10 hours

**Steps:**
1. Create `internal/service/client/client.go`
2. Implement service methods:
   - `ListClients(filters)` - With pagination
   - `GetClient(id)` - Get details (exclude secret hash)
   - `CreateClient(dto, adminUserID)` - Generate and hash secret
   - `UpdateClient(id, dto)` - Update configuration
   - `RegenerateSecret(id)` - Generate new secret
   - `DeleteClient(id)` - Soft delete
3. Implement client secret generation (32 bytes, base64url)
4. Implement bcrypt hashing (cost 12)
5. Add redirect URI validation
6. Implement authorization check (admin only)

**Acceptance Criteria:**
- [x] Client secrets generated cryptographically secure
- [x] Secrets hashed with bcrypt before storage
- [x] Plain secret only returned once at creation/regeneration
- [x] Redirect URIs validated (HTTPS in production)
- [x] Admin authorization checked
- [x] Pagination implemented
- [x] Soft delete sets is_active = false

**Deliverables:**
- `internal/service/client/client.go` ✓
- `internal/service/client/validation.go` ✓

**Notes:**
- `ListClients` defaults to active clients when `IsActive` filter is nil, consistent with the underlying repository's boolean parameter for `is_active`.
- `CreateClientDTO.IsActive` allows creating clients in an inactive state (useful for staged rollouts).
- Client secrets are 32 random bytes encoded as base64url (43 characters); hashed with bcrypt cost 12 before storage.
- HTTPS enforcement on redirect URIs is gated on `env == "production"`; loopback addresses (localhost, 127.0.0.1, ::1) are always permitted over HTTP.

### 4.3 Task 3.3: Implement Authorization Code Flow Service

**Priority:** Critical  
**Estimated Time:** 16 hours

**Steps:**
1. Create `internal/service/auth/authorization.go`
2. Implement authorization initiation:
   - `InitiateAuthorization(clientID, providerName, redirectURI, state, scope)`
   - Validate client exists and is active
   - Validate provider exists for client and is enabled
   - Validate redirect URI matches registered URIs
   - Generate OAuth provider authorization URL
   - Store state in session with client context
3. Implement provider callback handling:
   - `HandleProviderCallback(clientID, providerName, code, state)`
   - Validate state matches session
   - Get provider by client and name
   - Exchange provider code for ID token
   - Verify ID token signature
   - Extract user info
   - Create/update user in database
   - Generate authorization code
   - Store code with provider_id and client_id
4. Implement token exchange:
   - `ExchangeCodeForToken(code, clientID, clientSecret, redirectURI)`
   - Validate client credentials
   - Validate authorization code (not expired, not used, not revoked)
   - Verify code belongs to client
   - Verify redirect URI matches
   - Mark code as used
   - Generate JWT access token
   - Store token hash in database
   - Return access token
5. Implement logout:
   - `RevokeToken(tokenHash)`
   - Mark token as revoked

**Acceptance Criteria:**
- [x] Client validation works
- [x] Provider selection validates client ownership
- [x] Provider enabled check enforced within client scope
- [x] Redirect URI validation strict
- [x] State parameter CSRF protection works (state passed through to provider; session validation is at the transport layer)
- [x] ID token verification implemented (generic user-info endpoint approach; works for both OIDC and plain OAuth2)
- [x] User creation/update logic works
- [x] Authorization codes expire in 5 minutes
- [x] Codes are single-use
- [x] Code-to-client binding verified
- [x] JWT tokens expire in 60 minutes (configurable via ACCESS_TOKEN_EXPIRY_MINUTES)
- [x] Token revocation immediate

**Deliverables:**
- `internal/service/auth/authorization.go` ✓
- `internal/service/auth/token.go` ✓
- `internal/service/auth/provider_client.go` ✓

**Notes:**
- `InitiateAuthorization` accepts two redirect URI parameters: `callbackURL` (our server's provider callback endpoint) and `clientRedirectURI` (client app's final redirect URI validated against the DB).
- `HandleProviderCallback` fetches user info via the provider's `user_info_url`, normalising common field-name variants across providers (e.g. `given_name`/`first_name`).
- `ExchangeCodeForToken` validates the authorization code (not expired, not used, not revoked, correct client, correct redirect URI), marks it as used, issues a JWT, stores its SHA-256 hash for revocation, and returns a `TokenResponse`.
- `RevokeToken` looks up the token by hash and sets `is_revoked = true`.
- `AccessTokenManager.Expiry()` was added to `internal/auth/access_token.go` to expose the configured token lifetime.
- `GetProviderWithSecretByClientAndName` was added to `internal/service/provider/provider.go` to support the auth flow.
- `AuthService` was updated to accept a `*provider.Service` dependency; `server.go` was updated accordingly.

### 4.4 Task 3.4: Implement Session Management Service

**Priority:** High  
**Estimated Time:** 6 hours

**Steps:**
1. Create `internal/service/session/session.go`
2. Implement methods:
   - `ListAuthorizationCodes(filters)` - With pagination
   - `RevokeAuthorizationCode(id)` - Admin only
   - `ListAccessTokens(filters)` - With pagination
   - `RevokeAccessToken(id)` - Admin only
   - `RevokeUserSessions(userID)` - Revoke all user tokens
   - `RevokeClientSessions(clientID)` - Revoke all client tokens
3. Add admin authorization checks
4. Implement cleanup jobs for expired codes/tokens

**Acceptance Criteria:**
- [x] Pagination implemented for lists
- [x] Filters work correctly
- [x] Admin-only authorization enforced (service layer; middleware enforcement at transport layer)
- [x] Bulk revocation works
- [x] Cleanup jobs functional

**Deliverables:**
- `internal/service/session/session.go` ✓

**Notes:**
- `ListAuthorizationCodes` and `ListAccessTokens` accept optional `*uuid.UUID` and `*bool` filter pointers; nil values skip that dimension of filtering.
- Cleanup methods `CleanupExpiredCodes` and `CleanupExpiredTokens` call the corresponding repository `DeleteExpired*` queries and are designed to be invoked by a periodic background job.
- Bulk revocation via `RevokeUserSessions` / `RevokeClientSessions` delegates to `RevokeAccessTokensByUser` / `RevokeAccessTokensByClient` repository queries respectively.
- Admin authorisation enforcement is intentionally left to the transport layer (middleware) rather than duplicated inside the service.

### 4.5 Task 3.5: Implement User Management Service

**Priority:** Medium  
**Estimated Time:** 4 hours

**Steps:**
1. Create `internal/service/user/user.go`
2. Implement methods:
   - `ListUsers(filters)` - With pagination
   - `GetUser(id)` - Get user details
   - `UpdateUserStatus(id, isActive)` - Enable/disable account
   - `IsAdmin(userID)` - Check admin status
3. Add admin authorization checks

**Acceptance Criteria:**
- [x] Pagination works
- [x] Status update sets is_active
- [x] Admin check used by middleware
- [x] Filters work correctly

**Deliverables:**
- `internal/service/user/user.go` ✓

**Notes:**
- `ListUsersParams` uses `*bool` pointers for `IsActive` and `IsAdmin` filters; nil values fall back to sensible defaults (`IsActive` nil → true, `IsAdmin` nil → false) because the underlying repository query (`ListUsers`) always applies both filters as non-nullable booleans.
- `IsAdmin(userID)` fetches the user by ID and dereferences the nullable `*bool` field, returning `false` for NULL values in the database.
- `UpdateUserStatus` returns the updated `User` so callers can confirm the new state without a separate read.
- Service-level `User` model omits OAuth provider fields (`Provider`, `ProviderID`, `ProviderData`) to avoid leaking internal OAuth implementation details in API responses.

### 4.6 Task 3.6: Write Service Layer Unit Tests

**Priority:** High  
**Estimated Time:** 16 hours

**Steps:**
1. Mock repository layer interfaces
2. Write tests for provider service
3. Write tests for client service (including secret generation)
4. Write tests for authorization flow (complex scenarios)
5. Write tests for session management
6. Write tests for user management
7. Test error conditions and edge cases
8. Ensure >80% coverage

**Acceptance Criteria:**
- [x] All service methods tested
- [x] Mock repositories used
- [x] Happy paths tested
- [x] Error conditions tested
- [x] Edge cases covered
- [x] Code coverage >80%
- [x] All tests pass

**Deliverables:**
- Service test files for each service
- Mock interfaces

**Coverage Results:**
- `auth`: 80.7%
- `client`: 89.1%
- `provider`: 87.6%
- `session`: 86.2%
- `user`: 95.7%

### Phase 3 Completion Checklist

- [x] Provider service implemented (Task 3.1) ✓
- [x] Client management service implemented (Task 3.2) ✓
- [x] Authorization Code Flow service implemented (Task 3.3) ✓
- [x] Session management service implemented (Task 3.4) ✓
- [x] User management service implemented (Task 3.5) ✓
- [x] All services implemented
- [x] Business logic complete
- [x] Authorization checks in place
- [x] Input validation implemented
- [x] Error handling comprehensive
- [x] Unit tests written with >80% coverage
- [x] Code review completed

## 5. Phase 4: API Layer

**Duration:** Week 3-4  
**Dependencies:** Phase 3 complete  
**Owner:** Backend Team

### 5.1 Task 4.1: Implement OAuth Provider Management Endpoints

**Priority:** High  
**Estimated Time:** 10 hours

**Steps:**
1. Create `internal/transport/http/api/v1/handler/provider_handler.go`
2. Implement handlers (nested under clients):
   - `GET /api/v1/clients/:client_id/providers` - List all providers for client (admin only)
   - `GET /api/v1/clients/:client_id/providers/:id` - Get details (admin only)
   - `POST /api/v1/clients/:client_id/providers` - Create provider for client (admin only)
   - `PATCH /api/v1/clients/:client_id/providers/:id` - Update (admin only)
   - `DELETE /api/v1/clients/:client_id/providers/:id` - Delete (admin only)
3. Create DTOs in `dto.go`
4. Add admin middleware to routes
5. Add client ownership validation
6. Add request validation
7. Add to router in `router.go`

**Acceptance Criteria:**
- [x] All endpoints implemented under client scope
- [x] Admin middleware applied
- [x] Client ownership validated (provider belongs to client)
- [x] Request/response DTOs defined
- [x] Input validation works
- [x] Error responses follow OAuth 2.0 format
- [x] Provider secrets excluded from responses
- [x] Routes properly nested: `/api/v1/clients/:client_id/providers/...`

**Deliverables:**
- `internal/transport/http/api/v1/handler/provider_handler.go` ✓
- Updated `dto.go` ✓
- Updated router configuration ✓

**Notes:**
- `AdminMiddleware` created at `internal/middleware/admin.go`; requires prior `AuthMiddleware` to populate `user_id` in context, then calls `user.Service.IsAdmin()` — returns 403 if not admin.
- `ErrProviderClientMismatch` is surfaced as 404 to avoid leaking cross-client information.
- `handler.New()` updated to accept both `*user.Service` and `*provider.Service`; `api.RegisterRoutes` and `v1.RegisterRoutes` signatures updated accordingly.
- Provider client credentials (`provider_client_id`, `provider_client_secret`) are intentionally excluded from all API responses.

### 5.2 Task 4.2: Implement Public Authentication Endpoints

**Priority:** Critical  
**Estimated Time:** 8 hours

**Steps:**
1. Update `internal/transport/http/api/v1/handler/auth_handler.go`
2. Implement handlers:
   - `GET /api/v1/clients/:client_id/auth/providers` - List enabled providers for client (public)
   - `POST /api/v1/auth/token` - Token exchange (public, includes client_id in request)
   - `POST /api/v1/auth/logout` - Logout (authenticated)
3. Create request/response DTOs
4. Add token validation middleware for logout
5. Add to router

**Acceptance Criteria:**
- [x] Provider list returns only enabled providers for specified client
- [x] Provider list excludes sensitive data (secrets)
- [x] Client_id validated in provider list endpoint
- [x] Token endpoint validates all parameters including client_id
- [x] Token endpoint returns OAuth 2.0 compliant response
- [x] Logout requires valid bearer token
- [x] Routes use client scoping where appropriate

**Deliverables:**
- Updated `internal/transport/http/api/v1/handler/auth_handler.go` ✓
- Updated `internal/transport/http/api/v1/handler/dto.go` ✓ (TokenExchangeRequest/Response, PublicProviderResponse)
- Updated `internal/transport/http/api/v1/router.go` ✓

**Notes:**
- `GET /api/v1/clients/:client_id/auth/providers` is fully public; it returns only `name` and `display_name` fields — no internal URLs or credentials.
- `POST /api/v1/auth/token` accepts a JSON body with `grant_type` (must be `"authorization_code"`), `code`, `client_id` (UUID string), `client_secret`, and `redirect_uri`. Returns an OAuth 2.0 token response (`access_token`, `token_type`, `expires_in`, `scope`). Auth service errors are mapped to `invalid_client` / `invalid_grant` error codes.
- `POST /api/v1/auth/logout` is now protected by `AuthMiddleware`. It revokes the token in the database via `authService.RevokeRawToken` before clearing the session cookie, preventing token replay attacks.
- `RevokeRawToken(ctx, rawToken)` was added to `internal/service/auth/authorization.go` as a convenience wrapper that hashes the raw token internally.
- `AuthMiddleware` was updated to support the `Authorization: Bearer <token>` header in addition to the `access_token` cookie, and now stores the raw token in the Gin context under the `"raw_token"` key for use by the logout handler.
- `handler.New()` now accepts `*auth.Service` as its first parameter.

### 5.3 Task 4.3: Implement Web OAuth Flow Endpoints

**Priority:** Critical  
**Estimated Time:** 12 hours

**Steps:**
1. Update `internal/transport/http/web/handler/auth_handler.go`
2. Implement handlers:
   - `GET /web/auth/:client_id/:provider/login` - Initiate OAuth (public)
   - `GET /web/auth/:client_id/:provider/callback` - Handle callback (public)
3. Implement session management for state parameter with client context
4. Implement redirect logic
5. Add error handling with user-friendly messages
6. Add client and provider validation
7. Add to web router

**Acceptance Criteria:**
- [ ] Client_id parameter validated
- [ ] Provider parameter validated for client
- [ ] Provider belongs to client check enforced
- [ ] State parameter stored in secure session cookie with client context
- [ ] CSRF protection via state validation
- [ ] Redirects work correctly
- [ ] Error pages display helpful messages
- [ ] Authorization code passed to client
- [ ] Routes include both client_id and provider: `/web/auth/:client_id/:provider/...`

**Deliverables:**
- Updated web auth handler
- Session middleware with client context support
- Error page templates (if needed)

### 5.4 Task 4.4: Implement Client Management Endpoints

**Priority:** High  
**Estimated Time:** 8 hours

**Steps:**
1. Create/update client handler
2. Implement handlers:
   - `GET /api/v1/clients` - List (admin only)
   - `GET /api/v1/clients/:id` - Get (admin only)
   - `POST /api/v1/clients` - Create (admin only)
   - `PATCH /api/v1/clients/:id` - Update (admin only)
   - `POST /api/v1/clients/:id/regenerate-secret` - Regenerate (admin only)
   - `DELETE /api/v1/clients/:id` - Delete (admin only)
3. Create DTOs
4. Add admin middleware
5. Add to router

**Acceptance Criteria:**
- [ ] All endpoints implemented
- [ ] Pagination works
- [ ] Secret only returned at creation/regeneration
- [ ] Admin authorization enforced
- [ ] Input validation works

**Deliverables:**
- Client handler
- Client DTOs

### 5.5 Task 4.5: Implement User Management Endpoints

**Priority:** Medium  
**Estimated Time:** 4 hours

**Steps:**
1. Create user handler
2. Implement handlers:
   - `GET /api/v1/users` - List (admin only)
   - `PATCH /api/v1/users/:id` - Update status (admin only)
3. Create DTOs
4. Add admin middleware
5. Add to router

**Acceptance Criteria:**
- [ ] Pagination works
- [ ] Filters work
- [ ] Admin authorization enforced
- [ ] Status updates work

**Deliverables:**
- User handler
- User DTOs

### 5.6 Task 4.6: Implement Session Management Endpoints

**Priority:** Medium  
**Estimated Time:** 6 hours

**Steps:**
1. Create session handler
2. Implement handlers:
   - `GET /api/v1/sessions/codes` - List codes (admin only)
   - `DELETE /api/v1/sessions/codes/:id` - Revoke code (admin only)
   - `GET /api/v1/sessions/tokens` - List tokens (admin only)
   - `DELETE /api/v1/sessions/tokens/:id` - Revoke token (admin only)
3. Create DTOs
4. Add admin middleware
5. Add to router

**Acceptance Criteria:**
- [ ] Pagination works
- [ ] Filters work
- [ ] Revocation works immediately
- [ ] Admin authorization enforced

**Deliverables:**
- Session handler
- Session DTOs

### 5.7 Task 4.7: Implement Authentication Middleware

**Priority:** Critical  
**Estimated Time:** 8 hours

**Steps:**
1. Create/update `internal/middleware/auth.go`
2. Implement JWT token validation:
   - Extract bearer token from Authorization header
   - Parse and verify JWT signature
   - Check expiration
   - Hash token and check revocation in database
   - Extract user claims
   - Store user context
3. Implement admin authorization middleware:
   - Check is_admin flag from user context
   - Return 403 if not admin
4. Add middleware tests

**Acceptance Criteria:**
- [ ] JWT signature verification works
- [ ] Expiration checked
- [ ] Revoked tokens rejected
- [ ] User context populated
- [ ] Admin middleware enforces authorization
- [ ] Tests cover all scenarios

**Deliverables:**
- Updated auth middleware
- Admin middleware
- Middleware tests

### 5.8 Task 4.8: Write API Integration Tests

**Priority:** High  
**Estimated Time:** 20 hours

**Steps:**
1. Set up integration test environment
2. Write end-to-end tests for OAuth flow:
   - Client and provider setup
   - Provider selection (client-scoped)
   - Authorization initiation with client context
   - Callback handling with client validation
   - Token exchange with client credentials
   - API access with token
   - Logout
3. Write tests for admin endpoints:
   - Client management
   - Provider management (nested under clients)
   - User management
   - Session management
4. Test client-provider isolation:
   - Verify providers are isolated per client
   - Test cross-client provider access denial
   - Verify client ownership validation
5. Test error conditions
6. Test authentication/authorization
7. Ensure >80% API coverage

**Acceptance Criteria:**
- [ ] Complete OAuth flow tested with client context
- [ ] All admin endpoints tested
- [ ] Client-scoped provider endpoints tested
- [ ] Provider isolation between clients verified
- [ ] Client ownership validation tested
- [ ] Authentication middleware tested
- [ ] Authorization middleware tested
- [ ] Error responses tested
- [ ] Code coverage >80%
- [ ] All tests pass

**Deliverables:**
- Integration test suite
- Client-provider isolation tests

### Phase 4 Completion Checklist

- [x] All API endpoints implemented (Task 4.1 ✓, Task 4.2 ✓)
- [ ] Web endpoints functional
- [ ] Middleware implemented and tested
- [ ] DTOs defined for all endpoints
- [ ] Input validation comprehensive
- [ ] Error handling consistent
- [ ] Integration tests pass with >80% coverage
- [ ] API documentation started

## 6. Phase 5: Security Hardening

**Duration:** Week 4  
**Dependencies:** Phase 4 complete  
**Owner:** Security Team + Backend Team

### 6.1 Task 5.1: Implement Rate Limiting

**Priority:** Critical  
**Estimated Time:** 6 hours

**Steps:**
1. Choose rate limiting library (e.g., golang.org/x/time/rate)
2. Create `internal/middleware/ratelimit.go`
3. Implement rate limiters:
   - Token endpoint: 10 req/min per IP
   - Authorization endpoint: 20 req/min per IP
   - Admin endpoints: 30 req/min per user
4. Implement storage backend (memory or Redis)
5. Add 429 Too Many Requests response
6. Apply middleware to appropriate routes
7. Add tests

**Acceptance Criteria:**
- [ ] Rate limits enforced per specification
- [ ] 429 responses returned correctly
- [ ] Retry-After header included
- [ ] Tests verify limits work
- [ ] Performance impact minimal

**Deliverables:**
- Rate limiting middleware
- Configuration for rate limits
- Tests

### 6.2 Task 5.2: Configure CORS

**Priority:** High  
**Estimated Time:** 4 hours

**Steps:**
1. Create `internal/middleware/cors.go`
2. Implement CORS middleware:
   - Load allowed origins from config
   - Handle preflight requests
   - Set appropriate headers
   - Support credentials
3. Configure per environment (dev vs prod)
4. Apply to all routes
5. Add tests

**Acceptance Criteria:**
- [ ] Allowed origins configurable
- [ ] Preflight requests handled
- [ ] Credentials supported for allowed origins
- [ ] Wildcard not used in production
- [ ] Tests verify CORS headers

**Deliverables:**
- CORS middleware
- Configuration
- Tests

### 6.3 Task 5.3: Enhance CSRF Protection

**Priority:** High  
**Estimated Time:** 6 hours

**Steps:**
1. Update `internal/middleware/csrf.go` (if exists) or create
2. Implement double-submit cookie pattern:
   - Generate CSRF token
   - Set secure cookie
   - Validate token in request header
3. Apply to state-changing endpoints
4. Exempt OAuth callbacks (use state parameter)
5. Add tests

**Acceptance Criteria:**
- [ ] CSRF tokens generated securely
- [ ] Validation works for POST/PATCH/DELETE
- [ ] OAuth flow uses state parameter
- [ ] Tests verify protection works

**Deliverables:**
- CSRF middleware
- Tests

### 6.4 Task 5.4: Implement Security Headers

**Priority:** Medium  
**Estimated Time:** 3 hours

**Steps:**
1. Create `internal/middleware/security.go`
2. Implement security headers:
   - Content-Security-Policy
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - X-XSS-Protection: 1; mode=block
   - Strict-Transport-Security (HSTS)
3. Apply to all routes
4. Configure CSP appropriately

**Acceptance Criteria:**
- [ ] All security headers set
- [ ] CSP configured for application needs
- [ ] HSTS enabled for production
- [ ] Headers verified in responses

**Deliverables:**
- Security headers middleware

### 6.5 Task 5.5: Implement Security Event Logging

**Priority:** High  
**Estimated Time:** 6 hours

**Steps:**
1. Create `internal/util/security_log.go`
2. Implement structured logging for:
   - Failed authentication attempts
   - Token revocations
   - Admin actions (create/update/delete)
   - Client secret regenerations
   - Provider configuration changes
   - Rate limit violations
3. Include request ID, IP, user ID, timestamp
4. Configure log levels
5. Add to appropriate handlers and middleware

**Acceptance Criteria:**
- [ ] Security events logged with proper level
- [ ] Logs structured (JSON format)
- [ ] Sensitive data not logged
- [ ] Request correlation works
- [ ] Logs parseable for monitoring

**Deliverables:**
- Security logging utility
- Integration in handlers/middleware

### 6.6 Task 5.6: Security Audit

**Priority:** Critical  
**Estimated Time:** 12 hours

**Steps:**
1. Review all authentication/authorization logic
2. Verify secrets never logged or exposed
3. Check SQL injection prevention (sqlc queries)
4. Verify CSRF protection on all state-changing endpoints
5. Test XSS prevention
6. Verify rate limiting works
7. Check CORS configuration
8. Verify token validation
9. Test session security
10. Review error messages (no info leakage)
11. Document findings and fixes

**Acceptance Criteria:**
- [ ] No SQL injection vulnerabilities
- [ ] No XSS vulnerabilities
- [ ] CSRF protection complete
- [ ] No secret leakage
- [ ] Authentication/authorization secure
- [ ] All findings documented and addressed

**Deliverables:**
- Security audit report
- Fix commits for any issues found

### 6.7 Task 5.7: Penetration Testing

**Priority:** High  
**Estimated Time:** 8 hours

**Steps:**
1. Set up test environment
2. Run automated security scanners:
   - OWASP ZAP
   - sqlmap
   - nmap
3. Manual testing:
   - Token replay attacks
   - Authorization bypass attempts
   - CSRF attacks
   - Injection attacks
   - Rate limit bypass attempts
4. Document findings
5. Fix critical/high severity issues
6. Re-test

**Acceptance Criteria:**
- [ ] Automated scans completed
- [ ] Manual testing completed
- [ ] All critical issues fixed
- [ ] High severity issues fixed
- [ ] Findings documented

**Deliverables:**
- Penetration testing report
- Fix commits

### Phase 5 Completion Checklist

- [ ] Rate limiting implemented and tested
- [ ] CORS configured correctly
- [ ] CSRF protection complete
- [ ] Security headers applied
- [ ] Security logging implemented
- [ ] Security audit completed
- [ ] Penetration testing done
- [ ] All critical/high issues fixed
- [ ] Security documentation updated

## 7. Phase 6: Documentation & Deployment

**Duration:** Week 5  
**Dependencies:** Phase 5 complete  
**Owner:** DevOps + Backend Team

### 7.1 Task 6.1: Create OpenAPI/Swagger Documentation

**Priority:** High  
**Estimated Time:** 12 hours

**Steps:**
1. Install Swagger tools
2. Create `docs/api/openapi.yaml`
3. Document all API endpoints:
   - Request/response schemas
   - Authentication requirements
   - Error responses
   - Examples
4. Document OAuth 2.0 flow
5. Generate Swagger UI
6. Host documentation at `/api/docs`

**Acceptance Criteria:**
- [ ] All endpoints documented
- [ ] Schemas accurate
- [ ] Examples provided
- [ ] OAuth flow documented
- [ ] Swagger UI accessible
- [ ] Documentation accurate

**Deliverables:**
- `docs/api/openapi.yaml`
- Swagger UI integration

### 7.2 Task 6.2: Create Administrator Guide

**Priority:** Medium  
**Estimated Time:** 10 hours

**Steps:**
1. Create `docs/v0.2.0/AdministratorGuide.md`
2. Document:
   - Initial setup and configuration
   - Creating first admin user
   - Managing client applications
   - Managing OAuth providers for clients
   - Client-provider relationship and isolation
   - Managing users
   - Managing sessions
   - Security best practices
   - Troubleshooting
3. Include examples and screenshots
4. Explain client-scoped provider architecture

**Acceptance Criteria:**
- [ ] Setup instructions complete
- [ ] All admin tasks documented
- [ ] Client-provider relationship explained clearly
- [ ] Provider isolation per client documented
- [ ] Security guidelines included
- [ ] Troubleshooting section helpful

**Deliverables:**
- `docs/v0.2.0/AdministratorGuide.md`

### 7.3 Task 6.3: Create Client Integration Guide

**Priority:** High  
**Estimated Time:** 12 hours

**Steps:**
1. Create `docs/v0.2.0/ClientIntegrationGuide.md`
2. Document:
   - Overview of OAuth 2.0 Authorization Code Grant
   - Understanding client-scoped providers
   - Registering client application
   - Configuring OAuth providers for your client
   - Discovering available providers for your client
   - Initiating authorization flow with client context
   - Handling callbacks
   - Exchanging code for token
   - Using access tokens
   - Error handling
   - Code examples in multiple languages
3. Include complete example application
4. Explain provider isolation between clients

**Acceptance Criteria:**
- [ ] Integration steps clear
- [ ] Client-scoped provider model explained
- [ ] Provider configuration documented
- [ ] Code examples provided
- [ ] Error handling explained
- [ ] Example application works
- [ ] Multi-provider setup example included

**Deliverables:**
- `docs/v0.2.0/ClientIntegrationGuide.md`
- Example client application with multiple providers

### 7.4 Task 6.4: Create Dockerfile

**Priority:** High  
**Estimated Time:** 4 hours

**Steps:**
1. Create `Dockerfile`
2. Use multi-stage build:
   - Build stage with Go toolchain
   - Runtime stage with minimal base image
3. Copy binary and configuration
4. Set up non-root user
5. Expose port 8080
6. Set entrypoint
7. Test build and run

**Acceptance Criteria:**
- [ ] Multi-stage build works
- [ ] Image size optimized
- [ ] Runs as non-root user
- [ ] Health check configured
- [ ] Image builds successfully
- [ ] Container runs correctly

**Deliverables:**
- `Dockerfile`
- `.dockerignore`

### 7.5 Task 6.5: Create Docker Compose Configuration

**Priority:** High  
**Estimated Time:** 4 hours

**Steps:**
1. Create `docker-compose.yml`
2. Define services:
   - PostgreSQL database
   - Goauth API server
3. Configure:
   - Networks
   - Volumes for database persistence
   - Environment variables
   - Health checks
   - Restart policies
4. Create `.env.example`
5. Test with `docker-compose up`

**Acceptance Criteria:**
- [ ] Services start correctly
- [ ] Database migrations run automatically
- [ ] API accessible on localhost:8080
- [ ] Environment variables templated
- [ ] Volumes persist data
- [ ] Health checks work

**Deliverables:**
- `docker-compose.yml`
- `.env.example`

### 7.6 Task 6.6: Create Deployment Scripts

**Priority:** Medium  
**Estimated Time:** 6 hours

**Steps:**
1. Create `scripts/deploy/` directory
2. Create deployment script for Docker:
   - `deploy-docker.sh`
3. Create deployment script for Kubernetes:
   - `deploy-k8s.sh`
   - Kubernetes manifests in `k8s/`
4. Create backup script:
   - `backup-database.sh`
5. Create restore script:
   - `restore-database.sh`
6. Document usage

**Acceptance Criteria:**
- [ ] Scripts executable and working
- [ ] Kubernetes manifests valid
- [ ] Backup/restore tested
- [ ] Documentation clear

**Deliverables:**
- Deployment scripts
- Kubernetes manifests
- Backup/restore scripts
- Deployment documentation

### 7.7 Task 6.7: Set Up CI/CD Pipeline

**Priority:** High  
**Estimated Time:** 10 hours

**Steps:**
1. Create `.github/workflows/ci.yml` (or equivalent)
2. Configure CI pipeline:
   - Lint code (golangci-lint)
   - Run unit tests
   - Run integration tests
   - Check code coverage
   - Build binary
   - Build Docker image
3. Configure CD pipeline:
   - Push image to registry
   - Deploy to staging
   - Run smoke tests
   - Deploy to production (manual approval)
4. Add status badges to README

**Acceptance Criteria:**
- [ ] CI runs on all PRs
- [ ] All tests must pass
- [ ] Code coverage checked
- [ ] Docker image built
- [ ] CD deploys to staging automatically
- [ ] Production deployment gated

**Deliverables:**
- CI/CD pipeline configuration
- Updated README with badges

### 7.8 Task 6.8: Create Monitoring and Alerting

**Priority:** Medium  
**Estimated Time:** 8 hours

**Steps:**
1. Integrate Prometheus metrics:
   - Request count by endpoint
   - Response time histograms
   - Error rates
   - Token issuance rate
2. Create Grafana dashboards
3. Set up alerting rules:
   - High error rate
   - Service down
   - Database connection issues
   - High rate limit violations
4. Document monitoring setup

**Acceptance Criteria:**
- [ ] Metrics exposed at `/metrics`
- [ ] Dashboards visualize key metrics
- [ ] Alerts trigger correctly
- [ ] Documentation complete

**Deliverables:**
- Prometheus metrics integration
- Grafana dashboard JSON
- Alert rules
- Monitoring documentation

### 7.9 Task 6.9: Update README

**Priority:** Medium  
**Estimated Time:** 4 hours

**Steps:**
1. Update `README.md` with:
   - Project overview
   - Features of v0.2.0
   - Client-scoped provider architecture highlights
   - Quick start guide
   - Docker instructions
   - Development setup
   - Running tests
   - Contributing guidelines
   - License information
   - Links to documentation
2. Add badges (build status, coverage, etc.)
3. Explain benefits of client-scoped providers

**Acceptance Criteria:**
- [ ] README complete and accurate
- [ ] Client-scoped provider model highlighted
- [ ] Quick start works
- [ ] Links valid
- [ ] Badges display correctly

**Deliverables:**
- Updated `README.md`

### Phase 6 Completion Checklist

- [ ] API documentation complete (OpenAPI)
- [ ] Administrator guide written
- [ ] Client integration guide written
- [ ] Dockerfile created and tested
- [ ] Docker Compose configured
- [ ] Deployment scripts ready
- [ ] CI/CD pipeline operational
- [ ] Monitoring configured
- [ ] README updated
- [ ] All documentation reviewed

## 8. Testing & Quality Assurance

### 8.1 Overall Test Coverage Requirements

- **Unit Tests:** >80% coverage for each package
- **Integration Tests:** All API endpoints covered
- **Security Tests:** All attack vectors tested
- **Performance Tests:** Load testing completed

### 8.2 Test Execution Schedule

- **Daily:** Unit tests in CI pipeline
- **Per PR:** Integration tests
- **Weekly:** Security scans
- **Pre-release:** Full regression testing

## 9. Risk Management

### 9.1 Identified Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| OAuth provider API changes | Medium | High | Version lock, monitoring, fallback |
| Database migration failures | Low | Critical | Test migrations, backup before deploy |
| Security vulnerabilities | Medium | Critical | Security audit, penetration testing |
| Client-provider isolation breach | Low | Critical | Thorough testing, validation at all layers |
| Performance bottlenecks | Medium | Medium | Load testing, optimization |
| Third-party dependency issues | Medium | Medium | Vendor packages, lock files |
| Provider configuration complexity | Medium | Medium | Clear documentation, admin UI validation |

### 9.2 Rollback Plan

1. Keep previous version running during deployment
2. Database migrations support rollback
3. Feature flags for gradual rollout
4. Automated health checks trigger rollback
5. Database backups before production deployment

## 10. Success Criteria

### 10.1 Functional Criteria

- [ ] All API endpoints functional per specification
- [ ] OAuth 2.0 flow works with client-scoped providers
- [ ] Multiple providers can be configured per client
- [ ] Provider isolation between clients enforced
- [ ] Admin can manage clients and their providers
- [ ] Admin can manage users and sessions
- [ ] Tokens issued and validated correctly
- [ ] Session management works
- [ ] Client ownership validation works

### 10.2 Non-Functional Criteria

- [ ] Code coverage >80%
- [ ] All security tests pass
- [ ] Response time <200ms for 95th percentile
- [ ] Zero critical security vulnerabilities
- [ ] Documentation complete and accurate

### 10.3 Deployment Criteria

- [ ] Docker container runs successfully
- [ ] Database migrations work
- [ ] CI/CD pipeline operational
- [ ] Monitoring and alerting configured
- [ ] Backup/restore tested

## 11. Sign-Off

### 11.1 Phase Sign-Off Template

Each phase requires sign-off from:
- [ ] Development Lead
- [ ] QA Lead
- [ ] Security Lead (Phases 4-5)
- [ ] DevOps Lead (Phase 6)

### 11.2 Final Release Sign-Off

- [ ] All phases complete
- [ ] All tests passing
- [ ] Security audit approved
- [ ] Documentation reviewed
- [ ] Deployment tested
- [ ] Stakeholder approval

## 12. Appendices

### Appendix A: Environment Setup Checklist

- [ ] Go 1.25+ installed
- [ ] PostgreSQL 16+ installed
- [ ] Docker installed
- [ ] sqlc installed
- [ ] golang-migrate installed
- [ ] Development environment configured
- [ ] Test database accessible

### Appendix B: Key Configuration Values

See System Design Document Appendix B for full configuration reference.

### Appendix C: Useful Commands

```bash
# Run migrations
./db/scripts/run_migrations.sh

# Generate sqlc code
sqlc generate

# Run tests
go test ./...

# Run with coverage
go test -cover ./...

# Build application
go build -o bin/auth-server ./cmd/auth-server

# Run application
go run ./cmd/auth-server

# Build Docker image
docker build -t goauth-server:v0.2.0 .

# Run with Docker Compose
docker-compose up
```
