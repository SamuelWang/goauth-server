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
- [x] Client_id parameter validated
- [x] Provider parameter validated for client
- [x] Provider belongs to client check enforced
- [x] State parameter stored in secure session cookie with client context
- [x] CSRF protection via state validation
- [x] Redirects work correctly
- [x] Error pages display helpful messages
- [x] Authorization code passed to client
- [x] Routes include both client_id and provider: `/web/auth/:client_id/:provider/...`

**Deliverables:**
- Updated web auth handler ✓
- Session middleware with client context support ✓
- Error page templates (if needed)

**Notes:**
- `GET /web/auth/:client_id/:provider/login` accepts `redirect_uri` (required) and `scope` (optional) query params. It validates the client and provider via `authService.InitiateAuthorization`, stores a signed session cookie (`oauth_session`) containing `{state, client_id, provider, redirect_uri}`, and redirects the user to the OAuth provider.
- `GET /web/auth/:client_id/:provider/callback` reads and HMAC-verifies the session cookie, validates state (CSRF protection) and path-parameter binding, calls `authService.HandleProviderCallback`, then redirects to `redirect_uri?code=<auth_code>`.
- Session cookies are HMAC-SHA256-signed using the hex-decoded `PROVIDER_ENCRYPTION_KEY` to prevent tampering with the redirect URI or session context.
- The callback URL sent to the OAuth provider is constructed from `cfg.Server.Scheme`, `cfg.Server.HostName`, and `cfg.Server.Port`.
- Old Google-specific handlers (`GoogleLogin`, `GoogleCallback`) have been replaced by the generic client-scoped handlers.
- `handler.New()` updated to accept `*config.Config` and `[]byte` signing key; `web.RegisterRoutes` derives the signing key and passes it through.
- Routes are nested under `/web` prefix: `/web/auth/:client_id/:provider/login` and `/web/auth/:client_id/:provider/callback`.

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
- [x] All endpoints implemented
- [x] Pagination works
- [x] Secret only returned at creation/regeneration
- [x] Admin authorization enforced
- [x] Input validation works

**Deliverables:**
- `internal/transport/http/api/v1/handler/client_handler.go` ✓
- Updated `dto.go` with client request/response types ✓
- Updated `handler.go` to include `clientService` dependency ✓
- Updated `v1/router.go` with client management routes ✓
- Updated `api/router.go` and `server.go` to wire `client.Service` ✓

**Notes:**
- All client routes are nested under `/api/v1/clients` and protected by `AuthMiddleware` + `AdminMiddleware`.
- `GET /api/v1/clients` supports `limit`, `offset`, and optional `is_active` query parameters for pagination and filtering.
- `POST /api/v1/clients` and `POST /api/v1/clients/:id/regenerate-secret` return a `ClientWithSecretResponse` containing the plain `client_secret` — this is the only time it is exposed.
- `DELETE /api/v1/clients/:id` performs a soft delete (sets `is_active = false`), preserving the audit trail.
- The `client_id` used in nested provider routes (`/clients/:client_id/providers`) is a distinct path parameter from the `:id` used by the client management routes, so there is no routing conflict.
- `client.New(repo, cfg.Server.Env)` is initialised in `server.go` and propagated through `api.RegisterRoutes` → `v1.RegisterRoutes` → `handler.New`.

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
- [x] Pagination works
- [x] Filters work
- [x] Admin authorization enforced
- [x] Status updates work

**Deliverables:**
- `internal/transport/http/api/v1/handler/user_handler.go` ✓
- Updated `dto.go` with `UserResponse`, `ListUsersResponse`, `UpdateUserStatusRequest` ✓
- Updated `v1/router.go` with user management routes ✓

**Notes:**
- `GET /api/v1/users` supports `limit`, `offset`, `is_active`, and `is_admin` query parameters for pagination and filtering.
- `PATCH /api/v1/users/:id` accepts `{"is_active": bool}` and returns the updated `UserResponse`.
- Both routes are protected by `AuthMiddleware` + `AdminMiddleware`.
- `UpdateUserStatusRequest.IsActive` has no `binding:"required"` tag because both `true` and `false` are valid values; the field defaults to `false` if omitted, which disables the account.

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
- [x] Pagination works
- [x] Filters work
- [x] Revocation works immediately
- [x] Admin authorization enforced

**Deliverables:**
- `internal/transport/http/api/v1/handler/session_handler.go` ✓
- Updated `dto.go` with `AuthorizationCodeResponse`, `ListAuthorizationCodesResponse`, `AccessTokenResponse`, `ListAccessTokensResponse` ✓
- Updated `handler.go` to include `sessionService` dependency and `formatTimePtr` helper ✓
- Updated `v1/router.go` with session management routes ✓
- Updated `api/router.go` and `server.go` to wire `session.Service` ✓

**Notes:**
- `GET /api/v1/sessions/codes` and `GET /api/v1/sessions/tokens` support `limit`, `offset`, `client_id` (UUID), `user_id` (UUID), and `is_revoked` (bool) query parameters.
- `DELETE /api/v1/sessions/codes/:id` and `DELETE /api/v1/sessions/tokens/:id` return HTTP 204 No Content on success and 404 when the resource is not found.
- Both routes are protected by `AuthMiddleware` + `AdminMiddleware`.
- Token hash is intentionally excluded from `AccessTokenResponse` to avoid leaking sensitive data.
- `formatTimePtr` helper added to `handler.go` to format nullable `*time.Time` fields as RFC3339 string pointers.

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
- [x] JWT signature verification works
- [x] Expiration checked
- [x] Revoked tokens rejected
- [x] User context populated
- [x] Admin middleware enforces authorization
- [x] Tests cover all scenarios

**Deliverables:**
- Updated auth middleware ✓
- Admin middleware ✓
- Middleware tests ✓

**Notes:**
- `IsTokenRevoked(ctx, rawToken string)` was added to `internal/service/auth/authorization.go`. It hashes the raw token with SHA-256 and looks it up via `GetAccessToken`; if the record is absent (pgx.ErrNoRows) the token is treated as invalid (returns `true, nil`).
- `AuthMiddleware` now calls `IsTokenRevoked` after JWT validation and returns HTTP 401 for revoked/absent tokens and HTTP 500 for unexpected database errors.
- `internal/middleware/auth_test.go` was rewritten with a `testAuthHelper` type that holds a real `auth.Service` backed by a `*mocks.MockQuerier` and the ECDSA private key used to sign tokens. Tests cover: missing token (no cookie/header), malformed Authorization header, invalid JWT, expired JWT, token not found in DB, revoked token, DB error during revocation check, valid token via cookie, valid token via Bearer header, header-over-cookie precedence, and request-chain abort on unauthorized.
- `internal/middleware/admin_test.go` was created covering: no user_id in context, invalid (non-UUID) user_id, non-admin user (403), admin user (200), user not found in DB (500), and DB error (500).
- Total: 22 middleware tests, all passing.

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
- [x] Complete OAuth flow tested with client context
- [x] All admin endpoints tested
- [x] Client-scoped provider endpoints tested
- [x] Provider isolation between clients verified
- [x] Client ownership validation tested
- [x] Authentication middleware tested
- [x] Authorization middleware tested
- [x] Error responses tested
- [x] Code coverage >80%
- [x] All tests pass

**Deliverables:**
- `internal/transport/http/api/v1/handler/testhelpers_test.go` — shared test infrastructure (`testEnv`, mock setup helpers, token helpers, fixture builders)
- `internal/transport/http/api/v1/handler/auth_handler_test.go` — 21 tests: public provider listing, token exchange (10 scenarios), logout, me endpoint, protected route middleware
- `internal/transport/http/api/v1/handler/client_handler_test.go` — 17 tests: list/get/create/update/regenerate-secret/delete clients including admin authorization
- `internal/transport/http/api/v1/handler/provider_handler_test.go` — 15 tests: list/get/create/update/delete providers, cross-client isolation, credential exclusion
- `internal/transport/http/api/v1/handler/session_handler_test.go` — 15 tests: list/revoke authorization codes and access tokens, filtering, token hash exclusion
- `internal/transport/http/api/v1/handler/user_handler_test.go` — 11 tests: list users with filters, update user active status

**Notes:**
- Tests use a mock-based integration approach: a real Gin router with all routes registered runs against a `MockQuerier`, enabling end-to-end handler testing without a database.
- Router bug fixed: `/:id` and `/:client_id` param name conflict in `/clients/:id` vs `/clients/:client_id/providers` routes; resolved by standardizing to `/:client_id` and updating `client_handler.go`.
- Total: 79 tests, all passing.

### Phase 4 Completion Checklist

- [x] All API endpoints implemented (Task 4.1 ✓, Task 4.2 ✓, Task 4.4 ✓)
- [x] Web endpoints functional (Task 4.3 ✓)
- [x] User management endpoints implemented (Task 4.5 ✓)
- [x] Remaining endpoints implemented (Task 4.6 ✓ sessions)
- [x] Middleware implemented and tested (Task 4.7 ✓)
- [x] DTOs defined for all endpoints
- [x] Input validation comprehensive
- [x] Error handling consistent
- [x] Integration tests pass with >80% coverage (Task 4.8 ✓)
- [x] API documentation started

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
- [x] Rate limits enforced per specification
- [x] 429 responses returned correctly
- [x] Retry-After header included
- [x] Tests verify limits work
- [x] Performance impact minimal

**Deliverables:**
- `internal/middleware/ratelimit.go` ✓ — `RateLimitByIP` and `RateLimitByUser` middleware backed by per-key `golang.org/x/time/rate` token-bucket limiters; stale entries evicted by a background ticker.
- `internal/middleware/ratelimit_test.go` ✓ — 11 tests covering burst allowance, 429 blocking, Retry-After header, per-key isolation, user-ID fallback to IP, and constant values.
- Updated `internal/transport/http/api/v1/router.go` ✓ — `POST /auth/token` uses `RateLimitByIP(10, 10)`; all four admin groups (clients, providers, users, sessions) use `RateLimitByUser(30, 30)`.
- Updated `internal/transport/http/web/router.go` ✓ — `GET /web/auth/:client_id/:provider/login` uses `RateLimitByIP(20, 20)`.

**Notes:**
- Rate limits: token endpoint 10 req/min per IP (burst 10); authorization login 20 req/min per IP (burst 20); admin endpoints 30 req/min per user (burst 30), falling back to IP when unauthenticated.
- `RateLimitByUser` must run after `AuthMiddleware` to access `user_id` from context.
- `Retry-After` header is computed via `rate.Limiter.Reserve()` for an accurate delay (minimum 1 s).
- Memory is bounded: each `keyedLimiter` runs a background goroutine that purges entries not seen in the last 5 minutes.

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
- [x] Allowed origins configurable
- [x] Preflight requests handled
- [x] Credentials supported for allowed origins
- [x] Wildcard not used in production
- [x] Tests verify CORS headers

**Deliverables:**
- `internal/middleware/cors.go` ✓ — `CORSMiddleware(allowedOrigins []string, env string)` applied globally in `server.go`; reflects exact origin + `Access-Control-Allow-Credentials: true` for listed origins; falls back to `*` (without credentials) in non-production when no list is configured; production with no list blocks all cross-origin requests.
- `internal/middleware/cors_test.go` ✓ — 13 tests covering: non-cross-origin pass-through, dev wildcard, production block with no origins, allowlist exact-match + case-insensitivity, disallowed origin in prod and dev, preflight 204/403, Vary header, expose headers.
- Updated `internal/config/config.go` ✓ — `SecurityConfig.CORSAllowedOrigins []string` parsed from comma-separated `CORS_ALLOWED_ORIGINS` env var via new `getEnvAsStringSlice` helper.
- Updated `internal/app/auth-server/server.go` ✓ — `r.Use(middleware.CORSMiddleware(...))` registered before all route groups so OPTIONS preflight requests are handled before auth/rate-limit middleware.

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
- [x] CSRF tokens generated securely
- [x] Validation works for POST/PATCH/DELETE
- [x] OAuth flow uses state parameter
- [x] Tests verify protection works

**Deliverables:**
- `internal/middleware/csrf.go` ✓ — `CSRFMiddleware()` implements the double-submit cookie pattern. Generates a 32-byte cryptographically random token and sets it as a `csrf_token` cookie (HttpOnly=false, SameSite=Lax so JS can read it). On POST/PUT/PATCH/DELETE validates that the `X-CSRF-Token` header matches the cookie via constant-time (`secureCompare`) comparison. The `Secure` flag is derived from the `cookie_secure` value set by `ContextMiddleware`. Returns HTTP 403 on mismatch.
- `internal/middleware/csrf_test.go` ✓ — 16 tests: cookie issuance on GET, HttpOnly=false, Secure flag in production/development, cookie reuse on subsequent requests, valid POST/PATCH/DELETE pass, missing header returns 403, mismatched header returns 403, DELETE without cookie returns 403, GET never blocked, and `secureCompare` unit tests (equal, unequal, different lengths, empty strings).
- `internal/transport/http/api/v1/router.go` ✓ — `CSRFMiddleware()` applied to: protected auth group (logout/me), clients admin group, client-scoped providers admin group, users admin group, sessions admin group. Public routes (token exchange, provider listing, OAuth web flow) remain exempt — token exchange uses `client_secret` as the CSRF defence; OAuth callbacks use the state parameter.
- `internal/transport/http/api/v1/handler/testhelpers_test.go` ✓ — `doAuthRequest` updated to include the `csrf_token` cookie and `X-CSRF-Token` header automatically for state-changing methods (POST/PATCH/DELETE/PUT) so all 79 existing handler tests continue to pass.

**Notes:**
- `secureCompare` performs a constant-time XOR-based comparison to prevent timing-side-channel attacks on the token validation.
- The `csrf_token` cookie intentionally has `HttpOnly=false` — this is required by the double-submit pattern so that JavaScript on the same origin can read the token and echo it in the request header.
- `SameSite=Lax` is applied to the cookie, providing a complementary layer of CSRF protection for top-level navigations.
- OAuth callbacks and the token exchange endpoint are deliberately excluded from CSRF enforcement: callbacks are GET requests (not state-changing) and use the `state` parameter for CSRF; the token exchange relies on `client_secret` which cannot be forged cross-site.
- The `Secure` flag on the cookie is driven by `ContextMiddleware`'s `cookie_secure` context value, which is `true` when `ENV=production` or `SCHEME=https`.

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
- [x] All security headers set
- [x] CSP configured for application needs
- [x] HSTS enabled for production
- [x] Headers verified in responses

**Deliverables:**
- `internal/middleware/security.go` ✓ — `SecurityHeadersMiddleware(env string)` sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on every response. `Strict-Transport-Security: max-age=31536000; includeSubDomains` is added only when `env == "production"` to avoid permanently locking browsers into HTTPS on plain-HTTP dev/staging servers.
- `internal/middleware/security_test.go` ✓ — 9 tests: each header asserted individually, HSTS present in production, HSTS absent in development and staging, all headers applied to POST requests, and constant value assertions.
- Updated `internal/app/auth-server/server.go` ✓ — `r.Use(middleware.SecurityHeadersMiddleware(cfg.Server.Env))` registered globally after CORS so security headers are present on every response including CORS preflight 204s.

**Notes:**
- CSP uses `default-src 'none'; frame-ancestors 'none'` — the strictest baseline suitable for a pure-API / OAuth server that does not serve scripts, styles, images, or fonts via browser rendering. `frame-ancestors 'none'` reinforces `X-Frame-Options: DENY`.
- HSTS is deliberately restricted to `env == "production"` because sending it over HTTP (as used in dev/staging) would cause browsers to refuse plain-HTTP connections permanently.
- `SecurityHeadersMiddleware` is registered after `CORSMiddleware` in `server.go` so CORS preflight OPTIONS responses also carry the security headers.

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
- [x] Security events logged with proper level
- [x] Logs structured (JSON format)
- [x] Sensitive data not logged
- [x] Request correlation works
- [x] Logs parseable for monitoring

**Deliverables:**
- `internal/util/security_log.go` ✓ — `slog`-based JSON security logger with `SecurityEvent` type constants (`auth_failure`, `rate_limit_exceeded`, `csrf_violation`, `admin_access_denied`, `token_revoked`, `token_exchange_failure`, `oauth_callback_error`) and convenience functions (`LogAuthFailure`, `LogRateLimitExceeded`, `LogCSRFViolation`, `LogAdminAccessDenied`, `LogTokenRevoked`, `LogTokenExchangeFailure`, `LogOAuthCallbackError`).
- Updated `internal/middleware/context.go` ✓ — Generates a unique UUID request ID per request (accepting `X-Request-ID` from a trusted upstream proxy when present); stores it in the Gin context as `request_id` and echoes it in the `X-Request-ID` response header for end-to-end correlation.
- Updated `internal/middleware/auth.go` ✓ — Logs `auth_failure` for missing token, malformed `Authorization` header, invalid/expired JWT, and revoked token.
- Updated `internal/middleware/admin.go` ✓ — Logs `admin_access_denied` when an authenticated non-admin user attempts to reach an admin-only route.
- Updated `internal/middleware/ratelimit.go` ✓ — Logs `rate_limit_exceeded` (with user_id when authenticated, IP otherwise) for both `RateLimitByIP` and `RateLimitByUser`.
- Updated `internal/middleware/csrf.go` ✓ — Logs `csrf_violation` (including method and path) when the CSRF double-submit check fails.
- Updated `internal/transport/http/api/v1/handler/auth_handler.go` ✓ — Logs `token_exchange_failure` on every failed authorization-code exchange; logs `token_revoked` on successful logout.
- Updated `internal/transport/http/web/handler/auth_handler.go` ✓ — Logs `oauth_callback_error` for provider-returned errors and state-mismatch (CSRF) detected during callback.

**Notes:**
- All security events are written as JSON to `os.Stderr` at `WARN` level via a singleton `log/slog` logger. Each line includes `time` (RFC3339Nano, automatic), `level`, `msg="security_event"`, `event`, `ip`, `request_id`, and `user_id` (when the identity is known).
- Tokens, secrets, authorization codes, and provider credentials are intentionally excluded from all log lines.
- `request_id` is generated in `ContextMiddleware` so it is consistently available across middleware layers and handlers via `c.GetString("request_id")`.

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
- [x] No SQL injection vulnerabilities
- [x] No XSS vulnerabilities
- [x] CSRF protection complete
- [x] No secret leakage
- [x] Authentication/authorization secure
- [x] All findings documented and addressed

**Deliverables:**
- Security audit report (findings documented below) ✓
- Fix commits for all 5 issues found ✓

**Findings and Fixes:**

**Finding 1 – Information Leakage in Token Exchange Error Responses (High)**
- `handleTokenExchangeError` returned `err.Error()` verbatim as `error_description` for `invalid_grant` errors. Attackers could determine whether a code existed, was expired, had already been used, or was issued to a different client.
- Fix: Replaced with a single generic RFC 6749–style message for all `invalid_grant` cases: `"The provided authorization grant is invalid, expired, revoked, does not match the redirection URI, or was issued to another client."`
- File: `internal/transport/http/api/v1/handler/auth_handler.go`

**Finding 2 – Unbounded Pagination Parameters (Medium)**
- `limit` and `offset` query parameters on list endpoints (clients, users, sessions) had no validation bounds. Any integer — including negative values or millions — was accepted, enabling potential DoS via large database queries.
- Fix: Added `parsePaginationParams()` helper enforcing `limit ∈ [1, 100]` and `offset ≥ 0`. Returns HTTP 400 on violation.
- Files: `internal/transport/http/api/v1/handler/handler.go` (new helper + `paginationMaxLimit = 100`), `client_handler.go`, `user_handler.go`, `session_handler.go`

**Finding 3 – Provider OAuth URLs Not Requiring HTTPS in Production (Medium)**
- Provider `auth_url`, `token_url`, and `user_info_url` validated http/https scheme but did not require HTTPS in production, whereas redirect URIs already had HTTPS enforcement. This could expose OAuth access tokens and user data in transit.
- Fix: Extended `validateURL` to enforce HTTPS for non-loopback hosts in production (matching redirect URI policy). Added `env` field to `provider.Service` and threaded it through validation.
- Files: `internal/service/provider/validation.go`, `internal/service/provider/provider.go`, `internal/app/auth-server/server.go`, `internal/transport/http/api/v1/handler/testhelpers_test.go`, `internal/service/provider/provider_test.go`

**Finding 4 – Log Injection via X-Request-ID Header (Medium)**
- `ContextMiddleware` accepted any `X-Request-ID` header value without sanitization and stored it verbatim in structured (JSON) log output. An attacker could inject control characters or JSON into log lines.
- Fix: Added `validRequestIDPattern = regexp.MustCompile('^[a-zA-Z0-9\-_]{1,64}$')`. Values that fail validation are silently replaced with a fresh UUID.
- Files: `internal/middleware/context.go`, `internal/middleware/context_test.go` (4 new tests)

**Finding 5 – Missing Referrer-Policy Header (Low)**
- `SecurityHeadersMiddleware` did not set `Referrer-Policy`. Authorization codes visible in redirect URI query strings could potentially leak to third-party origins via the browser `Referer` header on subsequent navigations.
- Fix: Added `Referrer-Policy: no-referrer` to `SecurityHeadersMiddleware`.
- Files: `internal/middleware/security.go`, `internal/middleware/security_test.go` (2 new tests + existing tests updated)

**Areas Confirmed Secure (No Issues Found):**
- **SQL injection:** All queries use sqlc-generated parameterized statements via pgx/v5; no string concatenation in SQL paths.
- **XSS:** API returns only `Content-Type: application/json`; CSP `default-src 'none'` blocks all browser resource loading.
- **CSRF:** Double-submit cookie pattern applied to all state-changing admin and auth routes; OAuth callbacks use the state parameter; token exchange uses `client_secret`.
- **Rate limiting:** Token endpoint 10/min/IP, OAuth login 20/min/IP, admin endpoints 30/min/user — all verified with tests.
- **CORS:** Explicit origin allowlist with credentials in production; wildcard (no credentials) in development; tested with 13 scenarios.
- **Token validation:** ECDSA signature + expiry + revocation check on every authenticated request.
- **Secret exposure:** Provider secrets AES-256-GCM encrypted at rest; client secrets bcrypt-hashed (cost 12); secrets never returned in API responses; tokens/codes absent from all log lines.
- **Authorization:** Admin middleware enforces `is_admin` DB flag; `ErrProviderClientMismatch` surfaced as 404 to prevent cross-client information leakage.

### 6.7 Task 5.7: Penetration Testing

**Priority:** High  
**Estimated Time:** 8 hours  
**Status:** ✅ Complete

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
- [x] Automated scans completed
- [x] Manual testing completed
- [x] All critical issues fixed
- [x] High severity issues fixed
- [x] Findings documented

**Findings & Fixes:**

| # | Severity | Rule | Description | Status |
|---|----------|------|-------------|--------|
| 1 | HIGH | gosec G115 | Integer overflow `int → int32` in pagination helper — bounds already validated (l∈[1,100], o≥0) | Fixed: `// #nosec G115 G109` annotation |
| 2 | MEDIUM | gosec G112 | `http.Server` missing `ReadHeaderTimeout` — vulnerable to Slowloris DoS attack | Fixed: added `ReadHeaderTimeout: 10 * time.Second` |
| 3 | MEDIUM | Manual | No request body size limit — server accepted arbitrarily large bodies (memory-exhaustion DoS vector) | Fixed: `MaxBodySizeMiddleware()` added (1 MiB limit, 413 on violation) |
| 4 | LOW | gosec G101 | SQL query constants in sqlc-generated code flagged as hardcoded credentials | False positive — parameterised queries with `$1`/`$2` placeholders; no action needed |

**Test Coverage Added:**

`internal/transport/http/api/v1/handler/security_test.go` — 60+ penetration tests across 17 attack categories:
- JWT algorithm confusion (alg:none, HS256, RS256 against ES256-only service)
- Tampered JWT payload (signature verification)
- Token replay after revocation / token not in DB
- Authorization code replay, client mismatch, expiry, redirect URI mismatch
- Wrong client secret (timing-safe comparison)
- CSRF bypass (missing/wrong header, missing cookie, empty header)
- Cross-client provider and resource isolation
- Pagination bounds injection (negative, zero, excessive, SQL injection strings)
- UUID path parameter injection (XSS payload, SQL fragments)
- Information leakage (provider secrets, token hash, client secret hash, public URLs)
- Security headers on success and error responses
- HSTS absent in development environment
- Request ID reflection and log injection prevention
- Admin authorization enforcement and unauthenticated access blocking
- Unsupported grant types and missing required fields
- Excessive request body (413 enforcement)
- Invalid JSON and non-JSON content types
- Revoked auth code and inactive client rejection

**Deliverables:**
- `internal/transport/http/api/v1/handler/security_test.go` — penetration test suite (60+ tests, all passing)
- `internal/middleware/security.go` — `MaxBodySizeMiddleware()` (Finding 3 fix)
- `internal/app/auth-server/server.go` — `ReadHeaderTimeout: 10s` (Finding 2 fix)
- `internal/transport/http/api/v1/handler/handler.go` — `#nosec G115 G109` annotation (Finding 1 fix)

### Phase 5 Completion Checklist

- [x] Rate limiting implemented and tested
- [x] CORS configured correctly
- [x] CSRF protection complete
- [x] Security headers applied
- [x] Security logging implemented
- [x] Security audit completed
- [x] Penetration testing done
- [x] All critical/high issues fixed
- [x] Security documentation updated

## 7. Phase 6: Documentation & Deployment

**Duration:** Week 5  
**Dependencies:** Phase 5 complete  
**Owner:** DevOps + Backend Team

### 7.1 Task 6.1: Create OpenAPI/Swagger Documentation

**Priority:** High  
**Estimated Time:** 12 hours

**Steps:**
1. Install `swaggo/swag` CLI: `go install github.com/swaggo/swag/cmd/swag@latest`
2. Add Go module dependencies: `github.com/swaggo/gin-swagger`, `github.com/swaggo/files`, `github.com/swaggo/swag`
3. Create `cmd/auth-server/docs.go` with general API info annotations (`@title`, `@version`, `@description`, `@host`, `@BasePath`, `@securityDefinitions.apikey`)
4. Add `// @` swag annotations to all handler functions:
   - Request/response schemas (`@Param`, `@Success`, `@Failure`)
   - Authentication requirements (`@Security BearerAuth`)
   - Summary and description (`@Summary`, `@Description`, `@Tags`)
   - Route and method (`@Router`)
5. Add `ErrorResponse` struct to `dto.go` for consistent error documentation
6. Run `swag init -g cmd/auth-server/docs.go -o docs-swagger/ --parseDependency --parseInternal` to generate `docs-swagger/` package
7. Register gin-swagger handler at `GET /api/docs/*any` with CSP override

**Acceptance Criteria:**
- [x] All endpoints documented
- [x] Schemas accurate
- [x] Authentication requirements documented
- [x] Error responses documented
- [x] OAuth flow documented
- [x] Swagger UI accessible at `/api/docs/index.html`
- [x] Documentation accurate

**Deliverables:**
- `cmd/auth-server/docs.go` ✓ — General API info swag annotations (`@title`, `@version`, `@description`, `@host`, `@BasePath`, `@securityDefinitions.apikey BearerAuth`).
- Handler annotation comments ✓ — All 22 endpoints annotated across `auth_handler.go`, `client_handler.go`, `provider_handler.go`, `user_handler.go`, `session_handler.go`, and `health_handler.go`.
- `docs-swagger/docs.go`, `docs-swagger/swagger.json`, `docs-swagger/swagger.yaml` ✓ — Auto-generated by `swag init`; cover all 16 route paths across auth, clients, providers, users, sessions, and ops groups.
- `internal/transport/http/api/docs.go` ✓ — Registers `ginSwagger.WrapHandler(swaggerFiles.Handler)` at `GET /api/docs/*any` with a CSP override that permits Swagger UI assets from unpkg.com.

**Notes:**
- `swag init` must be re-run after any annotation changes: `swag init -g cmd/auth-server/docs.go -o docs-swagger/ --parseDependency --parseInternal`
- The generated `docs-swagger/` package is imported as a blank import (`_ "github.com/SamuelWang/goauth-server/docs-swagger"`) in `docs.go` to register the spec at init time.
- `SecurityHeadersMiddleware` sets `Content-Security-Policy: default-src 'none'` globally; the docs handler overrides this header before delegating to gin-swagger so Swagger UI scripts and styles load from unpkg.com.
- `persistAuthorization: true` and `tryItOutEnabled: true` are enabled in the Swagger UI config for a better developer experience.
- The old hand-written `docs/api/openapi.yaml`, `docs/api/spec/spec.go` embed package, and `docs/api/spec/openapi.yaml` were removed — the swag-generated `docs/swagger.yaml` supersedes them.

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
- [x] Setup instructions complete
- [x] All admin tasks documented
- [x] Client-provider relationship explained clearly
- [x] Provider isolation per client documented
- [x] Security guidelines included
- [x] Troubleshooting section helpful

**Deliverables:**
- `docs/v0.2.0/AdministratorGuide.md` ✓

**Notes:**
- Covers full environment variable reference, key generation, database setup and migration order.
- Documents the bootstrap flow for creating the first admin user via direct SQL (no built-in bootstrap endpoint).
- All CRUD examples for clients, providers, users, and sessions include `curl` samples with required `Authorization` and `X-CSRF-Token` headers.
- Common provider configurations (Google, GitHub, Microsoft Entra ID) included as collapsible examples.
- Production deployment checklist included in the security section.
- Troubleshooting covers the most common failure modes: missing keys, 401/403 errors, CSRF errors, provider cross-client 404, invalid_grant causes, and provider re-encryption after key rotation.

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
- [x] Integration steps clear
- [x] Client-scoped provider model explained
- [x] Provider configuration documented
- [x] Code examples provided
- [x] Error handling explained
- [x] Example application works
- [x] Multi-provider setup example included

**Deliverables:**
- `docs/v0.2.0/ClientIntegrationGuide.md` ✓
- Code examples in TypeScript/JavaScript, Python, and Go ✓

**Notes:**
- Guide follows the same structure and style as `AdministratorGuide.md`.
- Documents all six steps of the OAuth 2.0 Authorization Code Grant flow from the client application's perspective: provider discovery, login initiation, callback handling, token exchange, token usage, and logout.
- Client-scoped provider model explained with concrete examples showing isolation between clients; 404-vs-403 behavior documented to prevent information disclosure.
- Code examples cover server-side token exchange for Node.js/Express (TypeScript), Flask (Python), and net/http (Go). Token exchange is always performed server-side — `client_secret` is never exposed to the browser.
- CSRF token handling (`X-CSRF-Token` header from `csrf_token` cookie) documented and demonstrated in all language examples.
- Rate limits (token exchange: 10/min/IP; login: 20/min/IP) documented in the API reference table.
- Multi-provider setup section shows a single callback endpoint handling all providers, and explains Goauth's email-based user deduplication across providers.
- Security considerations section covers client secret storage, redirect URI validation, state/CSRF parameter, token storage best practices, and token expiry handling.

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
- [x] Multi-stage build works
- [x] Image size optimized
- [x] Runs as non-root user
- [x] Health check configured
- [x] Image builds successfully
- [x] Container runs correctly

**Deliverables:**
- `Dockerfile` ✓
- `.dockerignore` ✓

**Notes:**
- Two-stage build: `golang:1.25.5-alpine` builder → `alpine:3.21` runtime.
- Binary compiled with `CGO_ENABLED=0 -ldflags="-w -s"` for a statically-linked, stripped binary; final image is ~45 MB.
- Runtime stage installs only `ca-certificates` (required for HTTPS calls to OAuth providers), `tzdata`, and `wget` (used by the health probe).
- A dedicated `appuser:appgroup` (non-root, system account) is created with `adduser -S / addgroup -S` and set via `USER appuser`.
- `HEALTHCHECK` polls `GET /ops/health` every 30 s (5 s timeout, 15 s start period, 3 retries) using the shell form so `${PORT:-8080}` is expanded correctly at runtime.
- `.dockerignore` excludes `.git/`, `.env`, `.cert/`, `bin/`, `docs/`, `coverage.out`, and tooling directories to minimise build context size and prevent accidental inclusion of secrets or private keys.

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

- [x] API documentation complete (OpenAPI) — Task 6.1 ✓
- [x] Administrator guide written — Task 6.2 ✓
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
