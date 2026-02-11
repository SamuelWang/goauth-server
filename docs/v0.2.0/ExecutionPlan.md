# Execution Plan - v0.2.0

## Document Information
* **Version:** 0.2.0
* **Created:** February 1, 2026
* **Based on:** System Design Document v0.2.0
* **Project:** Goauth Server

## 1. Executive Summary

This document provides a detailed, step-by-step execution plan for implementing version 0.2.0 of the Goauth authentication and authorization service. The implementation is structured into 6 sequential phases, each with specific tasks, deliverables, and acceptance criteria.

### 1.1 Project Objectives
* Implement OAuth 2.0 Authorization Code Grant flow
* Enable configurable OAuth provider management (starting with Google)
* Implement administrator capabilities for managing users, clients, and sessions
* Establish secure token and session management
* Deploy containerized solution with PostgreSQL backend

### 1.2 Key Deliverables
* Database schema with 6 tables (oauth_providers, users, clients, authorization_codes, access_tokens, schema_migrations)
* Complete API with 3 router groups (web, api, ops)
* Admin management interface for providers, clients, users, and sessions
* Security features including rate limiting, CORS, CSRF protection
* Docker deployment configuration
* Comprehensive test coverage (>80%)

## 2. Phase 1: Database Schema

**Duration:** Week 1  
**Dependencies:** None  
**Owner:** Backend Team

### 2.1 Task 1.1: Create oauth_providers Migration

**Priority:** High  
**Estimated Time:** 4 hours

**Steps:**
1. Create migration file: `migrate create -ext sql -dir ./db/migrations create_oauth_providers_table`
2. Implement table schema:
   ```sql
   CREATE TABLE oauth_providers (
       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       name TEXT UNIQUE NOT NULL,
       display_name TEXT NOT NULL,
       client_id TEXT NOT NULL,
       client_secret TEXT NOT NULL,
       auth_url TEXT NOT NULL,
       token_url TEXT NOT NULL,
       user_info_url TEXT NOT NULL,
       scopes TEXT[] NOT NULL,
       is_enabled BOOLEAN DEFAULT false,
       created_at TIMESTAMPTZ DEFAULT now(),
       updated_at TIMESTAMPTZ DEFAULT now()
   );
   ```
3. Create indexes:
   ```sql
   CREATE INDEX idx_oauth_providers_is_enabled ON oauth_providers(is_enabled);
   ```
4. Add updated_at trigger
5. Create rollback migration

**Acceptance Criteria:**
- [ ] Migration file created and executable
- [ ] All columns match System Design specification
- [ ] Indexes created correctly
- [ ] Trigger for updated_at column works
- [ ] Rollback migration works correctly
- [ ] Migration runs successfully on clean database

**Deliverables:**
- `YYYYMMDDHHMMSS_create_oauth_providers_table.up.sql`
- `YYYYMMDDHHMMSS_create_oauth_providers_table.down.sql`

### 2.2 Task 1.2: Update users Table Migration

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
- [ ] is_admin column added with correct default
- [ ] Index created on is_admin column
- [ ] Existing users have is_admin = false
- [ ] Migration and rollback work correctly

**Deliverables:**
- `YYYYMMDDHHMMSS_add_is_admin_to_users.up.sql`
- `YYYYMMDDHHMMSS_add_is_admin_to_users.down.sql`

### 2.3 Task 1.3: Create clients Table Migration

**Priority:** High  
**Estimated Time:** 4 hours

**Steps:**
1. Create migration file: `migrate create -ext sql -dir ./db/migrations create_clients_table`
2. Implement table with all columns per System Design
3. Create foreign key to users(id) for created_by
4. Create indexes on id and is_active
5. Add updated_at trigger
6. Create rollback migration

**Acceptance Criteria:**
- [ ] All columns match specification
- [ ] Foreign key constraint works correctly
- [ ] Default grant_types array includes 'authorization_code'
- [ ] Indexes created
- [ ] Cascade delete behavior not set (preserve audit trail)
- [ ] Migration and rollback work

**Deliverables:**
- `YYYYMMDDHHMMSS_create_clients_table.up.sql`
- `YYYYMMDDHHMMSS_create_clients_table.down.sql`

### 2.4 Task 1.4: Create authorization_codes Table Migration

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
- [ ] All columns including provider_id present
- [ ] All three foreign keys with CASCADE delete
- [ ] Unique constraint on code column
- [ ] All indexes created (expires_at, user_id, client_id, provider_id)
- [ ] Migration and rollback work

**Deliverables:**
- `YYYYMMDDHHMMSS_create_authorization_codes_table.up.sql`
- `YYYYMMDDHHMMSS_create_authorization_codes_table.down.sql`

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
- [ ] All columns match specification
- [ ] token_hash has unique constraint
- [ ] Foreign keys with CASCADE delete work
- [ ] All indexes created
- [ ] Migration and rollback work

**Deliverables:**
- `YYYYMMDDHHMMSS_create_access_tokens_table.up.sql`
- `YYYYMMDDHHMMSS_create_access_tokens_table.down.sql`

### 2.6 Task 1.6: Seed Initial Google Provider

**Priority:** Medium  
**Estimated Time:** 2 hours  
**Dependencies:** Task 1.1 complete

**Steps:**
1. Create seed migration: `migrate create -ext sql -dir ./db/migrations seed_google_provider`
2. Insert Google OAuth provider with placeholder credentials:
   ```sql
   INSERT INTO oauth_providers (name, display_name, client_id, client_secret, auth_url, token_url, user_info_url, scopes, is_enabled)
   VALUES (
       'google',
       'Google',
       'PLACEHOLDER_CLIENT_ID',
       'PLACEHOLDER_CLIENT_SECRET',
       'https://accounts.google.com/o/oauth2/v2/auth',
       'https://oauth2.googleapis.com/token',
       'https://www.googleapis.com/oauth2/v2/userinfo',
       ARRAY['openid', 'email', 'profile'],
       false
   );
   ```
3. Add note in migration comments to configure via admin API
4. Create rollback migration

**Acceptance Criteria:**
- [ ] Google provider seeded with correct URLs
- [ ] is_enabled set to false (requires admin configuration)
- [ ] Placeholder credentials clearly marked
- [ ] Migration runs after oauth_providers table creation

**Deliverables:**
- `YYYYMMDDHHMMSS_seed_google_provider.up.sql`
- `YYYYMMDDHHMMSS_seed_google_provider.down.sql`

### 2.7 Task 1.7: Update Schema Dump

**Priority:** Low  
**Estimated Time:** 1 hour  
**Dependencies:** All migrations complete

**Steps:**
1. Run all migrations on clean database
2. Execute schema dump script: `./scripts/db/dump_schema.sh`
3. Verify `db/schema/schema.sql` is updated
4. Review schema for correctness
5. Commit schema dump

**Acceptance Criteria:**
- [ ] Schema dump includes all new tables
- [ ] All indexes and foreign keys present
- [ ] Triggers included
- [ ] Schema is properly formatted

**Deliverables:**
- Updated `db/schema/schema.sql`

### Phase 1 Completion Checklist

- [ ] All 5 table migrations created and tested
- [ ] All indexes created
- [ ] All foreign keys configured correctly
- [ ] Triggers for updated_at columns work
- [ ] Google provider seeded
- [ ] Schema dump updated
- [ ] All migrations can be rolled back
- [ ] Database documentation updated

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

-- name: GetOAuthProviderByName :one
SELECT * FROM oauth_providers
WHERE name = $1 LIMIT 1;

-- name: ListOAuthProviders :many
SELECT * FROM oauth_providers
ORDER BY display_name;

-- name: ListEnabledOAuthProviders :many
SELECT * FROM oauth_providers
WHERE is_enabled = true
ORDER BY display_name;

-- name: CreateOAuthProvider :one
INSERT INTO oauth_providers (
    name, display_name, client_id, client_secret,
    auth_url, token_url, user_info_url, scopes, is_enabled
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
) RETURNING *;

-- name: UpdateOAuthProvider :one
UPDATE oauth_providers
SET display_name = $2,
    client_id = $3,
    client_secret = $4,
    auth_url = $5,
    token_url = $6,
    user_info_url = $7,
    scopes = $8,
    is_enabled = $9,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteOAuthProvider :exec
UPDATE oauth_providers
SET is_enabled = false, updated_at = now()
WHERE id = $1;
```

3. Run `sqlc generate`
4. Verify generated code in `internal/repository/`

**Acceptance Criteria:**
- [ ] All CRUD operations implemented
- [ ] Queries use proper parameter binding
- [ ] sqlc generates code without errors
- [ ] Generated methods have correct signatures

**Deliverables:**
- `db/queries/oauth_providers.sql`
- Generated Go code in `internal/repository/`

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
- [ ] All queries support required operations
- [ ] Pagination implemented with LIMIT/OFFSET
- [ ] Filters for is_active status
- [ ] Soft delete sets is_active = false
- [ ] sqlc generation successful

**Deliverables:**
- `db/queries/clients.sql`
- Generated repository code

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
- [ ] All queries include provider_id column
- [ ] Filters for client_id, user_id, is_revoked
- [ ] Mark as used updates used_at timestamp
- [ ] Cleanup query for expired codes
- [ ] sqlc generation successful

**Deliverables:**
- `db/queries/authorization_codes.sql`
- Generated repository code

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
- [ ] token_hash used for lookups (not plain token)
- [ ] Filters for client_id, user_id, is_revoked
- [ ] Bulk revocation by client and user
- [ ] Cleanup query for expired tokens
- [ ] sqlc generation successful

**Deliverables:**
- `db/queries/access_tokens.sql`
- Generated repository code

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
- [ ] All existing queries include is_admin
- [ ] New admin-related queries implemented
- [ ] Pagination support added
- [ ] sqlc generation successful

**Deliverables:**
- Updated `db/queries/users.sql`
- Updated repository code

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
- [ ] All repository methods have tests
- [ ] Tests use isolated test database
- [ ] Test database cleaned between tests
- [ ] Foreign key constraints tested
- [ ] Edge cases covered
- [ ] Code coverage >80%
- [ ] All tests pass

**Deliverables:**
- `internal/repository/oauth_providers_test.go`
- `internal/repository/clients_test.go`
- `internal/repository/authorization_codes_test.go`
- `internal/repository/access_tokens_test.go`
- Updated `internal/repository/users_test.go`

### Phase 2 Completion Checklist

- [ ] All SQL query files created
- [ ] sqlc code generation successful
- [ ] All repository methods available
- [ ] Unit tests written for all repositories
- [ ] Tests pass with >80% coverage
- [ ] Code review completed
- [ ] Documentation updated

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
   - `ListProviders()` - List all providers
   - `ListEnabledProviders()` - Public endpoint data
   - `GetProvider(id)` - Get provider details
   - `GetProviderByName(name)` - Get by name
   - `CreateProvider(dto)` - Create with secret encryption
   - `UpdateProvider(id, dto)` - Update with secret re-encryption
   - `EnableProvider(id)` - Enable provider
   - `DisableProvider(id)` - Disable provider
4. Implement encryption/decryption for client_secret using AES-256-GCM
5. Add input validation

**Acceptance Criteria:**
- [ ] All service methods implemented
- [ ] Client secrets encrypted before storage
- [ ] Client secrets decrypted when needed for OAuth flow
- [ ] Secrets never returned in API responses
- [ ] Input validation for all fields
- [ ] Error handling for duplicate names
- [ ] URL validation for OAuth endpoints

**Deliverables:**
- `internal/service/provider/provider.go`
- `internal/service/provider/encryption.go`

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
- [ ] Client secrets generated cryptographically secure
- [ ] Secrets hashed with bcrypt before storage
- [ ] Plain secret only returned once at creation/regeneration
- [ ] Redirect URIs validated (HTTPS in production)
- [ ] Admin authorization checked
- [ ] Pagination implemented
- [ ] Soft delete sets is_active = false

**Deliverables:**
- `internal/service/client/client.go`
- `internal/service/client/validation.go`

### 4.3 Task 3.3: Implement Authorization Code Flow Service

**Priority:** Critical  
**Estimated Time:** 16 hours

**Steps:**
1. Create `internal/service/auth/authorization.go`
2. Implement authorization initiation:
   - `InitiateAuthorization(provider, clientID, redirectURI, state, scope)`
   - Validate provider is enabled
   - Validate client exists and is active
   - Validate redirect URI matches registered URIs
   - Generate OAuth provider authorization URL
   - Store state in session
3. Implement provider callback handling:
   - `HandleProviderCallback(provider, code, state)`
   - Validate state matches session
   - Exchange provider code for ID token
   - Verify ID token signature
   - Extract user info
   - Create/update user in database
   - Generate authorization code
   - Store code with provider_id
4. Implement token exchange:
   - `ExchangeCodeForToken(code, clientID, clientSecret, redirectURI)`
   - Validate client credentials
   - Validate authorization code (not expired, not used, not revoked)
   - Verify redirect URI matches
   - Mark code as used
   - Generate JWT access token
   - Store token hash in database
   - Return access token
5. Implement logout:
   - `RevokeToken(tokenHash)`
   - Mark token as revoked

**Acceptance Criteria:**
- [ ] Provider selection implemented
- [ ] Provider enabled check enforced
- [ ] Client validation works
- [ ] Redirect URI validation strict
- [ ] State parameter CSRF protection works
- [ ] ID token verification implemented
- [ ] User creation/update logic works
- [ ] Authorization codes expire in 5 minutes
- [ ] Codes are single-use
- [ ] JWT tokens expire in 60 minutes
- [ ] Token revocation immediate

**Deliverables:**
- `internal/service/auth/authorization.go`
- `internal/service/auth/token.go`
- `internal/service/auth/provider_client.go` (OAuth provider HTTP client)

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
- [ ] Pagination implemented for lists
- [ ] Filters work correctly
- [ ] Admin-only authorization enforced
- [ ] Bulk revocation works
- [ ] Cleanup jobs functional

**Deliverables:**
- `internal/service/session/session.go`

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
- [ ] Pagination works
- [ ] Status update sets is_active
- [ ] Admin check used by middleware
- [ ] Filters work correctly

**Deliverables:**
- `internal/service/user/user.go`

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
- [ ] All service methods tested
- [ ] Mock repositories used
- [ ] Happy paths tested
- [ ] Error conditions tested
- [ ] Edge cases covered
- [ ] Code coverage >80%
- [ ] All tests pass

**Deliverables:**
- Service test files for each service
- Mock interfaces

### Phase 3 Completion Checklist

- [ ] All services implemented
- [ ] Business logic complete
- [ ] Authorization checks in place
- [ ] Input validation implemented
- [ ] Error handling comprehensive
- [ ] Unit tests written with >80% coverage
- [ ] Code review completed

## 5. Phase 4: API Layer

**Duration:** Week 3-4  
**Dependencies:** Phase 3 complete  
**Owner:** Backend Team

### 5.1 Task 4.1: Implement OAuth Provider Management Endpoints

**Priority:** High  
**Estimated Time:** 8 hours

**Steps:**
1. Create `internal/transport/http/api/v1/handler/provider_handler.go`
2. Implement handlers:
   - `GET /api/v1/providers` - List all (admin only)
   - `GET /api/v1/providers/:id` - Get details (admin only)
   - `POST /api/v1/providers` - Create (admin only)
   - `PATCH /api/v1/providers/:id` - Update (admin only)
   - `DELETE /api/v1/providers/:id` - Disable (admin only)
3. Create DTOs in `dto.go`
4. Add admin middleware to routes
5. Add request validation
6. Add to router in `router.go`

**Acceptance Criteria:**
- [ ] All endpoints implemented
- [ ] Admin middleware applied
- [ ] Request/response DTOs defined
- [ ] Input validation works
- [ ] Error responses follow OAuth 2.0 format
- [ ] Secrets excluded from responses

**Deliverables:**
- `internal/transport/http/api/v1/handler/provider_handler.go`
- Updated `dto.go`
- Updated router configuration

### 5.2 Task 4.2: Implement Public Authentication Endpoints

**Priority:** Critical  
**Estimated Time:** 6 hours

**Steps:**
1. Update `internal/transport/http/api/v1/handler/auth_handler.go`
2. Implement handlers:
   - `GET /api/v1/auth/providers` - List enabled providers (public)
   - `POST /api/v1/auth/token` - Token exchange (public)
   - `POST /api/v1/auth/logout` - Logout (authenticated)
3. Create request/response DTOs
4. Add token validation middleware for logout
5. Add to router

**Acceptance Criteria:**
- [ ] Provider list returns only enabled providers
- [ ] Provider list excludes sensitive data
- [ ] Token endpoint validates all parameters
- [ ] Token endpoint returns OAuth 2.0 compliant response
- [ ] Logout requires valid bearer token

**Deliverables:**
- Updated auth handler
- DTOs for token exchange

### 5.3 Task 4.3: Implement Web OAuth Flow Endpoints

**Priority:** Critical  
**Estimated Time:** 10 hours

**Steps:**
1. Update `internal/transport/http/web/handler/auth_handler.go`
2. Implement handlers:
   - `GET /web/auth/:provider/login` - Initiate OAuth (public)
   - `GET /web/auth/:provider/callback` - Handle callback (public)
3. Implement session management for state parameter
4. Implement redirect logic
5. Add error handling with user-friendly messages
6. Add to web router

**Acceptance Criteria:**
- [ ] Provider parameter validated
- [ ] State parameter stored in secure session cookie
- [ ] CSRF protection via state validation
- [ ] Redirects work correctly
- [ ] Error pages display helpful messages
- [ ] Authorization code passed to client

**Deliverables:**
- Updated web auth handler
- Session middleware
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
**Estimated Time:** 16 hours

**Steps:**
1. Set up integration test environment
2. Write end-to-end tests for OAuth flow:
   - Provider selection
   - Authorization initiation
   - Callback handling
   - Token exchange
   - API access with token
   - Logout
3. Write tests for admin endpoints:
   - Provider management
   - Client management
   - User management
   - Session management
4. Test error conditions
5. Test authentication/authorization
6. Ensure >80% API coverage

**Acceptance Criteria:**
- [ ] Complete OAuth flow tested
- [ ] All admin endpoints tested
- [ ] Authentication middleware tested
- [ ] Authorization middleware tested
- [ ] Error responses tested
- [ ] Code coverage >80%
- [ ] All tests pass

**Deliverables:**
- Integration test suite

### Phase 4 Completion Checklist

- [ ] All API endpoints implemented
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
**Estimated Time:** 8 hours

**Steps:**
1. Create `docs/v0.2.0/AdministratorGuide.md`
2. Document:
   - Initial setup and configuration
   - Creating first admin user
   - Managing OAuth providers
   - Managing client applications
   - Managing users
   - Managing sessions
   - Security best practices
   - Troubleshooting
3. Include examples and screenshots

**Acceptance Criteria:**
- [ ] Setup instructions complete
- [ ] All admin tasks documented
- [ ] Security guidelines included
- [ ] Troubleshooting section helpful

**Deliverables:**
- `docs/v0.2.0/AdministratorGuide.md`

### 7.3 Task 6.3: Create Client Integration Guide

**Priority:** High  
**Estimated Time:** 10 hours

**Steps:**
1. Create `docs/v0.2.0/ClientIntegrationGuide.md`
2. Document:
   - Overview of OAuth 2.0 Authorization Code Grant
   - Registering client application
   - Discovering available providers
   - Initiating authorization flow
   - Handling callbacks
   - Exchanging code for token
   - Using access tokens
   - Error handling
   - Code examples in multiple languages
3. Include complete example application

**Acceptance Criteria:**
- [ ] Integration steps clear
- [ ] Code examples provided
- [ ] Error handling explained
- [ ] Example application works

**Deliverables:**
- `docs/v0.2.0/ClientIntegrationGuide.md`
- Example client application

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
   - Quick start guide
   - Docker instructions
   - Development setup
   - Running tests
   - Contributing guidelines
   - License information
   - Links to documentation
2. Add badges (build status, coverage, etc.)

**Acceptance Criteria:**
- [ ] README complete and accurate
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
| Performance bottlenecks | Medium | Medium | Load testing, optimization |
| Third-party dependency issues | Medium | Medium | Vendor packages, lock files |

### 9.2 Rollback Plan

1. Keep previous version running during deployment
2. Database migrations support rollback
3. Feature flags for gradual rollout
4. Automated health checks trigger rollback
5. Database backups before production deployment

## 10. Success Criteria

### 10.1 Functional Criteria

- [ ] All API endpoints functional per specification
- [ ] OAuth 2.0 flow works with Google provider
- [ ] Admin can manage providers, clients, users, sessions
- [ ] Tokens issued and validated correctly
- [ ] Session management works

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
./scripts/db/run_migrations.sh

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
