# Database Documentation

**Database:** PostgreSQL 16  
**Schema:** `public`  
**Extensions:** `pgcrypto`

## Table of Contents

1. [Overview](#overview)
2. [Entity Relationship Diagram](#entity-relationship-diagram)
3. [Tables](#tables)
   - [users](#users)
   - [clients](#clients)
   - [oauth_providers](#oauth_providers)
   - [authorization_codes](#authorization_codes)
   - [access_tokens](#access_tokens)
   - [schema_migrations](#schema_migrations)
4. [Functions & Triggers](#functions--triggers)
5. [Indexes](#indexes)
6. [Migration History](#migration-history)
7. [Queries](#queries)

## Overview

This database supports an OAuth 2.0 authorization server. It manages user identities, registered client applications, per-client OAuth provider configurations, authorization codes issued during the authorization flow, and access tokens granted to clients on behalf of users.

## Entity Relationship Diagram

```mermaid
erDiagram
    users {
        uuid id PK
        text email UK
        boolean email_verified
        text first_name
        text last_name
        boolean is_active
        varchar locale
        text provider
        text provider_id
        jsonb provider_data
        timestamptz last_login_at
        timestamptz created_at
        timestamptz updated_at
        boolean is_admin
    }

    clients {
        uuid id PK
        text name
        text description
        text client_secret_hash
        text[] redirect_uris
        text[] grant_types
        boolean is_active
        uuid created_by FK
        timestamptz created_at
        timestamptz updated_at
    }

    oauth_providers {
        uuid id PK
        uuid client_id FK
        text name
        text display_name
        text provider_client_id
        text provider_client_secret
        text auth_url
        text token_url
        text user_info_url
        text[] scopes
        boolean is_enabled
        timestamptz created_at
        timestamptz updated_at
    }

    authorization_codes {
        uuid id PK
        text code UK
        uuid client_id FK
        uuid user_id FK
        uuid provider_id FK
        text redirect_uri
        text scope
        text state
        text code_challenge
        varchar code_challenge_method
        timestamptz expires_at
        timestamptz used_at
        boolean is_revoked
        timestamptz created_at
    }

    access_tokens {
        uuid id PK
        text token_hash UK
        uuid client_id FK
        uuid user_id FK
        text scope
        timestamptz expires_at
        boolean is_revoked
        timestamptz created_at
    }

    users ||--o{ clients : "created_by"
    clients ||--o{ oauth_providers : "client_id"
    clients ||--o{ authorization_codes : "client_id"
    clients ||--o{ access_tokens : "client_id"
    users ||--o{ authorization_codes : "user_id"
    users ||--o{ access_tokens : "user_id"
    oauth_providers ||--o{ authorization_codes : "provider_id"
```

## Tables

### `users`

Stores user accounts. Users can be created via external OAuth providers (e.g., Google). The `provider` and `provider_id` columns identify the upstream identity, while `provider_data` stores raw profile data returned by the provider.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `uuid` | NOT NULL | `gen_random_uuid()` | Primary key |
| `email` | `text` | NOT NULL | — | User's email address (unique) |
| `email_verified` | `boolean` | NOT NULL | `false` | Whether the email has been verified |
| `first_name` | `text` | NULL | — | User's first name |
| `last_name` | `text` | NULL | — | User's last name |
| `is_active` | `boolean` | NOT NULL | `true` | Whether the account is active |
| `locale` | `varchar(10)` | NOT NULL | `'en-US'` | Preferred locale |
| `provider` | `text` | NULL | — | Name of the OAuth provider (e.g., `google`) |
| `provider_id` | `text` | NULL | — | User ID as provided by the upstream OAuth provider |
| `provider_data` | `jsonb` | NULL | `'{}'` | Raw profile payload from the OAuth provider |
| `last_login_at` | `timestamptz` | NULL | — | Timestamp of the most recent login |
| `created_at` | `timestamptz` | NOT NULL | `now()` | Record creation timestamp |
| `updated_at` | `timestamptz` | NOT NULL | `now()` | Record last-update timestamp (auto-managed by trigger) |
| `is_admin` | `boolean` | NULL | `false` | Whether the user has administrator privileges |

**Constraints:**

| Name | Type | Columns |
|---|---|---|
| `users_pkey` | PRIMARY KEY | `id` |
| `users_email_key` | UNIQUE | `email` |
| `users_provider_provider_id_key` | UNIQUE INDEX | `provider`, `provider_id` |

**Indexes:**

| Name | Columns | Purpose |
|---|---|---|
| `users_provider_provider_id_key` | `(provider, provider_id)` | Fast lookup by upstream provider identity |
| `idx_users_is_admin` | `(is_admin)` | Fast filtering of administrator accounts |

### `clients`

Stores registered OAuth 2.0 client applications. Each client is created by a user and holds the hashed client secret, allowed redirect URIs, and supported grant types.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `uuid` | NOT NULL | `gen_random_uuid()` | Primary key |
| `name` | `text` | NOT NULL | — | Human-readable name for the client application |
| `description` | `text` | NULL | — | Optional description |
| `client_secret_hash` | `text` | NOT NULL | — | Bcrypt hash of the client secret |
| `redirect_uris` | `text[]` | NOT NULL | — | Allowed redirect URIs for the authorization flow |
| `grant_types` | `text[]` | NOT NULL | `ARRAY['authorization_code']` | Supported OAuth grant types |
| `is_active` | `boolean` | NULL | `true` | Whether the client is active and can initiate flows |
| `created_by` | `uuid` | NOT NULL | — | FK → `users.id`; the admin who registered this client |
| `created_at` | `timestamptz` | NULL | `now()` | Record creation timestamp |
| `updated_at` | `timestamptz` | NULL | `now()` | Record last-update timestamp (auto-managed by trigger) |

**Constraints:**

| Name | Type | Columns |
|---|---|---|
| `clients_pkey` | PRIMARY KEY | `id` |
| `clients_created_by_fkey` | FOREIGN KEY | `created_by` → `users(id)` |

**Indexes:**

| Name | Columns | Purpose |
|---|---|---|
| `idx_clients_is_active` | `(is_active)` | Fast filtering of active clients |

### `oauth_providers`

Stores per-client OAuth provider configurations. A single client can have multiple configured providers (e.g., Google, GitHub). Each row holds the upstream provider credentials and endpoint URLs needed to drive the OAuth flow.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `uuid` | NOT NULL | `gen_random_uuid()` | Primary key |
| `client_id` | `uuid` | NOT NULL | — | FK → `clients.id`; owning client |
| `name` | `text` | NOT NULL | — | Internal provider identifier (e.g., `google`) |
| `display_name` | `text` | NOT NULL | — | Human-readable label shown in UI (e.g., `Sign in with Google`) |
| `provider_client_id` | `text` | NOT NULL | — | Client ID issued by the upstream OAuth provider |
| `provider_client_secret` | `text` | NOT NULL | — | Client secret issued by the upstream OAuth provider |
| `auth_url` | `text` | NOT NULL | — | Authorization endpoint URL of the upstream provider |
| `token_url` | `text` | NOT NULL | — | Token exchange endpoint URL of the upstream provider |
| `user_info_url` | `text` | NOT NULL | — | User info endpoint URL of the upstream provider |
| `scopes` | `text[]` | NOT NULL | — | OAuth scopes to request from the upstream provider |
| `is_enabled` | `boolean` | NULL | `false` | Whether this provider is currently enabled for use |
| `created_at` | `timestamptz` | NULL | `now()` | Record creation timestamp |
| `updated_at` | `timestamptz` | NULL | `now()` | Record last-update timestamp (auto-managed by trigger) |

**Constraints:**

| Name | Type | Columns |
|---|---|---|
| `oauth_providers_pkey` | PRIMARY KEY | `id` |
| `oauth_providers_client_id_name_key` | UNIQUE | `(client_id, name)` |
| `oauth_providers_client_id_fkey` | FOREIGN KEY | `client_id` → `clients(id)` ON DELETE CASCADE |

**Indexes:**

| Name | Columns | Purpose |
|---|---|---|
| `idx_oauth_providers_client_id` | `(client_id)` | Fast provider lookups per client |
| `idx_oauth_providers_is_enabled` | `(is_enabled)` | Fast filtering by enabled state |
| `idx_oauth_providers_client_enabled` | `(client_id, is_enabled)` | Fast lookup of enabled providers for a specific client |

### `authorization_codes`

Stores short-lived authorization codes issued during the OAuth 2.0 Authorization Code Grant flow. A code is single-use (`used_at` is set on redemption) and can be revoked. PKCE parameters (`code_challenge`, `code_challenge_method`) are stored to support public clients.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `uuid` | NOT NULL | `gen_random_uuid()` | Primary key |
| `code` | `text` | NOT NULL | — | The authorization code value (unique) |
| `client_id` | `uuid` | NOT NULL | — | FK → `clients.id`; the requesting client |
| `user_id` | `uuid` | NOT NULL | — | FK → `users.id`; the authorizing user |
| `provider_id` | `uuid` | NOT NULL | — | FK → `oauth_providers.id`; the provider used for authentication |
| `redirect_uri` | `text` | NOT NULL | — | The redirect URI included in the authorization request |
| `scope` | `text` | NULL | `''` | Requested OAuth scopes |
| `state` | `text` | NULL | — | Opaque state value from the client (CSRF protection) |
| `code_challenge` | `text` | NULL | — | PKCE code challenge (Base64URL-encoded SHA-256 of verifier) |
| `code_challenge_method` | `varchar(10)` | NULL | — | PKCE method (`S256` or `plain`) |
| `expires_at` | `timestamptz` | NOT NULL | — | Expiry timestamp; codes are invalid after this time |
| `used_at` | `timestamptz` | NULL | — | Timestamp when the code was redeemed; `NULL` if unused |
| `is_revoked` | `boolean` | NULL | `false` | Whether the code has been explicitly revoked |
| `created_at` | `timestamptz` | NULL | `now()` | Record creation timestamp |

**Constraints:**

| Name | Type | Columns |
|---|---|---|
| `authorization_codes_pkey` | PRIMARY KEY | `id` |
| `authorization_codes_code_key` | UNIQUE | `code` |
| `authorization_codes_client_id_fkey` | FOREIGN KEY | `client_id` → `clients(id)` ON DELETE CASCADE |
| `authorization_codes_user_id_fkey` | FOREIGN KEY | `user_id` → `users(id)` ON DELETE CASCADE |
| `authorization_codes_provider_id_fkey` | FOREIGN KEY | `provider_id` → `oauth_providers(id)` ON DELETE CASCADE |

**Indexes:**

| Name | Columns | Purpose |
|---|---|---|
| `idx_authorization_codes_expires_at` | `(expires_at)` | Efficient cleanup of expired codes |
| `idx_authorization_codes_user_id` | `(user_id)` | Fast lookup by user |
| `idx_authorization_codes_client_id` | `(client_id)` | Fast lookup by client |
| `idx_authorization_codes_provider_id` | `(provider_id)` | Fast lookup by provider |

### `access_tokens`

Stores issued JWT access tokens for auditing and revocation. The full token is never stored; only a hash (`token_hash`) is persisted so that a presented token can be validated and checked for revocation without storing the raw credential.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `uuid` | NOT NULL | `gen_random_uuid()` | Primary key |
| `token_hash` | `text` | NOT NULL | — | Hash of the issued JWT access token (unique) |
| `client_id` | `uuid` | NOT NULL | — | FK → `clients.id`; the client the token was issued to |
| `user_id` | `uuid` | NOT NULL | — | FK → `users.id`; the user the token represents |
| `scope` | `text` | NULL | `''` | Scopes granted by this token |
| `expires_at` | `timestamptz` | NOT NULL | — | Expiry timestamp of the token |
| `is_revoked` | `boolean` | NULL | `false` | Whether the token has been revoked |
| `created_at` | `timestamptz` | NULL | `now()` | Record creation timestamp |

**Constraints:**

| Name | Type | Columns |
|---|---|---|
| `access_tokens_pkey` | PRIMARY KEY | `id` |
| `access_tokens_token_hash_key` | UNIQUE | `token_hash` |
| `access_tokens_client_id_fkey` | FOREIGN KEY | `client_id` → `clients(id)` ON DELETE CASCADE |
| `access_tokens_user_id_fkey` | FOREIGN KEY | `user_id` → `users(id)` ON DELETE CASCADE |

**Indexes:**

| Name | Columns | Purpose |
|---|---|---|
| `idx_access_tokens_expires_at` | `(expires_at)` | Efficient cleanup of expired tokens |
| `idx_access_tokens_user_id` | `(user_id)` | Fast lookup by user |
| `idx_access_tokens_client_id` | `(client_id)` | Fast lookup by client |

### `schema_migrations`

Internal table managed by [golang-migrate](https://github.com/golang-migrate/migrate). Tracks which migrations have been applied.

| Column | Type | Nullable | Description |
|---|---|---|---|
| `version` | `bigint` | NOT NULL | Timestamp-based migration version |
| `dirty` | `boolean` | NOT NULL | `true` if the last migration failed mid-run |

**Constraints:**

| Name | Type | Columns |
|---|---|---|
| `schema_migrations_pkey` | PRIMARY KEY | `version` |

## Functions & Triggers

### `internal_set_updated_at()`

A `BEFORE UPDATE` trigger function that automatically sets `updated_at = now()` on any row modification.

```sql
CREATE FUNCTION public.internal_set_updated_at() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;
```

This trigger is attached to the following tables:

| Table | Trigger Name |
|---|---|
| `users` | `set_updated_at` |
| `clients` | `set_updated_at` |
| `oauth_providers` | `set_updated_at` |

## Indexes

Summary of all non-primary-key indexes:

| Index | Table | Columns | Type |
|---|---|---|---|
| `users_provider_provider_id_key` | `users` | `(provider, provider_id)` | UNIQUE |
| `idx_users_is_admin` | `users` | `(is_admin)` | BTREE |
| `idx_clients_is_active` | `clients` | `(is_active)` | BTREE |
| `idx_oauth_providers_client_id` | `oauth_providers` | `(client_id)` | BTREE |
| `idx_oauth_providers_is_enabled` | `oauth_providers` | `(is_enabled)` | BTREE |
| `idx_oauth_providers_client_enabled` | `oauth_providers` | `(client_id, is_enabled)` | BTREE |
| `idx_authorization_codes_expires_at` | `authorization_codes` | `(expires_at)` | BTREE |
| `idx_authorization_codes_user_id` | `authorization_codes` | `(user_id)` | BTREE |
| `idx_authorization_codes_client_id` | `authorization_codes` | `(client_id)` | BTREE |
| `idx_authorization_codes_provider_id` | `authorization_codes` | `(provider_id)` | BTREE |
| `idx_access_tokens_expires_at` | `access_tokens` | `(expires_at)` | BTREE |
| `idx_access_tokens_user_id` | `access_tokens` | `(user_id)` | BTREE |
| `idx_access_tokens_client_id` | `access_tokens` | `(client_id)` | BTREE |

## Migration History

Migrations are managed with [golang-migrate](https://github.com/golang-migrate/migrate) and live in `db/migrations/`. Each migration has an `.up.sql` and a `.down.sql` file.

| Version | File | Description |
|---|---|---|
| `20260109145607` | `create_users_table` | Creates the `users` table, `pgcrypto` extension, unique index on `(provider, provider_id)`, and the `internal_set_updated_at` trigger function |
| `20260213095938` | `add_is_admin_to_users` | Adds the `is_admin` boolean column to `users` and creates `idx_users_is_admin` |
| `20260213100111` | `create_clients_table` | Creates the `clients` table with FK to `users`, `is_active` index, and `set_updated_at` trigger |
| `20260216155147` | `create_oauth_providers_table` | Creates the `oauth_providers` table with FK to `clients` (CASCADE), three indexes, and `set_updated_at` trigger |
| `20260216155730` | `create_authorization_codes_table` | Creates the `authorization_codes` table with FKs to `clients`, `users`, and `oauth_providers` (all CASCADE), plus four indexes |
| `20260301120000` | `create_access_tokens_table` | Creates the `access_tokens` table with FKs to `clients` and `users` (both CASCADE), plus three indexes |

## Queries

SQLC-generated queries are defined in `db/queries/` and correspond to methods on the repository layer.

### Users (`db/queries/users.sql`)

| Query Name | Operation | Description |
|---|---|---|
| `CreateUser` | `INSERT` | Inserts a new user record and returns it |
| `GetUserByEmail` | `SELECT` | Looks up a single user by `email` |
| `GetUserByProviderID` | `SELECT` | Looks up a single user by `(provider, provider_id)` |
| `GetUserByID` | `SELECT` | Looks up a single user by `id` |
| `UpdateLastLogin` | `UPDATE` | Updates `provider_data` and `last_login_at` for a user |
| `UpdateUser` | `UPDATE` | Updates `email`, `email_verified`, `first_name`, `last_name`, and `locale` for a user |
