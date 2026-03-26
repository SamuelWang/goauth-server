-- Create refresh_tokens table migration (UP)
-- Stores issued refresh tokens using a token family model to support
-- rotation and replay detection.

CREATE TABLE refresh_tokens (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_family_id   UUID        NOT NULL,
    token_hash        TEXT        UNIQUE NOT NULL,
    client_id         UUID        NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id           UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_token_id   UUID        REFERENCES access_tokens(id) ON DELETE SET NULL,
    previous_token_id UUID        REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    scope             TEXT        NOT NULL DEFAULT '',
    expires_at        TIMESTAMPTZ NOT NULL,
    is_revoked        BOOLEAN     NOT NULL DEFAULT false,
    revoked_at        TIMESTAMPTZ,
    revoke_reason     TEXT,
    used_at           TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for family-wide revocation (replay detection)
CREATE INDEX idx_refresh_tokens_token_family_id ON refresh_tokens(token_family_id);

-- Index for user-based queries and session management
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);

-- Index for client-based queries
CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens(client_id);

-- Index for cleanup jobs (delete expired tokens)
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Index for linked access token lookups
CREATE INDEX idx_refresh_tokens_access_token_id ON refresh_tokens(access_token_id);
