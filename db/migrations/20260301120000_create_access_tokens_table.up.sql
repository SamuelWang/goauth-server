-- Create access_tokens table migration (UP)
-- Adds `access_tokens` table for storing issued JWT access tokens for auditing and revocation

CREATE TABLE access_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT UNIQUE NOT NULL,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope TEXT DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    is_revoked BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Create index on expires_at for cleanup queries
CREATE INDEX idx_access_tokens_expires_at ON access_tokens(expires_at);

-- Create index on user_id for user-based queries
CREATE INDEX idx_access_tokens_user_id ON access_tokens(user_id);

-- Create index on client_id for client-based queries
CREATE INDEX idx_access_tokens_client_id ON access_tokens(client_id);
