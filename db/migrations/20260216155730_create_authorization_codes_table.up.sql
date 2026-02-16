-- Create authorization_codes table migration (UP)
-- Adds `authorization_codes` table for OAuth 2.0 Authorization Code Grant flow

CREATE TABLE authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT UNIQUE NOT NULL,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES oauth_providers(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT DEFAULT '',
    state TEXT,
    code_challenge TEXT,
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    is_revoked BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Create index on expires_at for cleanup queries
CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes(expires_at);

-- Create index on user_id for user-based queries
CREATE INDEX idx_authorization_codes_user_id ON authorization_codes(user_id);

-- Create index on client_id for client-based queries
CREATE INDEX idx_authorization_codes_client_id ON authorization_codes(client_id);

-- Create index on provider_id for provider-based queries
CREATE INDEX idx_authorization_codes_provider_id ON authorization_codes(provider_id);
