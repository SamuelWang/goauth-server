-- Create oauth_providers table migration (UP)
-- Adds `oauth_providers` table for client-scoped OAuth provider management

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

-- Create index on client_id for fast lookups by client
CREATE INDEX idx_oauth_providers_client_id ON oauth_providers(client_id);

-- Create index on is_enabled for filtering enabled providers
CREATE INDEX idx_oauth_providers_is_enabled ON oauth_providers(is_enabled);

-- Create composite index for fast enabled provider lookups per client
CREATE INDEX idx_oauth_providers_client_enabled ON oauth_providers(client_id, is_enabled);

-- Create trigger to automatically update updated_at timestamp
DROP TRIGGER IF EXISTS set_updated_at ON oauth_providers;

CREATE TRIGGER set_updated_at
BEFORE UPDATE ON oauth_providers
FOR EACH ROW
EXECUTE FUNCTION internal_set_updated_at();
