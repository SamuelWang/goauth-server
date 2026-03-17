-- Create clients table migration (UP)
-- Adds `clients` table for OAuth2 client application management

CREATE TABLE clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    client_secret_hash TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code']::TEXT[],
    is_active BOOLEAN DEFAULT true,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Create index on is_active for filtering active clients
CREATE INDEX idx_clients_is_active ON clients(is_active);

-- Create trigger to automatically update updated_at timestamp
DROP TRIGGER IF EXISTS set_updated_at ON clients;

CREATE TRIGGER set_updated_at 
BEFORE UPDATE ON clients 
FOR EACH ROW 
EXECUTE FUNCTION internal_set_updated_at();
