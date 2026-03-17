-- Create oauth_providers table migration (DOWN)
-- Removes the `oauth_providers` table

-- Drop the trigger first
DROP TRIGGER IF EXISTS set_updated_at ON oauth_providers;

-- Drop the indexes
DROP INDEX IF EXISTS idx_oauth_providers_client_enabled;
DROP INDEX IF EXISTS idx_oauth_providers_is_enabled;
DROP INDEX IF EXISTS idx_oauth_providers_client_id;

-- Drop the table (cascade will handle foreign key references)
DROP TABLE IF EXISTS oauth_providers;
