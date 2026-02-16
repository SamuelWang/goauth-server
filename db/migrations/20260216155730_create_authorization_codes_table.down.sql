-- Create authorization_codes table migration (DOWN)
-- Removes the `authorization_codes` table

-- Drop the indexes
DROP INDEX IF EXISTS idx_authorization_codes_provider_id;
DROP INDEX IF EXISTS idx_authorization_codes_client_id;
DROP INDEX IF EXISTS idx_authorization_codes_user_id;
DROP INDEX IF EXISTS idx_authorization_codes_expires_at;

-- Drop the table (cascade will handle foreign key references)
DROP TABLE IF EXISTS authorization_codes;
