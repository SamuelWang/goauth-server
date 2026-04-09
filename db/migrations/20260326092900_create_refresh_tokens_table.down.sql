-- Create refresh_tokens table migration (DOWN)
-- Removes the refresh_tokens table and all its indexes.

-- Drop the indexes first
DROP INDEX IF EXISTS idx_refresh_tokens_access_token_id;
DROP INDEX IF EXISTS idx_refresh_tokens_expires_at;
DROP INDEX IF EXISTS idx_refresh_tokens_client_id;
DROP INDEX IF EXISTS idx_refresh_tokens_user_id;
DROP INDEX IF EXISTS idx_refresh_tokens_token_family_id;

-- Drop the table (CASCADE handles the self-referencing FK on previous_token_id)
DROP TABLE IF EXISTS refresh_tokens CASCADE;
