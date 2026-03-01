-- Create access_tokens table migration (DOWN)
-- Removes the `access_tokens` table

-- Drop the indexes
DROP INDEX IF EXISTS idx_access_tokens_client_id;
DROP INDEX IF EXISTS idx_access_tokens_user_id;
DROP INDEX IF EXISTS idx_access_tokens_expires_at;

-- Drop the table (cascade will handle foreign key references)
DROP TABLE IF EXISTS access_tokens;
