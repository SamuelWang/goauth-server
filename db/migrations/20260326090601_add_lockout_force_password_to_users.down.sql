-- Add lockout and force password change columns to users table (DOWN)
-- This migration removes all columns added in the UP migration.

-- Drop the index first
DROP INDEX IF EXISTS idx_users_locked_until;

-- Drop the columns
ALTER TABLE users DROP COLUMN IF EXISTS locked_until;
ALTER TABLE users DROP COLUMN IF EXISTS last_failed_login_at;
ALTER TABLE users DROP COLUMN IF EXISTS failed_login_attempts;
ALTER TABLE users DROP COLUMN IF EXISTS force_password_change;
ALTER TABLE users DROP COLUMN IF EXISTS password_hash;
