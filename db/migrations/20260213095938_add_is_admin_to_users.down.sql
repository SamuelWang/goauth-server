-- Add is_admin column to users table (DOWN)
-- This migration removes the is_admin column

-- Drop the index first
DROP INDEX IF EXISTS idx_users_is_admin;

-- Drop the is_admin column
ALTER TABLE users DROP COLUMN IF EXISTS is_admin;