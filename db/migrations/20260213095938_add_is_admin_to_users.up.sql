-- Add is_admin column to users table (UP)
-- This migration adds the is_admin column to track administrator users

-- Add is_admin column with default value false
ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT false;

-- Create index on is_admin for fast admin queries
CREATE INDEX idx_users_is_admin ON users(is_admin);