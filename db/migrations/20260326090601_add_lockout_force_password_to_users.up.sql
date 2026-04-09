-- Add lockout and force password change columns to users table (UP)
-- This migration adds columns to support account lockout and forced password changes.

-- Add password_hash column (nullable; stores Argon2id hash for local-auth accounts)
ALTER TABLE users ADD COLUMN password_hash TEXT;

-- Add force_password_change flag
ALTER TABLE users ADD COLUMN force_password_change BOOLEAN NOT NULL DEFAULT false;

-- Add failed login attempt tracking
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN last_failed_login_at TIMESTAMPTZ;

-- Add lockout expiry (nullable; NULL means not locked)
ALTER TABLE users ADD COLUMN locked_until TIMESTAMPTZ;

-- Index to support lock-expiry queries
CREATE INDEX idx_users_locked_until ON users(locked_until);
