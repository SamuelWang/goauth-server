-- Create users table migration (UP)
-- Adds `users` table, indexes, and trigger to keep `updated_at` current.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS
  users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    first_name TEXT,
    last_name TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    locale VARCHAR(10) NOT NULL DEFAULT 'en-US',
    provider TEXT,
    provider_id TEXT,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );

-- Unique constraints / indexes
CREATE UNIQUE INDEX IF NOT EXISTS users_provider_provider_id_key ON users (provider, provider_id);

-- Trigger function to set updated_at on updates
CREATE
OR REPLACE FUNCTION internal_set_updated_at () RETURNS TRIGGER AS $$
BEGIN
	NEW.updated_at = now();
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_updated_at ON users;

CREATE TRIGGER set_updated_at BEFORE
UPDATE ON users FOR EACH ROW
EXECUTE FUNCTION internal_set_updated_at ();