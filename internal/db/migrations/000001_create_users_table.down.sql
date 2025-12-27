-- Drop users table migration (DOWN)
-- Reverts the changes applied in the corresponding UP migration.

-- Remove trigger and function first
DROP TRIGGER IF EXISTS set_updated_at ON users;
DROP FUNCTION IF EXISTS internal_set_updated_at();

-- Drop indexes (optional; dropping the table will remove them as well)
DROP INDEX IF EXISTS users_provider_provider_id_key;

-- Drop the table
DROP TABLE IF EXISTS users;

-- Note: we intentionally do NOT drop the pgcrypto extension here because
-- it may be shared by other migrations or objects in the database.

