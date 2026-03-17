-- Create clients table migration (DOWN)
-- Removes the `clients` table

-- Drop the trigger first
DROP TRIGGER IF EXISTS set_updated_at ON clients;

-- Drop the indexes
DROP INDEX IF EXISTS idx_clients_is_active;

-- Drop the table (this will also remove the foreign key constraint)
DROP TABLE IF EXISTS clients;
