-- Add is_confidential and allow_refresh_tokens columns to clients table (DOWN)
-- Removes the columns added in the UP migration.

ALTER TABLE clients
  DROP COLUMN IF EXISTS allow_refresh_tokens,
  DROP COLUMN IF EXISTS is_confidential;
