-- Add is_confidential and allow_refresh_tokens columns to clients table (UP)
-- is_confidential: distinguishes confidential clients (can hold a secret) from public clients.
-- allow_refresh_tokens: gates refresh token issuance for this client.

ALTER TABLE clients
  ADD COLUMN is_confidential BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN allow_refresh_tokens BOOLEAN NOT NULL DEFAULT false;
