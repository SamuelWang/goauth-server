-- Allow direct-login access tokens to be tracked without a client_id.
-- Tokens issued via POST /auth/login and POST /auth/change-password have no
-- associated OAuth client, so client_id must be nullable.
ALTER TABLE access_tokens ALTER COLUMN client_id DROP NOT NULL;
