-- Revert: restore NOT NULL constraint on client_id.
-- WARNING: this will fail if any rows have a NULL client_id.
ALTER TABLE access_tokens ALTER COLUMN client_id SET NOT NULL;
