-- name: GetOAuthProvider :one
SELECT * FROM oauth_providers
WHERE id = $1 LIMIT 1;

-- name: GetOAuthProviderByClientAndName :one
SELECT * FROM oauth_providers
WHERE client_id = $1 AND name = $2 LIMIT 1;

-- name: ListOAuthProvidersByClient :many
SELECT * FROM oauth_providers
WHERE client_id = $1
ORDER BY display_name;

-- name: ListEnabledOAuthProvidersByClient :many
SELECT * FROM oauth_providers
WHERE client_id = $1 AND is_enabled = true
ORDER BY display_name;

-- name: CreateOAuthProvider :one
INSERT INTO oauth_providers (
    client_id, name, display_name, provider_client_id, provider_client_secret,
    auth_url, token_url, user_info_url, scopes, is_enabled
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
) RETURNING *;

-- name: UpdateOAuthProvider :one
UPDATE oauth_providers
SET display_name = $2,
    provider_client_id = $3,
    provider_client_secret = $4,
    auth_url = $5,
    token_url = $6,
    user_info_url = $7,
    scopes = $8,
    is_enabled = $9,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteOAuthProvider :exec
DELETE FROM oauth_providers
WHERE id = $1;

-- name: DisableOAuthProvider :exec
UPDATE oauth_providers
SET is_enabled = false, updated_at = now()
WHERE id = $1;
