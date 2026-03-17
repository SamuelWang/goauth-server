-- name: GetAccessToken :one
SELECT * FROM access_tokens
WHERE token_hash = $1 LIMIT 1;

-- name: GetAccessTokenByID :one
SELECT * FROM access_tokens
WHERE id = $1 LIMIT 1;

-- name: ListAccessTokens :many
SELECT * FROM access_tokens
WHERE
    ($1::uuid IS NULL OR client_id = $1) AND
    ($2::uuid IS NULL OR user_id = $2) AND
    ($3::boolean IS NULL OR is_revoked = $3)
ORDER BY created_at DESC
LIMIT $4 OFFSET $5;

-- name: CountAccessTokens :one
SELECT COUNT(*) FROM access_tokens
WHERE
    ($1::uuid IS NULL OR client_id = $1) AND
    ($2::uuid IS NULL OR user_id = $2) AND
    ($3::boolean IS NULL OR is_revoked = $3);

-- name: CreateAccessToken :one
INSERT INTO access_tokens (
    token_hash,
    client_id,
    user_id,
    scope,
    expires_at
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: RevokeAccessToken :exec
UPDATE access_tokens
SET is_revoked = true
WHERE id = $1;

-- name: RevokeAccessTokensByClient :exec
UPDATE access_tokens
SET is_revoked = true
WHERE client_id = $1;

-- name: RevokeAccessTokensByUser :exec
UPDATE access_tokens
SET is_revoked = true
WHERE user_id = $1;

-- name: DeleteExpiredAccessTokens :exec
DELETE FROM access_tokens
WHERE expires_at < now();
