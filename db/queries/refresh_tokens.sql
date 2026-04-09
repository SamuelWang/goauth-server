-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (
    token_hash,
    token_family_id,
    client_id,
    user_id,
    access_token_id,
    previous_token_id,
    scope,
    expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
) RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens
WHERE token_hash = $1 LIMIT 1;

-- name: GetRefreshTokenByID :one
SELECT * FROM refresh_tokens
WHERE id = $1 LIMIT 1;

-- name: ListRefreshTokensByUser :many
SELECT * FROM refresh_tokens
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountRefreshTokensByUser :one
SELECT COUNT(*) FROM refresh_tokens
WHERE user_id = $1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET is_revoked = true, revoked_at = now(), revoke_reason = $2
WHERE id = $1;

-- name: RevokeRefreshTokenFamily :exec
UPDATE refresh_tokens
SET is_revoked = true, revoked_at = now(), revoke_reason = $2
WHERE token_family_id = $1;

-- name: MarkRefreshTokenUsed :exec
UPDATE refresh_tokens
SET used_at = now(), is_revoked = true, revoke_reason = 'used'
WHERE id = $1;

-- name: RevokeRefreshTokensByUser :exec
UPDATE refresh_tokens
SET is_revoked = true, revoked_at = now(), revoke_reason = $2
WHERE user_id = $1 AND is_revoked = false;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens
WHERE expires_at < now();
