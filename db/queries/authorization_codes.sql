-- name: GetAuthorizationCode :one
SELECT * FROM authorization_codes
WHERE code = $1 LIMIT 1;

-- name: GetAuthorizationCodeByID :one
SELECT * FROM authorization_codes
WHERE id = $1 LIMIT 1;

-- name: ListAuthorizationCodes :many
SELECT * FROM authorization_codes
WHERE
    ($1::uuid IS NULL OR client_id = $1) AND
    ($2::uuid IS NULL OR user_id = $2) AND
    ($3::boolean IS NULL OR is_revoked = $3)
ORDER BY created_at DESC
LIMIT $4 OFFSET $5;

-- name: CountAuthorizationCodes :one
SELECT COUNT(*) FROM authorization_codes
WHERE
    ($1::uuid IS NULL OR client_id = $1) AND
    ($2::uuid IS NULL OR user_id = $2) AND
    ($3::boolean IS NULL OR is_revoked = $3);

-- name: CreateAuthorizationCode :one
INSERT INTO authorization_codes (
    code,
    client_id,
    user_id,
    provider_id,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method,
    expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
) RETURNING *;

-- name: MarkAuthorizationCodeUsed :one
UPDATE authorization_codes
SET used_at = now()
WHERE id = $1
RETURNING *;

-- name: RevokeAuthorizationCode :exec
UPDATE authorization_codes
SET is_revoked = true
WHERE id = $1;

-- name: RevokeAuthorizationCodeByCode :exec
UPDATE authorization_codes
SET is_revoked = true
WHERE code = $1;

-- name: DeleteExpiredAuthorizationCodes :exec
DELETE FROM authorization_codes
WHERE expires_at < now();
