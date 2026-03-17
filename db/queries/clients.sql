-- name: GetClient :one
SELECT * FROM clients
WHERE id = $1 LIMIT 1;

-- name: GetClientByID :one
SELECT * FROM clients
WHERE id = $1 AND is_active = true LIMIT 1;

-- name: ListClients :many
SELECT * FROM clients
WHERE
    ($1::boolean IS NULL OR is_active = $1)
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountClients :one
SELECT COUNT(*) FROM clients
WHERE
    ($1::boolean IS NULL OR is_active = $1);

-- name: CreateClient :one
INSERT INTO clients (
    name,
    description,
    client_secret_hash,
    redirect_uris,
    grant_types,
    is_active,
    created_by
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
) RETURNING *;

-- name: UpdateClient :one
UPDATE clients
SET
    name = $2,
    description = $3,
    redirect_uris = $4,
    grant_types = $5,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteClient :exec
UPDATE clients
SET is_active = false, updated_at = now()
WHERE id = $1;

-- name: RegenerateClientSecret :one
UPDATE clients
SET
    client_secret_hash = $2,
    updated_at = now()
WHERE id = $1
RETURNING *;
