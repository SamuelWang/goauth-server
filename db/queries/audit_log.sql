-- name: CreateAuditLogEntry :one
INSERT INTO audit_log (
    event_type,
    user_id,
    client_id,
    actor_id,
    ip_address,
    metadata
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING id;

-- name: ListAuditLogEntries :many
SELECT * FROM audit_log
WHERE
    ($1::text IS NULL OR event_type = $1) AND
    ($2::uuid IS NULL OR user_id = $2) AND
    ($3::uuid IS NULL OR client_id = $3)
ORDER BY created_at DESC
LIMIT $4 OFFSET $5;

-- name: CountAuditLogEntries :one
SELECT COUNT(*) FROM audit_log
WHERE
    ($1::text IS NULL OR event_type = $1) AND
    ($2::uuid IS NULL OR user_id = $2) AND
    ($3::uuid IS NULL OR client_id = $3);
