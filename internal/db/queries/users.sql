-- name: CreateUser :one
INSERT INTO
  users (
    email,
    email_verified,
    first_name,
    last_name,
    provider,
    provider_id,
    provider_data,
    locale,
    last_login_at
  )
VALUES
  ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING
  *;

-- name: GetUserByEmail :one
SELECT
  *
FROM
  users
WHERE
  email = $1
LIMIT
  1;

-- name: GetUserByProviderID :one
SELECT
  *
FROM
  users
WHERE
  provider = $1
  AND provider_id = $2
LIMIT
  1;

-- name: GetUserByID :one
SELECT
  *
FROM
  users
WHERE
  id = $1
LIMIT
  1;

-- name: UpdateLastLogin :one
UPDATE users
SET
  provider_data = $2,
  last_login_at = $3
WHERE
  id = $1
RETURNING
  *;

-- name: UpdateUser :one
UPDATE users
SET
  email = $2,
  email_verified = $3,
  first_name = $4,
  last_name = $5,
  locale = $6
WHERE
  id = $1
RETURNING
  *;