#!/usr/bin/env bash
set -euo pipefail

# locate repo root (fall back to cwd)
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ENV_FILE="$REPO_ROOT/.env"
TARGET_DIR="$REPO_ROOT/db/schema"
TARGET_FILE="$TARGET_DIR/schema.sql"

# Load environment variables from .env if present
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
fi

: "${DB_HOST:?DB_HOST is required (set in .env or environment)}"
: "${DB_PORT:?DB_PORT is required (set in .env or environment)}"
: "${DB_USER:?DB_USER is required (set in .env or environment)}"
: "${DB_PASSWORD:?DB_PASSWORD is required (set in .env or environment)}"
: "${DB_NAME:?DB_NAME is required (set in .env or environment)}"
: "${DB_SSLMODE:?DB_SSLMODE is required (set in .env or environment)}"

export DB_CONN="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=${DB_SSLMODE}"

mkdir -p "$TARGET_DIR"

echo "Dumping schema to $TARGET_FILE"

# https://github.com/sqlc-dev/sqlc/issues/4065
# Remove RESTRICT/UNRESTRICT commands to avoid issues with sqlc
pg_dump --schema-only --no-owner --no-privileges "$DB_CONN" | sed '/^\\restrict /d;/^\\unrestrict /d' > "$TARGET_FILE"

echo "Schema dumped to $TARGET_FILE"
