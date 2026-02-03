#!/usr/bin/env bash
set -euo pipefail

# Rollback DB migrations.
# Usage: rollback_migrations.sh [N|all]
# - N: number of down migrations to run (positive integer)
# - all: rollback all migrations (default)

# locate repo root (fall back to cwd)
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
ENV_FILE="$REPO_ROOT/.env"

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
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

MIGRATIONS_DIR="$REPO_ROOT/internal/db/migrations"

if [ ! -d "$MIGRATIONS_DIR" ]; then
  echo "Migrations directory not found: $MIGRATIONS_DIR" >&2
  exit 1
fi

ARG="${1:-all}"

usage() {
  echo "Usage: $0 [N|all]" >&2
  echo "  N   - number of down migrations to apply (positive integer)" >&2
  echo "  all - rollback all migrations (default)" >&2
  exit 2
}

if [ "$ARG" = "all" ]; then
  echo "Rolling back all migrations..."
  migrate -path internal/db/migrations -database "$DB_CONN" down
  echo "All migrations rolled back."
  exit 0
fi

if [[ "$ARG" =~ ^[0-9]+$ ]]; then
  if [ "$ARG" -eq 0 ]; then
    echo "N is 0 — nothing to do."
    exit 0
  fi
  echo "Rolling back $ARG migration(s)..."
  migrate -path internal/db/migrations -database "$DB_CONN" down "$ARG"
  echo "Rolled back $ARG migration(s)."
  exit 0
fi

echo "Invalid argument: $ARG" >&2
usage
