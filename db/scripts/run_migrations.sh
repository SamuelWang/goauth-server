#!/usr/bin/env bash
set -euo pipefail

# Run DB migrations by executing all *.up.sql files in db/migrations
# Behavior:
# - If a .env file exists at repository root it will be sourced and exported.
# - Required DB variables: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
# - Constructs DB_CONN

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

MIGRATIONS_DIR="$REPO_ROOT/db/migrations"

if [ ! -d "$MIGRATIONS_DIR" ]; then
  echo "Migrations directory not found: $MIGRATIONS_DIR" >&2
  exit 1
fi

# Usage: run_migrations.sh [N]
# If N is provided and is a positive integer, run only N up migrations.
# If no argument is provided, run all pending migrations.
if [ "$#" -gt 1 ]; then
  echo "Usage: $0 [N]" >&2
  exit 2
fi

if [ "$#" -eq 1 ]; then
  # Validate numeric positive integer
  case "$1" in
    ''|*[!0-9]*)
      echo "Invalid argument: must be a positive integer" >&2
      exit 2
      ;;
    *)
      STEPS="$1"
      if [ "$STEPS" -eq 0 ]; then
        echo "No migrations to apply (0 specified)."
        exit 0
      fi
      migrate -path "$MIGRATIONS_DIR" -database "$DB_CONN" up "$STEPS"
      ;;
  esac
else
  migrate -path "$MIGRATIONS_DIR" -database "$DB_CONN" up
fi

echo "Migrations command completed."
