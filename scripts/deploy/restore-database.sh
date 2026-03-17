#!/usr/bin/env bash
# restore-database.sh — Restore a Goauth PostgreSQL backup
#
# Usage:
#   ./scripts/deploy/restore-database.sh [OPTIONS] --file <backup.dump.gz>
#
# Options:
#   -f, --file FILE      Path to the backup file (.dump.gz)  REQUIRED
#   -e, --env FILE       Path to .env file (default: .env). Ignored when
#                        --host is provided explicitly.
#   -H, --host HOST      Database host          (default: localhost)
#   -P, --port PORT      Database port          (default: 5432)
#   -U, --user USER      Database user          (default: goauth)
#   -d, --dbname NAME    Database name          (default: goauth)
#   --drop-existing      Drop and recreate the database before restore.
#                        WARNING: this is DESTRUCTIVE and irreversible.
#   --docker             Connect via 'docker compose exec postgres'
#                        instead of a local pg_restore
#   -y, --yes            Skip confirmation prompts
#   -h, --help           Show this help message
#
# Environment variables (when not using --host flags):
#   DB_HOST, DB_PORT, DB_USER, DB_NAME, DB_PASSWORD (or PGPASSWORD)
#
# Examples:
#   # Restore into docker compose postgres (development)
#   ./scripts/deploy/restore-database.sh \
#     --docker --file ./backups/goauth_20260311_120000.dump.gz
#
#   # Restore to a remote database, dropping existing data first
#   ./scripts/deploy/restore-database.sh \
#     --host db.example.com \
#     --file ./backups/goauth_20260311_120000.dump.gz \
#     --drop-existing
set -euo pipefail

# ── Resolve project root ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

# ── Defaults ────────────────────────────────────────────────────────────────
BACKUP_FILE=""
ENV_FILE=".env"
DB_HOST_ARG=""
DB_PORT_ARG="5432"
DB_USER_ARG="goauth"
DB_NAME_ARG="goauth"
DROP_EXISTING=false
USE_DOCKER=false
YES=false

# ── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_success() { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Argument parsing ─────────────────────────────────────────────────────────
usage() {
  sed -n '/^# Usage/,/^[^#]/p' "$0" | head -n -1 | sed 's/^# \?//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--file)        BACKUP_FILE="$2";   shift 2 ;;
    -e|--env)         ENV_FILE="$2";      shift 2 ;;
    -H|--host)        DB_HOST_ARG="$2";   shift 2 ;;
    -P|--port)        DB_PORT_ARG="$2";   shift 2 ;;
    -U|--user)        DB_USER_ARG="$2";   shift 2 ;;
    -d|--dbname)      DB_NAME_ARG="$2";   shift 2 ;;
    --drop-existing)  DROP_EXISTING=true; shift   ;;
    --docker)         USE_DOCKER=true;    shift   ;;
    -y|--yes)         YES=true;           shift   ;;
    -h|--help)        usage ;;
    *) log_error "Unknown option: $1"; usage ;;
  esac
done

# ── Validate required arguments ──────────────────────────────────────────────
if [[ -z "${BACKUP_FILE}" ]]; then
  log_error "--file is required"
  usage
fi

if [[ ! -f "${BACKUP_FILE}" ]]; then
  log_error "Backup file not found: ${BACKUP_FILE}"
  exit 1
fi

# ── Load .env if present and no explicit host was given ──────────────────────
if [[ -z "${DB_HOST_ARG}" && -f "${ENV_FILE}" ]]; then
  log_info "Loading database config from ${ENV_FILE}"
  while IFS='=' read -r key value; do
    [[ "$key" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$key" ]] && continue
    case "$key" in
      DB_HOST|DB_PORT|DB_USER|DB_NAME|DB_PASSWORD|PGPASSWORD)
        export "$key"="$value"
        ;;
    esac
  done < "${ENV_FILE}"
fi

# Resolve final connection parameters
DB_HOST="${DB_HOST_ARG:-${DB_HOST:-localhost}}"
DB_PORT="${DB_PORT_ARG:-${DB_PORT:-5432}}"
DB_USER="${DB_USER_ARG:-${DB_USER:-goauth}}"
DB_NAME="${DB_NAME_ARG:-${DB_NAME:-goauth}}"

if [[ -n "${DB_PASSWORD:-}" && -z "${PGPASSWORD:-}" ]]; then
  export PGPASSWORD="${DB_PASSWORD}"
fi

# ── Pre-flight checks ────────────────────────────────────────────────────────
log_info "Running pre-flight checks"

if [[ "${USE_DOCKER}" == true ]]; then
  if ! command -v docker &>/dev/null; then
    log_error "docker is not installed or not in PATH"
    exit 1
  fi
  if ! docker compose version &>/dev/null; then
    log_error "docker compose (v2) is required"
    exit 1
  fi
else
  if ! command -v pg_restore &>/dev/null; then
    log_error "pg_restore is not installed. Install postgresql-client."
    exit 1
  fi
  if ! command -v psql &>/dev/null; then
    log_error "psql is not installed. Install postgresql-client."
    exit 1
  fi
fi

if ! command -v gzip &>/dev/null; then
  log_error "gzip is required but not found"
  exit 1
fi

log_success "Pre-flight checks passed"

# ── Safety confirmation ──────────────────────────────────────────────────────
FILE_SIZE="$(du -h "${BACKUP_FILE}" | cut -f1)"
echo ""
log_warn "You are about to restore the database '${DB_NAME}' on ${DB_HOST}:${DB_PORT}"
log_warn "Backup file: ${BACKUP_FILE} (${FILE_SIZE})"
if [[ "${DROP_EXISTING}" == true ]]; then
  log_warn "WARNING: --drop-existing is set. All existing data will be DELETED."
fi
echo ""

if [[ "${YES}" != true ]]; then
  read -r -p "Type 'yes' to continue: " CONFIRM
  if [[ "${CONFIRM}" != "yes" ]]; then
    log_info "Restore cancelled."
    exit 0
  fi
fi

# ── Drop and recreate database (optional) ────────────────────────────────────
if [[ "${DROP_EXISTING}" == true ]]; then
  log_warn "Dropping and recreating database '${DB_NAME}'"
  if [[ "${USE_DOCKER}" == true ]]; then
    docker compose exec -T postgres \
      psql --username="${DB_USER}" --dbname=postgres \
           -c "DROP DATABASE IF EXISTS ${DB_NAME};" \
           -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
  else
    psql \
      --host="${DB_HOST}" --port="${DB_PORT}" \
      --username="${DB_USER}" --dbname=postgres \
      -c "DROP DATABASE IF EXISTS ${DB_NAME};" \
      -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
  fi
  log_success "Database recreated"
fi

# ── Restore ──────────────────────────────────────────────────────────────────
log_info "Restoring database '${DB_NAME}' from ${BACKUP_FILE}"

if [[ "${USE_DOCKER}" == true ]]; then
  # Stream the decompressed dump into pg_restore inside the container
  gzip -dc "${BACKUP_FILE}" | \
    docker compose exec -T postgres \
      pg_restore \
        --username="${DB_USER}" \
        --dbname="${DB_NAME}" \
        --no-password \
        --exit-on-error \
        --clean \
        --if-exists
else
  gzip -dc "${BACKUP_FILE}" | \
    pg_restore \
      --host="${DB_HOST}" \
      --port="${DB_PORT}" \
      --username="${DB_USER}" \
      --dbname="${DB_NAME}" \
      --no-password \
      --exit-on-error \
      --clean \
      --if-exists
fi

log_success "Database restore complete!"
echo ""
echo "  Database: ${DB_NAME} on ${DB_HOST}:${DB_PORT}"
echo "  Restored from: ${BACKUP_FILE}"
