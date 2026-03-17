#!/usr/bin/env bash
# backup-database.sh — Create a compressed PostgreSQL backup of the Goauth database
#
# Usage:
#   ./scripts/deploy/backup-database.sh [OPTIONS]
#
# Options:
#   -e, --env FILE       Path to .env file (default: .env). Ignored when
#                        --host is provided explicitly.
#   -H, --host HOST      Database host          (default: localhost)
#   -P, --port PORT      Database port          (default: 5432)
#   -U, --user USER      Database user          (default: goauth)
#   -d, --dbname NAME    Database name          (default: goauth)
#   -o, --output DIR     Directory for backups  (default: ./backups)
#   -r, --retain DAYS    Delete backups older than N days (default: 30)
#   --docker             Connect via 'docker compose exec postgres'
#                        instead of a local pg_dump
#   -h, --help           Show this help message
#
# Environment variables (when not using --host flags):
#   DB_HOST, DB_PORT, DB_USER, DB_NAME, DB_PASSWORD (or PGPASSWORD)
#
# Output:
#   <output-dir>/goauth_<YYYYMMDD_HHMMSS>.dump.gz
#   - PostgreSQL custom-format dump, gzip-compressed
#   - Restorable with restore-database.sh
#
# Examples:
#   # Backup via docker compose (development)
#   ./scripts/deploy/backup-database.sh --docker
#
#   # Backup a remote production database
#   ./scripts/deploy/backup-database.sh \
#     --host db.example.com --port 5432 \
#     --user goauth --dbname goauth \
#     --output /var/backups/goauth
set -euo pipefail

# ── Resolve project root ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

# ── Defaults ────────────────────────────────────────────────────────────────
ENV_FILE=".env"
DB_HOST_ARG=""
DB_PORT_ARG="5432"
DB_USER_ARG="goauth"
DB_NAME_ARG="goauth"
OUTPUT_DIR="${PROJECT_ROOT}/backups"
RETAIN_DAYS=30
USE_DOCKER=false

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
    -e|--env)     ENV_FILE="$2";      shift 2 ;;
    -H|--host)    DB_HOST_ARG="$2";   shift 2 ;;
    -P|--port)    DB_PORT_ARG="$2";   shift 2 ;;
    -U|--user)    DB_USER_ARG="$2";   shift 2 ;;
    -d|--dbname)  DB_NAME_ARG="$2";   shift 2 ;;
    -o|--output)  OUTPUT_DIR="$2";    shift 2 ;;
    -r|--retain)  RETAIN_DAYS="$2";   shift 2 ;;
    --docker)     USE_DOCKER=true;    shift   ;;
    -h|--help)    usage ;;
    *) log_error "Unknown option: $1"; usage ;;
  esac
done

# ── Load .env if present and no explicit host was given ──────────────────────
if [[ -z "${DB_HOST_ARG}" && -f "${ENV_FILE}" ]]; then
  log_info "Loading database config from ${ENV_FILE}"
  # Source only DB_* variables; use grep+export to avoid executing arbitrary code
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

# PGPASSWORD is read by pg_dump automatically; prefer explicit DB_PASSWORD
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
  if ! command -v pg_dump &>/dev/null; then
    log_error "pg_dump is not installed. Install postgresql-client."
    exit 1
  fi
fi

if ! command -v gzip &>/dev/null; then
  log_error "gzip is required but not found"
  exit 1
fi

log_success "Pre-flight checks passed"

# ── Create output directory ──────────────────────────────────────────────────
mkdir -p "${OUTPUT_DIR}"

# ── Generate backup filename ──────────────────────────────────────────────────
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="${OUTPUT_DIR}/${DB_NAME}_${TIMESTAMP}.dump"
COMPRESSED_FILE="${BACKUP_FILE}.gz"

log_info "Starting backup of database '${DB_NAME}'"
log_info "Destination: ${COMPRESSED_FILE}"

# ── Run pg_dump ──────────────────────────────────────────────────────────────
if [[ "${USE_DOCKER}" == true ]]; then
  # Stream the dump directly from the container's pg_dump
  docker compose exec -T postgres \
    pg_dump \
      --username "${DB_USER}" \
      --dbname "${DB_NAME}" \
      --format=custom \
      --no-password \
    | gzip -9 > "${COMPRESSED_FILE}"
else
  pg_dump \
    --host="${DB_HOST}" \
    --port="${DB_PORT}" \
    --username="${DB_USER}" \
    --dbname="${DB_NAME}" \
    --format=custom \
    --no-password \
  | gzip -9 > "${COMPRESSED_FILE}"
fi

FILE_SIZE="$(du -h "${COMPRESSED_FILE}" | cut -f1)"
log_success "Backup created: ${COMPRESSED_FILE} (${FILE_SIZE})"

# ── Remove old backups ────────────────────────────────────────────────────────
if [[ "${RETAIN_DAYS}" -gt 0 ]]; then
  log_info "Removing backups older than ${RETAIN_DAYS} days"
  OLD_COUNT="$(find "${OUTPUT_DIR}" -maxdepth 1 -name "${DB_NAME}_*.dump.gz" \
    -mtime "+${RETAIN_DAYS}" | wc -l | tr -d ' ')"
  if [[ "${OLD_COUNT}" -gt 0 ]]; then
    find "${OUTPUT_DIR}" -maxdepth 1 -name "${DB_NAME}_*.dump.gz" \
      -mtime "+${RETAIN_DAYS}" -delete
    log_success "Removed ${OLD_COUNT} old backup(s)"
  else
    log_info "No old backups to remove"
  fi
fi

log_success "Database backup complete!"
echo ""
echo "  File:   ${COMPRESSED_FILE}"
echo "  Size:   ${FILE_SIZE}"
echo ""
echo "  To restore, run:"
echo "    ./scripts/deploy/restore-database.sh --file ${COMPRESSED_FILE}"
