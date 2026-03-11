#!/usr/bin/env bash
# deploy-docker.sh — Deploy Goauth Server using Docker Compose
#
# Usage:
#   ./scripts/deploy/deploy-docker.sh [OPTIONS]
#
# Options:
#   -e, --env FILE       Path to .env file (default: .env)
#   -t, --tag TAG        Docker image tag to deploy (default: latest)
#   -p, --pull           Pull latest images before deploying
#   -b, --build          Rebuild the server image before deploying
#   --no-migrate         Skip running database migrations
#   -h, --help           Show this help message
#
# Environment variables (loaded from .env file):
#   See docker-compose.yml for the full list.
#
# Examples:
#   # First-time deploy with .env file
#   cp .env.example .env && vim .env
#   ./scripts/deploy/deploy-docker.sh --build
#
#   # Rolling update (pull new image and restart)
#   ./scripts/deploy/deploy-docker.sh --pull
#
#   # Deploy a specific version tag
#   ./scripts/deploy/deploy-docker.sh --tag v0.2.1
set -euo pipefail

# ── Resolve project root ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

# ── Defaults ────────────────────────────────────────────────────────────────
ENV_FILE=".env"
IMAGE_TAG="latest"
PULL=false
BUILD=false
RUN_MIGRATE=true

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
    -e|--env)       ENV_FILE="$2";  shift 2 ;;
    -t|--tag)       IMAGE_TAG="$2"; shift 2 ;;
    -p|--pull)      PULL=true;      shift   ;;
    -b|--build)     BUILD=true;     shift   ;;
    --no-migrate)   RUN_MIGRATE=false; shift ;;
    -h|--help)      usage ;;
    *) log_error "Unknown option: $1"; usage ;;
  esac
done

# ── Pre-flight checks ────────────────────────────────────────────────────────
log_info "Running pre-flight checks"

if ! command -v docker &>/dev/null; then
  log_error "docker is not installed or not in PATH"
  exit 1
fi

if ! docker compose version &>/dev/null; then
  log_error "docker compose (v2) is required but not found"
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  log_error ".env file not found at: ${ENV_FILE}"
  log_error "Copy .env.example to ${ENV_FILE} and fill in the required values"
  exit 1
fi

# Validate required env vars are non-empty in the env file
REQUIRED_VARS=(
  DB_PASSWORD
  ACCESS_TOKEN_PRIVATE_KEY
  ACCESS_TOKEN_PUBLIC_KEY
  PROVIDER_ENCRYPTION_KEY
  SESSION_SIGNING_KEY
)
missing=0
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  [[ -z "$line" ]]                && continue
  KEY="${line%%=*}"
  VALUE="${line#*=}"
  for req in "${REQUIRED_VARS[@]}"; do
    if [[ "$KEY" == "$req" && -z "$VALUE" ]]; then
      log_error "Required variable ${req} is empty in ${ENV_FILE}"
      missing=$((missing + 1))
    fi
  done
done < "${ENV_FILE}"
if [[ $missing -gt 0 ]]; then
  log_error "${missing} required variable(s) are missing. Aborting."
  exit 1
fi

log_success "Pre-flight checks passed"

# Export VERSION so Docker Compose can use it for image tagging
export VERSION="${IMAGE_TAG}"

# ── Optional: pull latest images ─────────────────────────────────────────────
if [[ "${PULL}" == true ]]; then
  log_info "Pulling latest base images"
  docker compose --env-file "${ENV_FILE}" pull postgres migrate
  log_success "Images pulled"
fi

# ── Optional: rebuild server image ──────────────────────────────────────────
if [[ "${BUILD}" == true ]]; then
  log_info "Building server image (tag: ${IMAGE_TAG})"
  docker compose --env-file "${ENV_FILE}" build --no-cache server
  log_success "Server image built"
fi

# ── Run migrations ──────────────────────────────────────────────────────────
if [[ "${RUN_MIGRATE}" == true ]]; then
  log_info "Starting database and running migrations"
  docker compose --env-file "${ENV_FILE}" up -d postgres
  log_info "Waiting for postgres to be healthy"
  for i in $(seq 1 30); do
    if docker compose --env-file "${ENV_FILE}" exec -T postgres \
        pg_isready -U "${DB_USER:-goauth}" -d "${DB_NAME:-goauth}" &>/dev/null; then
      break
    fi
    if [[ $i -eq 30 ]]; then
      log_error "Postgres did not become healthy within 150 s. Aborting."
      exit 1
    fi
    sleep 5
  done
  docker compose --env-file "${ENV_FILE}" run --rm migrate
  log_success "Migrations applied"
fi

# ── Deploy server ────────────────────────────────────────────────────────────
log_info "Deploying server (tag: ${IMAGE_TAG})"
docker compose --env-file "${ENV_FILE}" up -d --remove-orphans server

# ── Health check ─────────────────────────────────────────────────────────────
PORT="$(grep -E '^PORT=' "${ENV_FILE}" | cut -d= -f2 || echo 8080)"
PORT="${PORT:-8080}"
log_info "Waiting for service to pass health check on port ${PORT}"
for i in $(seq 1 20); do
  if curl -sf "http://localhost:${PORT}/ops/health" &>/dev/null; then
    log_success "Service is healthy"
    break
  fi
  if [[ $i -eq 20 ]]; then
    log_error "Service did not become healthy within 100 s"
    docker compose --env-file "${ENV_FILE}" logs --tail=50 server
    exit 1
  fi
  sleep 5
done

log_success "Deployment complete!"
echo ""
echo "  API:      http://localhost:${PORT}/api/v1"
echo "  Docs:     http://localhost:${PORT}/api/docs/index.html"
echo "  Health:   http://localhost:${PORT}/ops/health"
