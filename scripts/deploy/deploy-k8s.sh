#!/usr/bin/env bash
# deploy-k8s.sh — Deploy Goauth Server to a Kubernetes cluster
#
# Usage:
#   ./scripts/deploy/deploy-k8s.sh [OPTIONS]
#
# Options:
#   -n, --namespace NS     Kubernetes namespace (default: goauth)
#   -t, --tag TAG          Docker image tag to deploy (default: 0.2.0)
#   -i, --image IMAGE      Full image name, e.g. registry.example.com/goauth-server
#                          (default: goauth-server)
#   --context CTX          kubectl context to use (default: current context)
#   --no-migrate           Skip the migration Job
#   --dry-run              Print manifests without applying them
#   -h, --help             Show this help message
#
# Prerequisites:
#   - kubectl configured and pointing at the target cluster
#   - The goauth-secret Secret must be populated before running this script.
#     See k8s/secret.yaml for required keys, or create it manually:
#
#       kubectl create secret generic goauth-secret \
#         --namespace=goauth \
#         --from-literal=db-password='...' \
#         --from-literal=access-token-private-key='...' \
#         --from-literal=access-token-public-key='...' \
#         --from-literal=provider-encryption-key='...' \
#         --from-literal=session-signing-key='...'
#
# Examples:
#   # First-time deploy
#   ./scripts/deploy/deploy-k8s.sh --tag 0.2.0
#
#   # Update to a new image tag
#   ./scripts/deploy/deploy-k8s.sh --tag 0.2.1
#
#   # Dry-run to preview what would be applied
#   ./scripts/deploy/deploy-k8s.sh --dry-run
set -euo pipefail

# ── Resolve project root ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

# ── Defaults ────────────────────────────────────────────────────────────────
NAMESPACE="goauth"
IMAGE_TAG="0.2.0"
IMAGE_NAME="goauth-server"
KUBE_CONTEXT=""
RUN_MIGRATE=true
DRY_RUN=false

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
    -n|--namespace) NAMESPACE="$2";     shift 2 ;;
    -t|--tag)       IMAGE_TAG="$2";     shift 2 ;;
    -i|--image)     IMAGE_NAME="$2";    shift 2 ;;
    --context)      KUBE_CONTEXT="$2";  shift 2 ;;
    --no-migrate)   RUN_MIGRATE=false;  shift   ;;
    --dry-run)      DRY_RUN=true;       shift   ;;
    -h|--help)      usage ;;
    *) log_error "Unknown option: $1"; usage ;;
  esac
done

FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"
KUBECTL="kubectl"
if [[ -n "${KUBE_CONTEXT}" ]]; then
  KUBECTL="kubectl --context=${KUBE_CONTEXT}"
fi

KUBECTL_APPLY="${KUBECTL} apply"
if [[ "${DRY_RUN}" == true ]]; then
  KUBECTL_APPLY="${KUBECTL_APPLY} --dry-run=client"
  log_warn "Dry-run mode — no changes will be applied"
fi

K8S_DIR="${PROJECT_ROOT}/k8s"

# ── Pre-flight checks ────────────────────────────────────────────────────────
log_info "Running pre-flight checks"

if ! command -v kubectl &>/dev/null; then
  log_error "kubectl is not installed or not in PATH"
  exit 1
fi

if [[ "${DRY_RUN}" == false ]]; then
  if ! ${KUBECTL} cluster-info &>/dev/null; then
    log_error "Cannot reach the Kubernetes cluster. Check your kubeconfig and context."
    exit 1
  fi
fi

log_success "Pre-flight checks passed"
log_info "Target: namespace=${NAMESPACE}, image=${FULL_IMAGE}"

# ── Apply namespace ──────────────────────────────────────────────────────────
log_info "Applying namespace"
${KUBECTL_APPLY} -f "${K8S_DIR}/namespace.yaml"

# ── Apply ConfigMap ──────────────────────────────────────────────────────────
log_info "Applying ConfigMap"
${KUBECTL_APPLY} -f "${K8S_DIR}/configmap.yaml"

# ── Check Secret exists (skip in dry-run) ────────────────────────────────────
if [[ "${DRY_RUN}" == false ]]; then
  if ! ${KUBECTL} get secret goauth-secret -n "${NAMESPACE}" &>/dev/null; then
    log_error "Secret 'goauth-secret' does not exist in namespace '${NAMESPACE}'."
    log_error "Create it before deploying:"
    log_error ""
    log_error "  kubectl create secret generic goauth-secret \\"
    log_error "    --namespace=${NAMESPACE} \\"
    log_error "    --from-literal=db-password='...' \\"
    log_error "    --from-literal=access-token-private-key='...' \\"
    log_error "    --from-literal=access-token-public-key='...' \\"
    log_error "    --from-literal=provider-encryption-key='...' \\"
    log_error "    --from-literal=session-signing-key='...'"
    exit 1
  fi
  log_success "Secret 'goauth-secret' exists"
fi

# ── Run migrations ──────────────────────────────────────────────────────────
if [[ "${RUN_MIGRATE}" == true ]]; then
  log_info "Applying migration Job"
  # Delete any previous completed/failed Job with the same name first
  if [[ "${DRY_RUN}" == false ]]; then
    ${KUBECTL} delete job goauth-migrate -n "${NAMESPACE}" --ignore-not-found=true &>/dev/null
  fi
  ${KUBECTL_APPLY} -f "${K8S_DIR}/migrate-job.yaml"

  if [[ "${DRY_RUN}" == false ]]; then
    log_info "Waiting for migration Job to complete (timeout: 120 s)"
    if ! ${KUBECTL} wait --for=condition=complete job/goauth-migrate \
        -n "${NAMESPACE}" --timeout=120s; then
      log_error "Migration Job did not complete in time. Logs:"
      ${KUBECTL} logs -n "${NAMESPACE}" \
        -l app.kubernetes.io/component=migration --tail=100 || true
      exit 1
    fi
    log_success "Migrations applied"
  fi
fi

# ── Update deployment image ──────────────────────────────────────────────────
log_info "Setting server image to ${FULL_IMAGE}"
# Patch the image in deployment.yaml before applying
PATCHED_DEPLOYMENT="$(sed "s|image: goauth-server:.*|image: ${FULL_IMAGE}|g" \
  "${K8S_DIR}/deployment.yaml")"

if [[ "${DRY_RUN}" == true ]]; then
  echo "${PATCHED_DEPLOYMENT}" | ${KUBECTL_APPLY} -f -
else
  echo "${PATCHED_DEPLOYMENT}" | ${KUBECTL_APPLY} -f -
fi

# ── Apply Service and Ingress ─────────────────────────────────────────────────
log_info "Applying Service"
${KUBECTL_APPLY} -f "${K8S_DIR}/service.yaml"

log_info "Applying Ingress"
${KUBECTL_APPLY} -f "${K8S_DIR}/ingress.yaml"

# ── Wait for rollout ─────────────────────────────────────────────────────────
if [[ "${DRY_RUN}" == false ]]; then
  log_info "Waiting for deployment rollout (timeout: 120 s)"
  if ! ${KUBECTL} rollout status deployment/goauth-server \
      -n "${NAMESPACE}" --timeout=120s; then
    log_error "Deployment rollout did not complete in time. Logs:"
    ${KUBECTL} logs -n "${NAMESPACE}" \
      -l app.kubernetes.io/component=server --tail=50 || true
    exit 1
  fi
  log_success "Rollout complete"
fi

log_success "Kubernetes deployment complete!"
if [[ "${DRY_RUN}" == false ]]; then
  echo ""
  echo "  Pods:"
  ${KUBECTL} get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=goauth-server
fi
