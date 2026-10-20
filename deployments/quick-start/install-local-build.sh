#!/bin/bash
# ============================================================================
# Agent Manager quick-start, installed from this checkout
# ============================================================================
# Runs the regular quick-start installer (install.sh) against a local k3d
# cluster, but takes Agent Manager's own charts and images from this source
# tree instead of the published registry:
#
#   - charts are installed from deployments/helm-charts (AMP_LOCAL_CHARTS_DIR);
#   - the first-party images (amp-api, amp-console, amp-observer,
#     amp-evaluation-monitor) are built here with docker and loaded straight
#     into the cluster with `k3d image import` — nothing is pushed anywhere.
#
# Third-party components (OpenChoreo, the API Platform gateway, Thunder, ...)
# are installed from their public registries exactly as install.sh does.
#
# Use it to run a branch that has no published charts. Released versions are
# installed with install.sh (or k3d-install.sh) instead.
#
# Usage:
#   bash deployments/quick-start/install-local-build.sh [--skip-build]
#
#   --skip-build   reuse the images already built locally (docker image ls).
#
# Environment:
#   AMP_LOCAL_IMAGE_REGISTRY  name prefix for the local images (default amp-local)
#   AMP_LOCAL_VALUES_DIR      optional directory of extra values files, one per
#                             chart, named <chart-name>.yaml (for example
#                             wso2-agent-manager.yaml); each one found is passed
#                             to that chart's install with -f.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SKIP_BUILD=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true; shift ;;
        -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $1 (see --help)" >&2; exit 1 ;;
    esac
done

LOCAL_IMAGE_REGISTRY="${AMP_LOCAL_IMAGE_REGISTRY:-amp-local}"
# The charts' own default image tag, so no per-image tag override is needed:
# global.ampImageRegistry alone redirects every first-party image here.
LOCAL_IMAGE_TAG="0.0.0-dev"
# Fixed in install.sh; the cluster the images are loaded into.
LOCAL_CLUSTER_NAME="amp-local"

# image name | Dockerfile directory | build context (relative to the repo root).
# Mirrors .github/release-config.json, which is what CI builds.
LOCAL_IMAGES=(
    "amp-api|agent-manager-service|agent-manager-service"
    "amp-console|console|console"
    "amp-observer|agent-manager-observer|agent-manager-observer"
    "amp-evaluation-monitor|evaluation-job|."
)

local_image_ref() {
    printf '%s/%s:%s' "${LOCAL_IMAGE_REGISTRY}" "$1" "${LOCAL_IMAGE_TAG}"
}

for tool in docker k3d helm kubectl; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "❌ ${tool} is required" >&2; exit 1; }
done

if [[ "${SKIP_BUILD}" == "true" ]]; then
    for entry in "${LOCAL_IMAGES[@]}"; do
        name="${entry%%|*}"
        docker image inspect "$(local_image_ref "${name}")" >/dev/null 2>&1 || {
            echo "❌ $(local_image_ref "${name}") is not built; run without --skip-build" >&2
            exit 1
        }
    done
else
    for entry in "${LOCAL_IMAGES[@]}"; do
        IFS='|' read -r name dir context <<<"${entry}"
        echo "🔨 Building $(local_image_ref "${name}") from ${dir}/"
        docker build \
            --file "${REPO_ROOT}/${dir}/Dockerfile" \
            --build-arg "VERSION=${LOCAL_IMAGE_TAG}" \
            --tag "$(local_image_ref "${name}")" \
            "${REPO_ROOT}/${context}"
    done
fi

# Called by install.sh once the cluster is up and before anything is installed,
# so the first pod that needs an image finds it already on the node.
amp_after_cluster_ready() {
    local refs=()
    local entry
    for entry in "${LOCAL_IMAGES[@]}"; do
        refs+=("$(local_image_ref "${entry%%|*}")")
    done
    log_info "Loading locally built images into k3d cluster '${LOCAL_CLUSTER_NAME}'..."
    if ! k3d image import "${refs[@]}" --cluster "${LOCAL_CLUSTER_NAME}"; then
        log_error "Failed to load the local images into the cluster"
        exit 1
    fi
    log_success "Local images loaded"
}

# values_file_args <chart-name> -> "-f <file>" when AMP_LOCAL_VALUES_DIR holds one.
values_file_args() {
    local file="${AMP_LOCAL_VALUES_DIR:-}/$1.yaml"
    if [[ -n "${AMP_LOCAL_VALUES_DIR:-}" && -f "${file}" ]]; then
        printf '%s\n%s\n' "-f" "${file}"
    fi
}

# Overrides install.sh honors (see install-helpers.sh). The images are already on
# the node, so nothing may try to pull them: the console defaults to Always.
# shellcheck disable=SC2034  # arrays are inherited by the subshell that sources install.sh
AMP_HELM_ARGS=(
    --set "global.ampImageRegistry=${LOCAL_IMAGE_REGISTRY}"
    --set console.image.pullPolicy=IfNotPresent
    --set agentManagerService.image.pullPolicy=IfNotPresent
)
# shellcheck disable=SC2034
OBSERVABILITY_HELM_ARGS=(--set "global.ampImageRegistry=${LOCAL_IMAGE_REGISTRY}")
# shellcheck disable=SC2034
EVALUATION_HELM_ARGS=(--set "global.ampImageRegistry=${LOCAL_IMAGE_REGISTRY}")
# shellcheck disable=SC2034
PLATFORM_RESOURCES_HELM_ARGS=()
# shellcheck disable=SC2034
GATEWAY_HELM_ARGS=()
# Thunder keeps install-helpers' default (a fixed local admin password) plus any file.
# shellcheck disable=SC2034
THUNDER_HELM_ARGS=(--set thunder.setup.admin.password=admin)

while IFS= read -r arg; do [[ -n "${arg}" ]] && AMP_HELM_ARGS+=("${arg}"); done < <(values_file_args wso2-agent-manager)
while IFS= read -r arg; do [[ -n "${arg}" ]] && OBSERVABILITY_HELM_ARGS+=("${arg}"); done < <(values_file_args wso2-amp-observability-extension)
while IFS= read -r arg; do [[ -n "${arg}" ]] && EVALUATION_HELM_ARGS+=("${arg}"); done < <(values_file_args wso2-amp-evaluation-extension)
while IFS= read -r arg; do [[ -n "${arg}" ]] && PLATFORM_RESOURCES_HELM_ARGS+=("${arg}"); done < <(values_file_args wso2-amp-platform-resources-extension)
while IFS= read -r arg; do [[ -n "${arg}" ]] && GATEWAY_HELM_ARGS+=("${arg}"); done < <(values_file_args wso2-amp-api-platform-gateway-extension)
while IFS= read -r arg; do [[ -n "${arg}" ]] && THUNDER_HELM_ARGS+=("${arg}"); done < <(values_file_args wso2-amp-thunder-extension)

export AMP_LOCAL_CHARTS_DIR="${REPO_ROOT}/deployments/helm-charts"

echo "🚀 Running the quick-start installer with local charts and images"
# Subshell: install.sh's exit calls stay contained; arrays and functions are inherited.
rc=0
( set +e; source "${SCRIPT_DIR}/install.sh" ) || rc=$?
exit "${rc}"
