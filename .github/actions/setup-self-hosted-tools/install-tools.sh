#!/usr/bin/env bash
#
# Idempotent tool bootstrap for the long-lived self-hosted runner VM.
#
# GitHub-hosted images ship docker, helm, kubectl, jq and gh preinstalled; a
# bare datacenter VM does not. This installs only what is missing (or pinned
# to a different version), so the first nightly on a fresh VM provisions the
# host and every later run is a near no-op — a handful of `command -v` calls.
#
# Binaries that don't need root land in a per-user bin dir appended to
# $GITHUB_PATH, so the provisioning survives across runs without touching
# /usr/local. Only the Docker engine, OS packages and sysctl tuning need root;
# when sudo isn't available the script fails with the exact one-off command a
# human has to run on the VM, instead of failing obscurely later.

set -euo pipefail

TOOLS="${TOOLS:-}"
BIN_DIR="${TOOL_BIN_DIR:-${HOME}/.local/share/amp-ci/bin}"

# Version pins. k3d and yq (and their sha256s) mirror
# .github/actions/amp-dev-stack so the nightly and the instrumentation matrix
# stand up byte-identical tooling. helm matches the version package-charts
# previously pulled via azure/setup-helm; kubectl matches amp-dev-stack.
K3D_VERSION="v5.8.3"
K3D_SHA256="dbaa79a76ace7f4ca230a1ff41dc7d8a5036a8ad0309e9c54f9bf3836dbe853e"
YQ_VERSION="v4.45.4"
YQ_SHA256="b96de04645707e14a12f52c37e6266832e03c29e95b9b139cddcae7314466e69"
HELM_VERSION="v3.14.0"
KUBECTL_VERSION="v1.31.0"
GH_VERSION="2.97.0"

log()  { echo "  $*"; }
ok()   { echo "✅ $*"; }
warn() { echo "::warning::$*"; }
die()  { echo "::error::$*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

wants() {
  case ",${TOOLS}," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

# True when the tool is installed AND its version output contains the pin, so
# bumping a pin above actually replaces a binary this action installed on an
# earlier run.
version_matches() {
  local want="$1"
  shift
  "$@" 2>/dev/null | grep -qF "${want}"
}

# ---------------------------------------------------------------------------
# Environment probing
# ---------------------------------------------------------------------------

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  *) die "Unsupported runner architecture '$(uname -m)'. The pinned k3d/yq checksums in this action cover linux/amd64 only; add the matching arm64 digests before running the nightly on an arm64 VM." ;;
esac

SUDO=""
if [ "$(id -u)" -eq 0 ]; then
  SUDO="env"
elif sudo -n true 2>/dev/null; then
  SUDO="sudo -n"
fi

need_root() {
  [ -n "${SUDO}" ] || die "'$1' is missing and installing it needs root, but this runner has no passwordless sudo. Provision it once on the VM, then re-run: $2"
}

mkdir -p "${BIN_DIR}"
export PATH="${BIN_DIR}:${PATH}"
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "${BIN_DIR}" >> "${GITHUB_PATH}"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

# ---------------------------------------------------------------------------
# Base OS packages
#
# Every job needs some of these: the workflow shells out to curl, jq and git;
# deployments/quick-start/install.sh hard-requires curl and lsof and aborts at
# its prerequisite check without them; deployments/scripts/*.sh use openssl and
# jq. Resolve by *command*, not package name, so a VM that already has them
# from another source is left alone.
# ---------------------------------------------------------------------------

install_base_packages() {
  declare -A pkg_for_cmd=(
    [curl]=curl [jq]=jq [git]=git [lsof]=lsof [openssl]=openssl
    [tar]=tar [unzip]=unzip [setfacl]=acl [envsubst]=gettext-base
  )

  local cmd missing=()
  for cmd in "${!pkg_for_cmd[@]}"; do
    have "${cmd}" || missing+=("${pkg_for_cmd[${cmd}]}")
  done

  if [ ${#missing[@]} -eq 0 ]; then
    ok "Base packages already present"
    return 0
  fi

  log "Missing base packages: ${missing[*]}"
  have apt-get || die "Base packages ${missing[*]} are missing and this runner has no apt-get. Install them with the VM's package manager and re-run."
  need_root "${missing[*]}" "apt-get update && apt-get install -y ca-certificates ${missing[*]}"
  ${SUDO} DEBIAN_FRONTEND=noninteractive apt-get update -qq
  ${SUDO} DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates "${missing[@]}"
  ok "Installed base packages: ${missing[*]}"
}

# ---------------------------------------------------------------------------
# Docker engine + buildx
# ---------------------------------------------------------------------------

install_docker() {
  if ! have docker; then
    need_root docker "curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh"
    log "Installing Docker Engine via the official get.docker.com script"
    curl -fsSL https://get.docker.com -o "${TMP}/get-docker.sh"
    ${SUDO} sh "${TMP}/get-docker.sh"
    ok "Docker Engine installed"
  fi

  # `docker info` failing means either the daemon is down (fresh install, or a
  # VM reboot with the unit not enabled) or the runner user cannot reach the
  # socket. Starting the daemon is harmless in both cases, so try it first.
  if ! docker info >/dev/null 2>&1 && [ -n "${SUDO}" ]; then
    if have systemctl; then
      ${SUDO} systemctl enable --now docker || true
    else
      ${SUDO} service docker start || true
    fi
  fi

  # Socket access for the non-root runner user. usermod makes it durable across
  # reboots, but a group change does NOT apply to the already-running runner
  # process — setfacl grants access to *this* session immediately.
  if ! docker info >/dev/null 2>&1; then
    [ -n "${SUDO}" ] || die "Docker is installed but not reachable as $(id -un), and there is no passwordless sudo to fix it. Run once on the VM: usermod -aG docker $(id -un) && systemctl restart docker, then restart the runner service."
    ${SUDO} usermod -aG docker "$(id -un)" || true
    have setfacl && ${SUDO} setfacl -m "u:$(id -un):rw" /var/run/docker.sock 2>/dev/null || true
    if ! docker info >/dev/null 2>&1; then
      warn "Falling back to chmod 0666 on /var/run/docker.sock. Acceptable on a dedicated CI VM, but it grants every local user root-equivalent access through Docker."
      ${SUDO} chmod 0666 /var/run/docker.sock || true
    fi
  fi

  docker info >/dev/null 2>&1 || die "Docker is installed but 'docker info' still fails. Check 'systemctl status docker' on the runner VM."
  ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?') reachable as $(id -un)"

  # build-images pushes a multi-arch manifest, which needs the buildx plugin.
  # get.docker.com ships docker-buildx-plugin; a pre-existing distro Docker
  # often does not.
  if ! docker buildx version >/dev/null 2>&1; then
    log "docker buildx plugin missing — installing docker-buildx-plugin"
    if have apt-get && [ -n "${SUDO}" ]; then
      ${SUDO} DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-buildx-plugin || true
    fi
    docker buildx version >/dev/null 2>&1 || die "docker buildx is unavailable and could not be installed. Install the docker-buildx-plugin package on the runner VM."
  fi
  ok "$(docker buildx version)"
}

# ---------------------------------------------------------------------------
# Pinned single-binary tools
# ---------------------------------------------------------------------------

install_k3d() {
  if ! version_matches "${K3D_VERSION}" k3d version; then
    curl -fsSL -o "${TMP}/k3d" "https://github.com/k3d-io/k3d/releases/download/${K3D_VERSION}/k3d-linux-${ARCH}"
    echo "${K3D_SHA256}  ${TMP}/k3d" | sha256sum -c -
    install -m 0755 "${TMP}/k3d" "${BIN_DIR}/k3d"
  fi
  ok "$(k3d version | head -1)"
}

install_yq() {
  if ! version_matches "${YQ_VERSION}" yq --version; then
    curl -fsSL -o "${TMP}/yq" "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${ARCH}"
    echo "${YQ_SHA256}  ${TMP}/yq" | sha256sum -c -
    install -m 0755 "${TMP}/yq" "${BIN_DIR}/yq"
  fi
  ok "$(yq --version)"
}

install_kubectl() {
  if ! version_matches "${KUBECTL_VERSION}" kubectl version --client; then
    # Verify against the officially published digest rather than a hardcoded
    # one, so bumping KUBECTL_VERSION needs no hash update here.
    curl -fsSL -o "${TMP}/kubectl" "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl"
    curl -fsSL -o "${TMP}/kubectl.sha256" "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl.sha256"
    echo "$(cat "${TMP}/kubectl.sha256")  ${TMP}/kubectl" | sha256sum -c -
    install -m 0755 "${TMP}/kubectl" "${BIN_DIR}/kubectl"
  fi
  ok "kubectl $(kubectl version --client 2>/dev/null | head -1)"
}

install_helm() {
  if ! version_matches "${HELM_VERSION}" helm version --short; then
    local tarball="helm-${HELM_VERSION}-linux-${ARCH}.tar.gz"
    curl -fsSL -o "${TMP}/${tarball}" "https://get.helm.sh/${tarball}"
    curl -fsSL -o "${TMP}/${tarball}.sha256sum" "https://get.helm.sh/${tarball}.sha256sum"
    (cd "${TMP}" && sha256sum -c "${tarball}.sha256sum")
    tar -xzf "${TMP}/${tarball}" -C "${TMP}"
    install -m 0755 "${TMP}/linux-${ARCH}/helm" "${BIN_DIR}/helm"
  fi
  ok "helm $(helm version --short)"
}

install_gh() {
  if ! version_matches "${GH_VERSION}" gh --version; then
    local tarball="gh_${GH_VERSION}_linux_${ARCH}.tar.gz"
    curl -fsSL -o "${TMP}/${tarball}" "https://github.com/cli/cli/releases/download/v${GH_VERSION}/${tarball}"
    curl -fsSL -o "${TMP}/checksums.txt" "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_checksums.txt"
    (cd "${TMP}" && grep " ${tarball}\$" checksums.txt | sha256sum -c -)
    tar -xzf "${TMP}/${tarball}" -C "${TMP}"
    install -m 0755 "${TMP}/gh_${GH_VERSION}_linux_${ARCH}/bin/gh" "${BIN_DIR}/gh"
  fi
  ok "$(gh --version | head -1)"
}

# ---------------------------------------------------------------------------
# Kernel tuning for k3s + OpenSearch
#
# GitHub-hosted images ship generous defaults; a stock Ubuntu VM does not, and
# the resulting failures are non-obvious:
#   * vm.max_map_count — the observability plane runs OpenSearch, whose
#     bootstrap check hard-fails below 262144 and the pod CrashLoopBackOffs
#     with no hint that a host sysctl is responsible.
#   * fs.inotify.* — k3s plus the controller set AMP installs blows past the
#     128-instance default; the symptom is "too many open files" surfacing in
#     an unrelated controller.
# Best-effort: warn rather than fail, so a locked-down VM still gets as far as
# it can and the log states exactly what to set.
# ---------------------------------------------------------------------------

tune_kernel() {
  declare -A want=(
    [vm.max_map_count]=262144
    [fs.inotify.max_user_instances]=1024
    [fs.inotify.max_user_watches]=1048576
  )
  local key current
  for key in "${!want[@]}"; do
    current="$(sysctl -n "${key}" 2>/dev/null || echo 0)"
    case "${current}" in
      ''|*[!0-9]*) current=0 ;;
    esac
    [ "${current}" -ge "${want[${key}]}" ] && continue

    if [ -z "${SUDO}" ]; then
      warn "${key} is ${current}, needs >= ${want[${key}]} for k3s/OpenSearch, and there is no sudo to raise it. Run on the VM: sysctl -w ${key}=${want[${key}]} and persist it in /etc/sysctl.d/99-amp-ci.conf."
      continue
    fi

    if ${SUDO} sysctl -w "${key}=${want[${key}]}" >/dev/null 2>&1; then
      log "sysctl ${key}: ${current} -> ${want[${key}]}"
      # Persist so a VM reboot doesn't silently regress the next nightly.
      echo "${key}=${want[${key}]}" | ${SUDO} tee -a /etc/sysctl.d/99-amp-ci.conf >/dev/null 2>&1 || true
    else
      warn "Could not raise ${key} (currently ${current}, want ${want[${key}]})."
    fi
  done
  ok "Kernel parameters checked"
}

# ---------------------------------------------------------------------------

echo "Requested tools: ${TOOLS:-<base only>}"
install_base_packages
wants docker  && install_docker
wants k3d     && install_k3d
wants yq      && install_yq
wants kubectl && install_kubectl
wants helm    && install_helm
wants gh      && install_gh
wants sysctl  && tune_kernel

echo ""
ok "Runner tooling ready (user bin: ${BIN_DIR})"
