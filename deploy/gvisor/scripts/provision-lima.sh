#!/usr/bin/env bash
# Provision the *Lima VM* as the trusted gVisor runtime and observation host.
# Run from macOS with:
#   limactl shell gvisor-dev sudo bash /Users/.../deploy/gvisor/scripts/provision-lima.sh
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
deploy_dir="$(cd -- "${script_dir}/.." && pwd)"
# shellcheck source=../versions.env
source "${deploy_dir}/versions.env"

if [[ "${EUID}" -ne 0 ]]; then
  echo "provision-lima.sh must run as root inside the Lima VM" >&2
  exit 2
fi

case "$(uname -m)" in
  aarch64|arm64) ;;
  *)
    echo "This pinned gVisor artifact is for arm64; got $(uname -m). Update deploy/gvisor/versions.env for this VM architecture." >&2
    exit 2
    ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --yes --no-install-recommends \
  build-essential ca-certificates clang curl docker.io git iproute2 jq python3 \
  tcpdump unzip util-linux zip zstd

for value in GVISOR_RELEASE_VERSION GVISOR_SOURCE_URL GVISOR_SOURCE_TAG GVISOR_SOURCE_COMMIT \
  SECCHECK_PATCH_SHA256 SECCHECK_BAZEL_VERSION SECCHECK_BAZEL_URL SECCHECK_BAZEL_SHA256 \
  MITMPROXY_IMAGE; do
  if [[ -z "${!value:-}" ]]; then
    echo "versions.env must define ${value}" >&2
    exit 2
  fi
done
if [[ ! "${GVISOR_SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || \
  [[ ! "${SECCHECK_PATCH_SHA256}" =~ ^[0-9a-f]{64}$ ]] || \
  [[ ! "${SECCHECK_BAZEL_SHA256}" =~ ^[0-9a-f]{64}$ ]] || \
  [[ ! "${MITMPROXY_IMAGE}" =~ ^mitmproxy/mitmproxy:[^@]+@sha256:[0-9a-f]{64}$ ]]; then
  echo "versions.env contains an invalid immutable source or checksum pin" >&2
  exit 2
fi

install -d -m 0755 /usr/local/bin
download_dir="$(mktemp -d)"
runtime_json=""
trap 'rm -rf "${download_dir}" "${runtime_json}"' EXIT
curl --fail --location --retry 3 --output "${download_dir}/gvisor.tar.zstd" "${GVISOR_TARBALL_URL}"
printf '%s  %s\n' "${GVISOR_TARBALL_SHA512}" "${download_dir}/gvisor.tar.zstd" | sha512sum --check --strict
tar --zstd --extract --file "${download_dir}/gvisor.tar.zstd" --directory /usr/local/bin

install -d -m 0750 /etc/benchmark-gvisor /var/log/benchmark-gvisor
install -m 0640 "${deploy_dir}/pod-init.json" /etc/benchmark-gvisor/pod-init.json
install -d -m 0755 /usr/local/libexec/benchmark-gvisor

printf '%s  %s\n' "${SECCHECK_PATCH_SHA256}" "${script_dir}/seccheck-raw.patch" | sha256sum --check --strict
git init --quiet "${download_dir}/gvisor-source"
git -C "${download_dir}/gvisor-source" remote add origin "${GVISOR_SOURCE_URL}"
git -C "${download_dir}/gvisor-source" fetch --quiet --depth 1 origin \
  "refs/tags/${GVISOR_SOURCE_TAG}:refs/tags/${GVISOR_SOURCE_TAG}"
source_commit="$(git -C "${download_dir}/gvisor-source" rev-parse "${GVISOR_SOURCE_TAG}^{}")"
if [[ "${source_commit}" != "${GVISOR_SOURCE_COMMIT}" ]]; then
  echo "gVisor tag ${GVISOR_SOURCE_TAG} resolved to ${source_commit}, expected ${GVISOR_SOURCE_COMMIT}" >&2
  exit 1
fi
git -C "${download_dir}/gvisor-source" checkout --quiet --detach "${GVISOR_SOURCE_COMMIT}"
if [[ "$(git -C "${download_dir}/gvisor-source" rev-parse HEAD)" != "${GVISOR_SOURCE_COMMIT}" ]]; then
  echo "gVisor source checkout did not resolve to the configured commit" >&2
  exit 1
fi
git -C "${download_dir}/gvisor-source" apply --check "${script_dir}/seccheck-raw.patch"
git -C "${download_dir}/gvisor-source" apply "${script_dir}/seccheck-raw.patch"

curl --fail --location --retry 3 --output "${download_dir}/bazel" "${SECCHECK_BAZEL_URL}"
printf '%s  %s\n' "${SECCHECK_BAZEL_SHA256}" "${download_dir}/bazel" | sha256sum --check --strict
chmod 0755 "${download_dir}/bazel"
if [[ "$("${download_dir}/bazel" --version)" != "bazel ${SECCHECK_BAZEL_VERSION}" ]]; then
  echo "downloaded Bazel does not match ${SECCHECK_BAZEL_VERSION}" >&2
  exit 1
fi
if [[ "$(<"${download_dir}/gvisor-source/.bazelversion")" != "${SECCHECK_BAZEL_VERSION}" ]]; then
  echo "gVisor source requires Bazel $(<"${download_dir}/gvisor-source/.bazelversion"), expected ${SECCHECK_BAZEL_VERSION}" >&2
  exit 1
fi
(
  cd "${download_dir}/gvisor-source"
  "${download_dir}/bazel" build -c opt //examples/seccheck:server_cc
)
install -m 0755 "${download_dir}/gvisor-source/bazel-bin/examples/seccheck/server_cc" \
  /usr/local/libexec/benchmark-gvisor/seccheck-raw
install -m 0755 "${script_dir}/runsc-benchmark" /usr/local/libexec/benchmark-gvisor/runsc-benchmark
install -m 0644 "${deploy_dir}/benchmark-gvisor-seccheck.service" \
  /etc/systemd/system/benchmark-gvisor-seccheck.service
install -d -m 0755 /etc/systemd/system/docker.service.d
cat >/etc/systemd/system/docker.service.d/benchmark-gvisor-seccheck.conf <<'EOF'
[Unit]
Requires=benchmark-gvisor-seccheck.service
After=benchmark-gvisor-seccheck.service
EOF

if ! getent group 10001 >/dev/null; then
  groupadd --gid 10001 benchwork
fi
if ! getent passwd 10001 >/dev/null; then
  useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin benchwork
fi

runtime_json="$(mktemp)"
cat >"${runtime_json}" <<'JSON'
{
  "runsc-benchmark": {
    "path": "/usr/local/libexec/benchmark-gvisor/runsc-benchmark",
    "runtimeArgs": [
      "--network=sandbox",
      "--directfs=false",
      "--debug",
      "--debug-log=/var/log/benchmark-gvisor/runsc.%ID%.%COMMAND%.log",
      "--strace",
      "--pod-init-config=/etc/benchmark-gvisor/pod-init.json"
    ]
  }
}
JSON

daemon_config=/etc/docker/daemon.json
if [[ -s "${daemon_config}" ]]; then
  jq --argjson runtimes "$(<"${runtime_json}")" \
    '.runtimes = ((.runtimes // {}) + $runtimes)' \
    "${daemon_config}" >"${daemon_config}.new"
else
  jq -n --argjson runtimes "$(<"${runtime_json}")" '{runtimes: $runtimes}' >"${daemon_config}.new"
fi
install -m 0644 "${daemon_config}.new" "${daemon_config}"
rm -f "${daemon_config}.new"

systemctl daemon-reload
systemctl enable --now benchmark-gvisor-seccheck.service
systemctl enable docker
systemctl restart docker

# A fresh `limactl shell` session picks up this group membership. Do not alter
# root's group set when the provisioner is invoked from an interactive root
# shell.
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  usermod --append --groups docker "${SUDO_USER}"
fi

if ! docker info --format '{{json .Runtimes}}' | jq -e 'has("runsc-benchmark")' >/dev/null; then
  echo "Docker did not register runsc-benchmark" >&2
  exit 1
fi
docker pull --platform linux/arm64 "${MITMPROXY_IMAGE}"
mitm_repo_digest="${MITMPROXY_IMAGE%%:*}@${MITMPROXY_IMAGE##*@}"
if [[ "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "${MITMPROXY_IMAGE}")" != "linux/arm64" ]] || \
  ! docker image inspect --format '{{json .RepoDigests}}' "${MITMPROXY_IMAGE}" | \
    jq -e --arg digest "${mitm_repo_digest}" 'index($digest) != null' >/dev/null; then
  echo "mitmproxy image does not match the pinned Linux/arm64 digest ${mitm_repo_digest}" >&2
  exit 1
fi
if ! systemctl is-active --quiet benchmark-gvisor-seccheck.service || [[ ! -S /run/benchmark-gvisor/seccheck.sock ]]; then
  echo "SecCheck collector did not become ready" >&2
  exit 1
fi

echo "Installed $(/usr/local/bin/runsc --version 2>/dev/null || /usr/local/bin/runsc version | head -n 1)"
echo "Docker runtime runsc-benchmark, the pinned mitmproxy image, and the raw SecCheck collector are ready. Run ${deploy_dir}/scripts/build-agent-image.sh next (with sudo if the current Lima shell has not refreshed group membership)."
