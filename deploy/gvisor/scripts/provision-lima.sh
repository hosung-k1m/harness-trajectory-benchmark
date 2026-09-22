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
  ca-certificates curl docker.io iproute2 jq python3 tcpdump util-linux zstd

install -d -m 0755 /usr/local/bin
download_dir="$(mktemp -d)"
trap 'rm -rf "${download_dir}"' EXIT
curl --fail --location --retry 3 --output "${download_dir}/gvisor.tar.zstd" "${GVISOR_TARBALL_URL}"
printf '%s  %s\n' "${GVISOR_TARBALL_SHA512}" "${download_dir}/gvisor.tar.zstd" | sha512sum --check --strict
tar --zstd --extract --file "${download_dir}/gvisor.tar.zstd" --directory /usr/local/bin

install -d -m 0750 /etc/benchmark-gvisor /var/log/benchmark-gvisor /run/benchmark-gvisor
install -m 0640 "${deploy_dir}/pod-init.json" /etc/benchmark-gvisor/pod-init.json

runtime_json="$(mktemp)"
trap 'rm -rf "${download_dir}" "${runtime_json}"' EXIT
cat >"${runtime_json}" <<'JSON'
{
  "runsc-benchmark": {
    "path": "/usr/local/bin/runsc",
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

systemctl enable --now docker
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

echo "Installed $(/usr/local/bin/runsc --version 2>/dev/null || /usr/local/bin/runsc version | head -n 1)"
echo "Docker runtime runsc-benchmark is ready. Run ${deploy_dir}/scripts/build-agent-image.sh next (with sudo if the current Lima shell has not refreshed group membership)."
