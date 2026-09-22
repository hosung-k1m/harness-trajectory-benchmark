#!/usr/bin/env bash
# Build the untrusted workload image inside the Lima VM's Docker daemon.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
deploy_dir="$(cd -- "${script_dir}/.." && pwd)"
# shellcheck source=../versions.env
source "${deploy_dir}/versions.env"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Build this image in the Lima VM, not on macOS." >&2
  exit 2
fi

docker_cmd=(docker)
if ! docker info >/dev/null 2>&1; then
  docker_cmd=(sudo docker)
fi

"${docker_cmd[@]}" build \
  --platform linux/arm64 \
  --build-arg "AGENT_NODE_IMAGE=${AGENT_NODE_IMAGE}" \
  --build-arg "CODEX_VERSION=${CODEX_VERSION}" \
  --tag harness-trajectory-agent:codex-${CODEX_VERSION} \
  --file "${deploy_dir}/Dockerfile.agent" \
  "${deploy_dir}"
