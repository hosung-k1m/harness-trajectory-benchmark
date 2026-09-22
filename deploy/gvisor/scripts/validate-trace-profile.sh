#!/usr/bin/env bash
# Validate the committed trace-point names against the installed gVisor build.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
deploy_dir="$(cd -- "${script_dir}/.." && pwd)"

metadata="$(mktemp)"
trap 'rm -f "${metadata}"' EXIT
runsc trace metadata >"${metadata}"

jq -r '.trace_session.points[].name' "${deploy_dir}/pod-init.json" | while IFS= read -r point; do
  if ! grep -Fq "Name: ${point}," "${metadata}"; then
    echo "Installed runsc does not expose required trace point: ${point}" >&2
    exit 1
  fi
done

echo "SecCheck profile is compatible with $(runsc --version 2>/dev/null || runsc version | head -n 1)"
