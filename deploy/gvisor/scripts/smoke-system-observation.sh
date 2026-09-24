#!/usr/bin/env bash
# Verifies the runtime, persistent raw SecCheck collector, and runsc logs.
# This is deliberately not a complete-observation claim; it only proves that
# the VM is ready for the backend implementation.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this smoke test as root inside the Lima VM." >&2
  exit 2
fi

image=alpine:3.21
command=(/bin/sh -c 'touch /tmp/benchmark-gvisor-smoke && /bin/echo observed')
if [[ "${1:-}" == "--agent" ]]; then
  image=harness-trajectory-agent:codex-0.155.1
  command=(codex --version)
fi

socket=/run/benchmark-gvisor/seccheck.sock
capture_dir=/run/benchmark-gvisor/seccheck
container_name="benchmark-gvisor-smoke-$$"
container_id=""

cleanup() {
  docker rm --force "${container_name}" >/dev/null 2>&1 || true
  if [[ -n "${container_id}" ]]; then
    rm -f "${capture_dir}/${container_id}.frames" "${capture_dir}/${container_id}.done"
  fi
}
trap cleanup EXIT

systemctl is-active --quiet benchmark-gvisor-seccheck.service || {
  echo "Persistent SecCheck collector is not active" >&2
  exit 1
}
[[ -S "${socket}" ]] || { echo "Persistent SecCheck listener is not ready" >&2; exit 1; }

docker run --detach --name "${container_name}" --runtime runsc-benchmark "${image}" "${command[@]}"
container_id="$(docker inspect --format '{{.Id}}' "${container_name}")"
docker wait "${container_name}" >/dev/null

for _ in $(seq 1 50); do
  [[ -f "${capture_dir}/${container_id}.done" ]] && break
  sleep 0.1
done
[[ -s "${capture_dir}/${container_id}.frames" ]] || {
  echo "No raw SecCheck frames were persisted. Inspect the collector journal and validate pod-init.json against runsc trace metadata." >&2
  exit 1
}
[[ -f "${capture_dir}/${container_id}.done" ]] || {
  echo "SecCheck collector did not publish a drain status" >&2
  exit 1
}
jq -e '.frames > 0 and .oversize == 0 and .reportedDrops == 0' \
  "${capture_dir}/${container_id}.done" >/dev/null || {
  echo "SecCheck collector reported incomplete smoke capture" >&2
  exit 1
}

log_count="$(find /var/log/benchmark-gvisor -type f -name 'runsc.*.log' -mmin -2 | wc -l | tr -d ' ')"
[[ "${log_count}" -gt 0 ]] || {
  echo "No fresh runsc logs were written" >&2
  exit 1
}

echo "gVisor system-observation smoke test passed"
echo "SecCheck raw frame bytes: $(wc -c <"${capture_dir}/${container_id}.frames")"
echo "Fresh runsc logs: ${log_count}"
