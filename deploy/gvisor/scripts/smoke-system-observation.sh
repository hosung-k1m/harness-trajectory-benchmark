#!/usr/bin/env bash
# Verifies the runtime, startup-installed SecCheck session, and runsc logs.
# This is deliberately not the Milestone 3 evidence collector; it only proves
# that the VM is ready for the backend implementation.
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

state_dir="$(mktemp -d /var/tmp/benchmark-gvisor-smoke.XXXXXX)"
socket=/run/benchmark-gvisor/seccheck.sock
container_name="benchmark-gvisor-smoke-$$"
listener_pid=""

cleanup() {
  docker rm --force "${container_name}" >/dev/null 2>&1 || true
  [[ -n "${listener_pid}" ]] && kill "${listener_pid}" >/dev/null 2>&1 || true
  rm -f "${socket}"
  rm -rf "${state_dir}"
}
trap cleanup EXIT

rm -f "${socket}"
python3 - "${socket}" "${state_dir}/seccheck.raw" <<'PY' &
import os
import socket
import struct
import sys

path, output = sys.argv[1:]
# gVisor's remote SecCheck sink uses SOCK_SEQPACKET. Its message boundaries are
# part of the raw evidence format, so the production collector must retain them.
server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
server.bind(path)
os.chmod(path, 0o660)
server.listen(8)
server.settimeout(20)
with open(output, "wb") as stream:
    try:
        while True:
            connection, _ = server.accept()
            with connection:
                # Remote SecCheck requires a protobuf Handshake{version: 1}
                # before it makes the socket nonblocking and emits frames.
                if connection.recv(10240) != b"\x08\x01":
                    continue
                connection.sendall(b"\x08\x01")
                while True:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    # Keep the SOCK_SEQPACKET message boundary in this probe.
                    stream.write(struct.pack(">I", len(chunk)) + chunk)
                    stream.flush()
    except TimeoutError:
        pass
PY
listener_pid=$!

for _ in $(seq 1 50); do
  [[ -S "${socket}" ]] && break
  sleep 0.1
done
[[ -S "${socket}" ]] || { echo "SecCheck listener did not start" >&2; exit 1; }

docker run --detach --name "${container_name}" --runtime runsc-benchmark "${image}" "${command[@]}"
docker wait "${container_name}" >/dev/null

sleep 0.2
[[ -s "${state_dir}/seccheck.raw" ]] || {
  echo "No SecCheck bytes were received. Inspect /var/log/benchmark-gvisor and validate pod-init.json against runsc trace metadata." >&2
  exit 1
}

log_count="$(find /var/log/benchmark-gvisor -type f -name 'runsc.*.log' -mmin -2 | wc -l | tr -d ' ')"
[[ "${log_count}" -gt 0 ]] || {
  echo "No fresh runsc logs were written" >&2
  exit 1
}

echo "gVisor system-observation smoke test passed"
echo "SecCheck bytes: $(wc -c <"${state_dir}/seccheck.raw")"
echo "Fresh runsc logs: ${log_count}"
