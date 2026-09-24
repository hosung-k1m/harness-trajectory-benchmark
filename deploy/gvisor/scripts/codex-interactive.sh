#!/usr/bin/env bash
# Run an interactive Codex session in the instrumented Lima gVisor runtime.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "${script_dir}/../../.." && pwd)"
source "${script_dir}/../versions.env"

if [[ "$(uname -s)" != Linux ]]; then
  echo "Run this script through limactl shell gvisor-dev." >&2
  exit 2
fi
if [[ ! -f "${repo_dir}/.env" ]]; then
  echo "Missing ${repo_dir}/.env (CODEX_API_KEY)." >&2
  exit 2
fi
if ! sudo systemctl is-active --quiet benchmark-gvisor-seccheck.service; then
  echo "The gVisor SecCheck collector is not running." >&2
  exit 1
fi

run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
output_root="${HTB_INTERACTIVE_OUTPUT_DIR:-${HOME}/benchmark-interactive}"
mkdir -p -m 0700 "${output_root}"
chmod 0700 "${output_root}"
output_dir="${output_root}/${run_id}"
mkdir -p -m 0700 "${output_dir}/system"
chmod 0700 "${output_dir}" "${output_dir}/system"
sudo install -d -m 0700 -o 10001 -g 10001 "${output_dir}/workspace"
key_file="$(mktemp)"
chmod 0600 "${key_file}"
python3 - "${repo_dir}/.env" "${key_file}" <<'PY'
import pathlib, sys
source, target = map(pathlib.Path, sys.argv[1:])
values = []
for line in source.read_text().splitlines():
    line = line.strip()
    if line.startswith('export '):
        line = line[7:].strip()
    if not line.startswith('CODEX_API_KEY='):
        continue
    value = line.split('=', 1)[1].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not value or '\n' in value or '\r' in value:
        sys.exit('CODEX_API_KEY is empty or invalid')
    values.append(value)
if len(values) != 1:
    sys.exit('Expected exactly one CODEX_API_KEY entry in .env')
target.write_text('OPENAI_API_KEY=' + values[0] + '\n')
PY

suffix="${run_id//[^a-zA-Z0-9]/}"
network="htb-interactive-${suffix}"
bridge="hib${suffix: -12}"
gateway="htb-proxy-${suffix}"
agent="htb-codex-${suffix}"
proxy_dir="${output_dir}/proxy"
mkdir -m 0700 "${proxy_dir}"
agent_id=""
capture_pid=""
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "${capture_pid}" ]]; then
    sudo kill -INT "${capture_pid}" 2>/dev/null || true
    wait "${capture_pid}" 2>/dev/null || true
  fi
  if [[ -n "${agent_id}" ]]; then
    sudo docker logs "${agent}" >"${output_dir}/codex-output.log" 2>&1 || true
    for i in {1..30}; do
      [[ -f "/run/benchmark-gvisor/seccheck/${agent_id}.done" ]] && break
      sleep 0.2
    done
    sudo cp "/run/benchmark-gvisor/seccheck/${agent_id}.frames" "${output_dir}/system/seccheck.frames" 2>/dev/null || true
    sudo cp "/run/benchmark-gvisor/seccheck/${agent_id}.done" "${output_dir}/system/seccheck.done" 2>/dev/null || true
    sudo find /var/log/benchmark-gvisor -maxdepth 1 -type f \
      -name "runsc.${agent_id}.*.log" -exec cp -t "${output_dir}/system" {} + 2>/dev/null || true
  fi
  sudo docker rm -f "${agent}" "${gateway}" >/dev/null 2>&1 || true
  sudo docker network rm "${network}" >/dev/null 2>&1 || true
  rm -f "${key_file}"
  sudo chown -R "$(id -u):$(id -g)" "${output_dir}" 2>/dev/null || true
  echo "Session evidence: ${output_dir}" >&2
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

sudo docker image inspect "harness-trajectory-agent:codex-${CODEX_VERSION}" >/dev/null
sudo docker image inspect "${MITMPROXY_IMAGE}" >/dev/null
sudo docker network create --internal -o "com.docker.network.bridge.name=${bridge}" "${network}" >/dev/null
sudo docker run --detach --pull=never --name "${gateway}" --network "${network}" \
  --mount "type=bind,src=${proxy_dir},dst=/home/mitmproxy/.mitmproxy" \
  "${MITMPROXY_IMAGE}" mitmdump --mode regular@8080 --mode dns@53 \
  --listen-host 0.0.0.0 --set confdir=/home/mitmproxy/.mitmproxy \
  -w /home/mitmproxy/.mitmproxy/flows.mitm >/dev/null
sudo docker network connect bridge "${gateway}"
gateway_ip="$(sudo docker inspect --format "{{(index .NetworkSettings.Networks \"${network}\").IPAddress}}" "${gateway}")"
for i in {1..100}; do
  [[ -s "${proxy_dir}/mitmproxy-ca-cert.pem" ]] && \
    sudo docker exec "${gateway}" python3 -c 'import socket; s=socket.create_connection(("127.0.0.1", 8080), 0.2); s.close()' >/dev/null 2>&1 && break
  sleep 0.1
done
if [[ ! -s "${proxy_dir}/mitmproxy-ca-cert.pem" ]]; then
  echo "mitmproxy did not create its CA certificate." >&2
  exit 1
fi
sudo tcpdump -i "${bridge}" -s 0 -U -w "${output_dir}/system/bridge.pcap" >"${output_dir}/system/tcpdump.log" 2>&1 &
capture_pid=$!
sleep 0.3
if ! kill -0 "${capture_pid}" 2>/dev/null; then
  echo "Packet capture did not start." >&2
  exit 1
fi

# The internal Docker network has no external route. The gateway is its only
# path to the Internet and is also connected to the VM's external bridge.
command=(/bin/sh -c 'printf %s "$OPENAI_API_KEY" | codex login --with-api-key >/dev/null && exec codex --sandbox workspace-write')
if (( $# > 0 )); then command=("$@"); fi
echo "Interactive Codex session; run evidence will be saved under ${output_dir}" >&2
set +e
sudo docker run --interactive --tty --pull=never --name "${agent}" \
  --runtime runsc-benchmark --network "${network}" \
  --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges \
  --workdir /workspace \
  --mount "type=bind,src=${output_dir}/workspace,dst=/workspace" \
  --mount "type=bind,src=${proxy_dir}/mitmproxy-ca-cert.pem,dst=/etc/benchmark/mitmproxy-ca-cert.pem,readonly" \
  --env-file "${key_file}" \
  --env "http_proxy=http://${gateway_ip}:8080" \
  --env "https_proxy=http://${gateway_ip}:8080" \
  --env "HTTP_PROXY=http://${gateway_ip}:8080" \
  --env "HTTPS_PROXY=http://${gateway_ip}:8080" \
  --env NODE_EXTRA_CA_CERTS=/etc/benchmark/mitmproxy-ca-cert.pem \
  --env CODEX_CA_CERTIFICATE=/etc/benchmark/mitmproxy-ca-cert.pem \
  --env SSL_CERT_FILE=/etc/benchmark/mitmproxy-ca-cert.pem \
  "harness-trajectory-agent:codex-${CODEX_VERSION}" "${command[@]}"
status=$?
set -e
agent_id="$(sudo docker inspect --format '{{.Id}}' "${agent}" 2>/dev/null || true)"
exit "${status}"
