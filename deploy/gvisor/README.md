# Lima gVisor runtime setup

This directory provisions the Lima VM as Milestone 3's trusted runtime and
observation host. `runsc`, Docker, the SecCheck listener, packet capture, and
the later Go backend run in the VM. The Codex agent is a separate unprivileged
gVisor container. It receives neither the Docker socket nor collector paths.

```text
Lima VM (trusted host and collectors)
├── Docker daemon with runsc-benchmark
├── /run/benchmark-gvisor/seccheck.sock
├── /var/log/benchmark-gvisor/
└── gVisor agent: Codex CLI, workspace, narrowly scoped credentials
```

This deliberately is not Docker-in-Docker. A DinD host makes per-run cgroup,
network-namespace, and host-veth capture an inner-container concern. Directly
hosting `runsc` in the VM gives the Milestone 3 backend an independent view of
each run.

## Provision the existing Lima VM

The configured `gvisor-dev` instance is arm64, so build and run native
`linux/arm64` images. From macOS, run:

```sh
limactl shell gvisor-dev sudo bash \
  /Users/hosungkim/source/repos/harness-trajectory-benchmark/deploy/gvisor/scripts/provision-lima.sh
```

The provisioner installs Docker Engine plus the checksum-verified gVisor
artifact in `versions.env`, registers the `runsc-benchmark` Docker runtime, and
installs a startup SecCheck profile. It preserves existing Docker daemon
configuration while adding that runtime and adds the provisioning user to the
Docker group. The image-build script automatically falls back to `sudo docker`
when the current Lima session has not refreshed its group membership.

The static profile connects every sandbox to one VM-owned Unix socket. The
future Go collector must associate each connection using SecCheck container
context and write per-run raw sources, retaining the `SOCK_SEQPACKET` message
boundaries. The socket is pre-opened by `runsc` and is not exposed to the
workload.

The selected runtime flags intentionally keep gVisor's Netstack (`--network=sandbox`)
and disable DirectFS (`--directfs=false`) for the initial observation-focused
prototype. The debug and strace logs are corroborating best-effort data; raw
SecCheck protobuf frames are the primary system-observation source.

The committed profile is intentionally version-validated. The pinned arm64
gVisor release exposes process lifecycle and syscall points, but does not
currently expose a structured Sentry signal-delivery point; `sentry/task_exit`
is retained and signal coverage remains an explicit Milestone 3 limitation.

Validate the installed gVisor build before a workload run:

```sh
limactl shell gvisor-dev sudo bash \
  /Users/hosungkim/source/repos/harness-trajectory-benchmark/deploy/gvisor/scripts/validate-trace-profile.sh
```

## Build the Codex workload image

```sh
limactl shell gvisor-dev bash \
  /Users/hosungkim/source/repos/harness-trajectory-benchmark/deploy/gvisor/scripts/build-agent-image.sh
```

The image is deliberately credential-free. The harness must supply an
ephemeral `CODEX_API_KEY`, access token, or mounted state only at run time, and
must ensure no untrusted subprocess can read it. For a non-interactive harness
execution, use an explicit command such as:

```sh
docker run --rm --runtime runsc-benchmark \
  --mount type=bind,src=/run/benchmark-workspaces/RUN_ID,dst=/workspace \
  -e CODEX_API_KEY \
  harness-trajectory-agent:codex-0.155.1 \
  codex exec --sandbox workspace-write "perform the benchmark task"
```

Do not pass `/var/run/docker.sock`, the SecCheck socket, `/var/log`, or host
collector directories into this container. The Milestone 3 backend will create
the workspace, cgroup, per-run veth, DNS/gateway policy, and evidence paths;
the example only verifies the image/runtime interface.

## Smoke test

Before connecting the control plane, prove that the startup SecCheck session
and runtime logs work:

```sh
limactl shell gvisor-dev sudo bash \
  /Users/hosungkim/source/repos/harness-trajectory-benchmark/deploy/gvisor/scripts/smoke-system-observation.sh
```

This test starts a temporary VM-owned UDS listener, runs an `alpine` process
with `runsc-benchmark`, completes the SecCheck protocol handshake, and requires
both received SecCheck frames and fresh runtime logs. It is not the persistent
collector and does not claim packet, DNS, gateway, plaintext, or
complete-observation coverage.

After building the workload image, repeat it with `--agent` to run
`codex --version` under gVisor:

```sh
limactl shell gvisor-dev sudo bash \
  /Users/hosungkim/source/repos/harness-trajectory-benchmark/deploy/gvisor/scripts/smoke-system-observation.sh --agent
```

## Network collector contract for Milestone 3

For each run, the backend must:

1. Create a dedicated network namespace and veth pair in the Lima VM.
2. Start an unprivileged agent with `runsc-benchmark` in that namespace.
3. Capture the VM-side veth peer to a per-run pcapng file, including capture
   statistics and drops.
4. Snapshot addresses, routes, firewall state, and interface counters at start
   and stop.
5. Optionally route traffic through a VM-owned DNS resolver and TLS gateway.
   Packet capture is encrypted evidence for HTTPS; it is not plaintext capture.

Loopback never crosses the host-side veth. It remains observable only through
the structured gVisor sources until the Milestone 4 Netstack instrumentation is
implemented. Missing or dropped data remains explicit degraded health evidence,
as required by Milestone 3.
