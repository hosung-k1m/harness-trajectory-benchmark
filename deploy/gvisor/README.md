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

The provisioner installs Docker Engine plus the checksum-verified, date-pinned
gVisor artifact in `versions.env`, then builds the VM-owned raw SecCheck
collector with Bazel from the matching, immutable upstream release commit. It
verifies the upstream annotated tag, source commit, collector patch digest,
required Bazel version, and Bazel binary digest before installing the result.
The collector is a restartable systemd service that owns
`/run/benchmark-gvisor/seccheck.sock` and writes root-only, per-container
`<container-id>.frames` and `<container-id>.done` files below
`/run/benchmark-gvisor/seccheck`. Docker requires that service, and the
`runsc-benchmark` wrapper refuses a workload if its listener is not ready.

This is deliberately an availability gate for the configured collector, not a
claim of complete system observation: a service restart, malformed frame,
kernel/runtime loss, or an unsupported trace point is preserved as degraded
evidence by the backend. The provisioner preserves existing Docker daemon
configuration while adding that runtime and adds the provisioning user to the
Docker group. The image-build script automatically falls back to `sudo docker`
when the current Lima session has not refreshed its group membership.

The static profile connects every sandbox to one VM-owned Unix socket. The
patched upstream C++ collector requires the initial `container/start` frame,
validates its lower-case SHA-256 container ID, retains `SOCK_SEQPACKET` message
boundaries with a length prefix, and writes the corresponding raw source plus a
drain status file. The socket is pre-opened by `runsc` and is not exposed to
the workload.

The selected runtime flags intentionally keep gVisor's Netstack (`--network=sandbox`)
and disable DirectFS (`--directfs=false`) for the initial observation-focused
prototype. The debug and strace logs are corroborating best-effort data; raw
SecCheck protobuf frames are the primary system-observation source.

### Updating the collector pin

Treat updates to `versions.env` and `scripts/seccheck-raw.patch` as one
reviewed supply-chain change. Choose a dated gVisor release that exposes every
point in `pod-init.json`, set the matching release tag and peeled commit, update
the dated runtime URL and checksum, set the source commit/tag, record the
matching Bazel version and arm64 binary checksum, then regenerate the patch
against that exact commit. Provisioning fails instead of building a moving
branch or a collector whose source tag, commit, patch, or Bazel metadata does
not match.

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

## Interactive Codex CLI

With the VM provisioned and the Codex image built, add `CODEX_API_KEY=...` to
the repository's ignored `.env` and run `make codex-interactive` from a macOS
terminal. The launcher reads that entry, signs the CLI into API-key mode, and
opens its terminal UI. The key is passed through a private temporary env file
and removed on exit. The agent has a fresh writable workspace, an internal
Docker network with no direct Internet route, and a mitmproxy gateway with its
CA certificate. The workspace is retained with the session evidence; the
container's Codex state is removed on exit.

After exit, the launcher prints the evidence directory under
`~/benchmark-interactive/` in the Lima VM. `proxy/flows.mitm` contains captured
proxy flows; `codex-output.log` retains terminal output; `system/` contains raw
SecCheck frames, drain status, per-container runsc logs, and best-effort bridge
packet capture. Inspect it with `limactl shell gvisor-dev -- ls -la ~/benchmark-interactive/RUN_ID`.
This is a direct interactive runtime path and
does not create a signed control-plane evidence bundle. Proxy and system
capture have the same best-effort limitations described above. Raw logs and
flows can contain the API key or session content; the output directory is
private and should be handled as sensitive data.

## Smoke test

Before connecting the control plane, prove that the startup SecCheck session
and runtime logs work:

```sh
limactl shell gvisor-dev sudo bash \
  /Users/hosungkim/source/repos/harness-trajectory-benchmark/deploy/gvisor/scripts/smoke-system-observation.sh
```

This test requires the persistent VM-owned collector, runs an `alpine` process
with `runsc-benchmark`, and requires its raw `SOCK_SEQPACKET` frames, drain
status, and fresh runtime logs. It does not claim packet, DNS, gateway,
plaintext, or complete-observation coverage.

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

Provisioning pulls the digest-pinned Linux/arm64 mitmproxy image and verifies
its local repository digest before gateway runs use `--pull=never`. Gateway
readiness probes the HTTP CONNECT and DNS listeners before starting a workload.
The `gateway-flows.mitm` archive is the authoritative proxy capture;
`gateway-plaintext.txt` and `dns.log` are rendered views, not byte-exact wire
evidence. `dns-observation.json` reports the number of rendered DNS query lines
(including the readiness probe); zero lines alone do not degrade sensor health.

Loopback never crosses the host-side veth. It remains observable only through
the structured gVisor sources until the Milestone 4 Netstack instrumentation is
implemented. Missing or dropped data remains explicit degraded health evidence,
as required by Milestone 3.
