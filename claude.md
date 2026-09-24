# Harness Trajectory Benchmark — Agent Guide

This guide is for coding agents working in this repository. Read
[README.md](README.md) for local setup,
[architecture.md](agentDocs/architecture.md) for system contracts,
[trackedEvents.md](agentDocs/trackedEvents.md) for conversation event
semantics, and [tasks.md](agentDocs/tasks.md) for delivery status and the
next acceptance check.

## Current state

The platform has a Go CLI and control-plane server sharing the versioned
`/v1` API. Run state, lifecycle TrackedEvents, raw evidence, and development
evidence bundles persist across restart. Mock observations exercise the
normalization and export pipeline. The compatibility backend runs trusted
processes on the host.

The `gvisor-container` backend runs workloads in a Lima-hosted gVisor
container. It currently retains best-effort SecCheck protobuf frames, runsc
logs, output, resource samples, workspace snapshots, packet captures,
network configuration, and a mitmproxy flow archive. Its system and network
observations remain raw; the canonical gVisor trajectory contains lifecycle
events only. The immediate work is to decode SecCheck and mitmproxy captures
into TrackedEvents and a useful trajectory view. Current backends reject
verified execution.

## Repository map

| Path | Responsibility |
| --- | --- |
| `cmd/benchmark`, `cmd/controlplane` | Non-interactive CLI and HTTP server. |
| `pkg/backend`, `pkg/events`, `pkg/client` | Public backend, event, and client contracts. |
| `internal/backend/compat`, `internal/backend/gvisor` | Current execution adapters and raw collection. |
| `internal/evidence`, `internal/bundle` | Raw records, artifacts, bundles, and integrity checks. |
| `internal/normalizer`, `internal/llmnormalizer` | Existing compatibility/mock mappings and provider projections. |
| `internal/appender`, `internal/eventlog`, `internal/replay` | Canonical event order, validation, and replay. |
| `internal/controlplane`, `internal/api` | Run orchestration, persistence, and shared `/v1` handlers. |
| `internal/projection`, `internal/profile`, `internal/verification` | Derived views, capability profiles, and verification logic. |
| `internal/plaintext`, `internal/openaivalidator` | Stream assembly and pinned model-wire validation. |
| `schemas/`, `testdata/golden/` | Versioned JSON contracts and deterministic fixtures. |
| `deploy/gvisor/`, `web/` | Lima runtime setup and the current web status view. |
| `agentDocs/` | Architecture, tasks, and event-contract documents. |

## Contracts to preserve

- One append-only TrackedEvent log has gap-free global `seq` values assigned
  only by the trusted appender. Sensors own source-local order. Observation
  time and append time are separate.
- Raw sensor records and artifacts remain immutable and separate from
  normalized events. An observed event cites the exact raw source or a
  bounded artifact item and its normalizer identity.
- `tool/call` and conversation events describe intent. Process, file,
  network, MCP, and verifier events describe observed effects. Correlation
  adds a labelled link; it does not rewrite source facts.
- Provider-native data remains the source of record. OpenAI-compatible
  `model/*` events are versioned projections. Missing provider usage stays
  missing.
- Complete plaintext and destination preservation are requirements for
  later verified profiles. A mitmproxy archive describes proxy-visible
  traffic; rendered text and packets cannot be treated as byte-exact
  plaintext for all sandbox traffic.
- The CLI and web UI use the same `/v1` API. Do not add a browser-only
  execution or evidence path.

For the next milestone, use the retained SecCheck protobuf frames and
`gateway-flows.mitm` archive as inputs. Treat runsc logs and rendered
gateway/DNS text as diagnostic views. Start with a representative retained
run and an evidence-linked timeline; integrate the proven mapping into live
run completion afterward. [tasks.md](agentDocs/tasks.md) has the ordered
work and acceptance checks.

## Development commands

The module declares Go 1.24 and currently uses the pinned `go-cose`
dependency. The schema check uses the Python packages pinned in
`requirements-schema.txt`.

```sh
python3 -m pip install -r requirements-schema.txt
make check          # formatting check, vet, race tests, schema validation
make test           # regular Go tests
make test-e2e       # opt-in real CLI/server subprocess gate
make build
go run ./cmd/benchmark --help
go run ./cmd/controlplane --listen 127.0.0.1:8080 --data-dir .benchmark
```

`make fmt`, `make fmt-check`, `make vet`, `make test-race`, and
`make schema-check` are available separately. `make codex-interactive`
uses the provisioned `gvisor-dev` Lima VM; this interactive capture is not a
control-plane benchmark run. See [the deployment guide](deploy/gvisor/README.md)
for provisioning and sensor details. `dist/` holds ignored local build and
test artifacts.

The CLI writes JSON/JSONL results to stdout and diagnostics to stderr. Its
exit codes are 0 success, 2 validation, 3 execution, 4 policy, 5 telemetry,
6 verification, and 7 infrastructure.

## Coding and testing

- Use idiomatic Go, `gofmt`, explicit error returns, and context-owned
  cleanup. Libraries must not call `os.Exit`, `log.Fatal`, or panic for
  ordinary errors; only `main` selects a process exit.
- Prefer the standard library and small concrete types. The existing
  third-party packages are pinned in `go.mod`; justify additions.
  Accept minimal interfaces at external boundaries when they improve reuse.
  Avoid `any`, hidden side effects, and interfaces created only for mocks.
- Write behavior-focused, table-driven tests before changing nontrivial
  logic. Use deterministic fixtures, explicit failure cases, and `t.Run`
  names. Do not rewrite `testdata/golden/` during tests.
- Keep transport handlers thin and validate input at the boundary. Keep
  backend-native and provider-native formats behind adapters rather than
  leaking them into domain logic.
- Update Go contracts, matching `schemas/`, fixtures, and compatibility
  tests together. Run `make check` for code changes and the relevant
  end-to-end gate when the execution path changes. A skipped gVisor test on
  an unsupported host is not a live runtime acceptance.
- Manage every goroutine and file descriptor with an explicit owner and
  termination path. Choose simple APIs and defaults; avoid setup sequences
  that force consumers to assemble internal components by hand.

These conventions support the architecture; use judgment when a concrete
trade-off calls for a different implementation.
