# Delivery status and implementation tasks

This file is the single source of truth for delivery status, phase scope,
implementation tasks, and acceptance gates. The stable system design and
contracts remain in [architecture-handoff.md](architecture-handoff.md); they do
not track delivery status. Each checkbox is an incremental, reviewable change.
Complete tasks in order within a milestone; keep the CLI and web UI on the same
`/v1` API. Run `make check` for each code change and add the relevant failure
tests before claiming a verification capability.

**Completed Phase 1 scope:** The control-plane and evidence pipeline was
validated with deterministic mock-data end-to-end tests. Real gVisor runtime
provisioning starts in Phase 2. Mock acquisition remains explicitly labelled
and never confers verified-execution eligibility.

**Phase 1 acceptance method:** The gate starts the real control-plane
binary for local-process lifecycle and restart checks, and a child-process
control-plane server with a test-only execution driver for mock observations.
Both use the production `/v1` handlers, durable store, appender, normalizers,
verifier, and signing code; tests drive the public CLI and compare API results.
Unit tests and mocked HTTP responses do not replace this subprocess gate.
Use an actual browser for web-only behavior. Phase 1 browser acceptance was
checked locally with the installed Chrome through DevTools, without adding
browser dependencies to the project. Later runtime-dependent
milestones require a supported host; unsupported skips never count as passes.
Fixtures must not depend on live provider availability or billing.

## Phase status

Status last reviewed: 2026-09-22.

| Phase | Scope | Status | Acceptance authority |
| --- | --- | --- | --- |
| Phase 0 | Contracts and deterministic fixtures | **Complete** | Phase 0 acceptance gate and historical audit below |
| Phase 1 | Durable control plane and mock-data end-to-end acceptance | **Complete** | Milestones 1 and 2 |
| Phase 2 | Best-effort raw gVisor system and network capture | **Active** | Milestone 3 |
| Phase 3 | Structured gVisor observation and complete capture profiles | **Planned** | Milestone 4 |
| Phase 4 | Provider protocols, MCP, and semantic correlation | **Planned** | Milestone 5 |
| Phase 5 | Public verification and admission policy | **Planned** | Milestone 6 |
| Phase 6 | Second backend validation | **Planned** | Milestone 7 |

A phase is complete only when every required task is checked and its acceptance
gate has passed. A later phase may be explored early, but that does not change
the recorded status of either phase.

## Implemented baseline

The checkmarks below mean the named code is present. Milestone acceptance is
assessed separately in the audit below.

- [x] Phase 0 contracts, pinned schemas, golden fixtures, replay, projections,
  plaintext assembly, raw-chain checks, and profile validation.
- [x] A development-only Phase 1 slice: durable single-writer trajectory
  appender, hash-chained local raw records, local-process execution, normalizer,
  shared API and CLI lifecycle, minimal `/web/` status view, and a development
  Ed25519-signed evidence manifest.
- [x] Local-process runs reject `verified`; `make check` passes on this baseline.

The local-process backend runs trusted workloads on the host. Its dedicated
working directory is not a sandbox. It has no filesystem, DNS, boundary-flow,
or network-plaintext sensor. Neither its manifest signature nor its current
`ineligible` report establishes a verified run.

## Historical audit before persistence/export and mock-data acceptance (2026-09-21)

This audit records the pre-fix state that motivated Milestones 1 and 2. Its
failed Phase 1 row is historical; the current authoritative status is the phase
table above and the checked acceptance work below.

| Scope | Result | Evidence and remaining gap |
| --- | --- | --- |
| Phase 0 contract and fixture exit criterion | **Verified for the stated Phase 0 exit criterion** | `TestPhase0GoldenAcceptance` sends the same golden log through replay, projection, and the Go verifier; plaintext reconstructs in both directions and model events pass the Go validator. `scripts/schema_check.py` now checks every golden event, its model bodies, committed positive and negative OpenAI fixtures, and positive and negative evidence and control API cases against the pinned Draft 2020-12 schemas. `make check` runs this in CI. Raw record chain and coverage validation have separate Go tests; the Phase 0 golden log itself has no raw records, so it does not establish raw-evidence verification for Phase 1. |
| Phase 1 development slice | **Verified for CLI/API execution; browser behavior unverified** | A live `controlplane` process and separate `benchmark` CLI created, started, followed, inspected, and exported a completed local-process trajectory. The `/web/` HTML returned successfully; no browser interaction test was run. Raw records and a signed manifest were retained. The run correctly reported `ineligible`, and `--verified` was rejected. The current in-process integrity check runs before `run/finish` is appended and the log is sealed, so that report does not cover the final trajectory. |
| Full Phase 1 exit criterion | **Not met** | The live test returned an unsupported error for evidence export and `not_found` for the completed run after server restart. The local-process backend has no isolated container, filesystem/DNS/boundary-flow/plaintext sensors, or observed-traffic provider normalization. The existing HTTP integration test uses `httptest` and does not establish the milestone's full-process end-to-end gate. |

Current Phase 1 scope is the mock-data gate above. Automated sealing, persistence, export, restart, idempotency, provider projection, and plaintext fault checks now pass; browser inspection, evidence downloads, and reload checks also pass. This does not establish real isolated execution.

`go test -count=1` for the relevant packages and `make check` both passed.
The live smoke test used a temporary data directory and did not alter fixtures.
At that historical audit, milestones 1–7 remained open. The current Phase 1
mock-data acceptance below is complete; later runtime milestones remain open.

- [x] **P0.1 Prove schema conformance.** Validate committed golden and negative
  fixtures against the committed tracked-event, evidence, control API, and
  OpenAI-compatible JSON Schemas in CI. Compare schema results with Go
  validators and resolve any disagreement before marking Phase 0 fully met.

**Phase 0 acceptance gate:** The same golden `tracked-events.jsonl` is accepted
by the Go conversation replayer, evidence verifier, analysis projection code,
and committed JSON Schemas. Its plaintext streams reconstruct byte-for-byte;
all remote LLM events validate against the pinned OpenAI-compatible schema;
negative fixtures fail for their expected reasons. The historical audit above
records the passing evidence for this gate.

## Milestone 1 — Make development runs durable and exportable

- [x] **P1.0 Verify the sealed trajectory.** Finish and seal the event log
  before calculating its integrity report and manifest, then bind the reported
  result to the final event-chain head. An added, removed, or changed terminal
  event must invalidate verification on replay.
- [x] **P1.1 Persist the control-plane catalog and idempotency state.** Store
  run specs, lifecycle state, verification report, and idempotency keys alongside
  each run. On startup, reload and validate sealed logs and manifests; identify
  interrupted unsealed runs explicitly. A restart must preserve `/v1/runs`,
  status, trajectory, and lifecycle replay behavior without duplicating events.
- [x] **P1.2 Export a complete evidence bundle.** Implement
  `/v1/runs/{id}/evidence/export` and the existing CLI command using a versioned
  bundle containing the trajectory, raw records, run spec, observation plan,
  capability and health documents, artifact digests, and signed manifest.
  Verify path safety, content hashes, and round-trip import from a separate
  directory. Remove the current explicit unsupported response.
- [x] **P1.3 Expose persisted evidence through both surfaces.** Show the
  verification status and evidence summary in `/web/` via `/v1`; let the CLI
  inspect and export the same records. A completed run remains inspectable
  after a server restart.
  Persistence/API/CLI checks and real-browser inspection, export, and reload checks pass.

**Acceptance gate:** Start the server in a fresh data directory;
create, start, and complete a local-process run through the CLI; inspect it in
`/web/`; then stop and restart the server. The same run, status, verification
report, and gap-free trajectory must be available through CLI, browser, and
`/v1`. Repeating a request with the same idempotency key must return the same
run or lifecycle result without adding events. Export its evidence, unpack it
in a separate directory, and validate every included hash and manifest
signature; modifying one byte must be detected. An interrupted run must reload
with an explicit recoverable or failed state and no duplicate sequence number.

## Milestone 2 — Phase 1 mock-data end-to-end gate

- [x] **P1.4 Add a test-only execution driver.** Feed deterministic mock
  observations through the existing RunDriver boundary in a child-process
  control-plane server. Do not add a production isolated backend. Mark mock
  capabilities and source trust domains explicitly; reject verified runs.
- [x] **P1.5 Exercise raw system and network evidence.** Independently chain
  mock process, file, DNS, plaintext, boundary-flow, and provider sources.
  Normalize records into `TrackedEvent` with exact raw references and complete
  source coverage. Global sequence numbers remain appender-owned.
- [x] **P1.6 Exercise full-duplex plaintext.** Retain mock HTTP wire bytes,
  endpoint identities, chunk sequences, byte offsets, and end-of-stream markers
  in both directions. Do not claim that mock capture proves TLS interception
  or destination-preserving acquisition on an isolated host.
- [x] **P1.7 Reconcile mock boundary accounting.** Derive mock boundary totals
  from the complete fixture bytes, independently of captured-chunk fault
  injection. A dropped final plaintext chunk and a successful opaque flow with
  no plaintext must each fail verification with a specific reason.
- [x] **P1.8 Exercise provider normalization.** Decode mock native HTTP bytes
  and normalize request, response, streaming-frame, and usage fixtures through
  `internal/llmnormalizer`. Validate pinned OpenAI-compatible projections;
  assert exact provider-reported usage and no fabricated usage when absent.
- [x] **P1.9 Complete the mock-data end-to-end gate.** Use real CLI subprocesses
  and `/v1` to create, start, follow, inspect, export, and validate runs. Check
  restart/idempotency, raw coverage, flow reconciliation, and separate-process
  bundle validation. Browser inspection and downloads are checked locally in Chrome.

**Acceptance gate:** On the development host, use a test-only
mock driver with the real control-plane HTTP handlers and durable evidence
pipeline. The CLI and API must agree on the run, gap-free trajectory, and
verification report, including after restart. Export and validate the signed
bundle in a separate process, extract it into a separate directory, replay
its trajectory, and detect a changed evidence byte. Clean and missing-usage
fixtures must pass integrity checks without claiming verified execution.
Dropped-plaintext and opaque-flow fixtures must retain their completed mock
workload result and evidence while failing verification with the expected
reason. Browser inspection, export, and reload behavior pass in a real Chrome session.

Real process isolation, host/veth collection, DNS bypass prevention, TLS
capture, and collector fault handling are runtime acceptance work for Phase 2
and later, not claims established by these synthetic fixtures.

## Milestone 3 — gVisor prototype (Phase 2)

**Objective:** Run benchmark workloads inside gVisor and retain a broad,
tamper-evident dump of the system and network activity visible to the
configured sensors. Collection is best effort. Missing, truncated, dropped, or
unsupported observations are recorded in capture health and do not fail the
workload.

Phase 2 produces a sealed raw capture bundle that can serve as input to later
normalization, correlation, and verification. It does not require a normalized
`TrackedEvent` trajectory, global cross-source ordering, semantic reconstruction,
complete plaintext recovery, fail-closed capture, or verified-run eligibility.

### Phase 2 observation layout

```text
                         host observation domain

  +------------------------- gVisor sandbox -------------------------+
  | agent process                                                  |
  |      +--> Sentry syscalls, processes, files, IPC, and sockets  |
  |      +--> stdout and stderr                                    |
  |      +--> Netstack loopback and external network activity      |
  +-------------|--------------------------------|------------------+
                |                                |
       SecCheck remote sink             AF_PACKET / per-run veth
       and runsc debug logs                       |
                |                        host packet capture
                |                        controlled DNS logs
                |                        optional trusted gateway
                +---------------+----------------+
                                |
                     append-only raw collectors
                                |
                  digests and capture health report
                                |
                    sealed raw evidence bundle
```

Sensors and collectors run outside the workload's control domain. Digests and
source hash chains make retained evidence tamper evident; they do not prove
that a sensor observed every operation.

### Phase 2 capture requirements

System and runtime capture includes:

- a SecCheck trace session installed during sandbox initialization with the
  remote protobuf sink and selected process, filesystem, signal, IPC, and
  socket context fields;
- `runsc --strace` plus runsc debug, Sentry, Gofer, and runtime logs as
  best-effort diagnostic sources even when equivalent SecCheck records exist;
- separate workload stdout and stderr byte streams;
- periodic cgroup and runtime resource snapshots; and
- workspace metadata and content snapshots before and after execution.

Disable DirectFS initially when practical so filesystem activity follows the
Gofer path. This expands the observable surface without claiming complete
per-read or per-write content capture.

Network capture includes:

- full packet bytes, direction, interface metadata, and capture timestamps on
  the host side of the per-run veth;
- network namespace configuration, addresses, routes, firewall rules, and
  interface counters at start and stop;
- queries and responses from the controlled DNS resolver when configured;
- socket and connection activity available from SecCheck or runsc logs; and
- request, response, and stream bytes available from the optional trusted
  gateway for supported protocols.

The host veth does not expose gVisor's internal loopback traffic, and packet
capture does not expose encrypted application plaintext. The capture manifest
records these limitations. Unsupported encryption, certificate pinning, QUIC,
custom protocols, proxy bypasses, and capture gaps degrade the record without
failing a Phase 2 workload.

When enabled, the gateway keeps its private CA key on the host and may inject a
run-scoped public trust certificate. It preserves the intended destination and
stores exact captured bytes as protected raw evidence. Redaction applies only
to derived exports or views, never to authoritative bytes used for evidence
digests.

### Phase 2 evidence and failure semantics

Every collector preserves exact source records before interpretation and adds
collector-owned run ID, sensor ID, boot ID, per-source receipt sequence,
available monotonic and wall-clock times, encoding, payload, previous digest,
and current digest. Receipt sequence orders one source only and is never
presented as a global execution order.

The capture manifest records gVisor and collector versions and executable
digests, OCI configuration, effective runsc flags, enabled SecCheck points,
network and gateway configuration, source start and stop state, record and byte
counts, chain heads, file digests, drops, retries, disconnects, parse errors,
truncation, drain state, and available clock information. Existing evidence
signing may sign the manifest after collection drains. A valid signature proves
integrity of retained evidence, not completeness of observation.

Collector failure creates health evidence and a degraded capture status. The
workload continues unless execution itself can no longer proceed. Teardown
drains available collectors, records incomplete drains, seals received
evidence, and removes run-scoped resources.

- [ ] **P2.1** Implement gVisor lifecycle with per-run cgroup, network
  namespace, veth pair, filesystem scope, and artifact scope.
- [ ] **P2.2** Capture `runsc --strace`, runtime logs, SecCheck protobuf frames,
  stdout, stderr, resource snapshots, and before-and-after filesystem evidence
  as separate best-effort raw sources.
- [ ] **P2.3** Capture full packets on the host side of the per-run veth along
  with network configuration, counters, controlled DNS logs, and optional
  trusted-gateway output for supported protocols.
- [ ] **P2.4** Seal exact raw source bytes using per-source receipt sequences,
  hash chains, artifact digests, a capture manifest, and explicit health
  metadata. Sensor loss degrades the capture but does not fail the workload.
- [ ] **P2.5** Run the same deterministic workload under the local-process
  compatibility baseline and gVisor; compare workload results and artifacts,
  and document the capture surfaces and known gaps.

**Acceptance gate:** Run the deterministic workload on gVisor through the
public API. Retain stdout, stderr, runsc and available SecCheck records,
host-veth packets, network configuration, available DNS and gateway logs,
filesystem snapshots, and capture health in a tamper-evident raw bundle.
Changing a retained artifact must invalidate its digest or signature. Missing,
dropped, truncated, or unsupported observations remain visible as degraded
health and do not fail the workload. Stopping the gVisor run must release its
cgroup, namespace, veth, and filesystem scope while retaining sealed evidence.
Phase 2 does not produce or require a normalized `TrackedEvent` trajectory.

## Milestone 4 — Structured gVisor observation (Phase 3)

- [ ] **P3.1** Normalize the raw SecCheck stream into structured Sentry records
  with stable process, file, pipe, socket, and flow identities; retain debug
  text as corroborating best-effort evidence.
- [ ] **P3.2** Instrument Netstack DNS, loopback, connections, packets, and byte
  counters. Transport records over a protected collector channel with explicit
  sequence, backpressure, drop, and shutdown accounting.
- [ ] **P3.3** Add fail-closed plaintext capture and reconciliation for each
  allowed protocol, plus synchronous process, file, and connection enforcement
  hooks. Prove the required event families are complete before upgrading the
  gVisor capability profile.

**Acceptance gate:** Exercise process creation, file access, DNS,
loopback, allowed external connections, and blocked connections inside gVisor.
The exported bundle must link each resulting event to structured raw evidence
with stable identities and complete source ranges. For every allowed protocol,
captured plaintext must reconstruct exactly and reconcile with host boundary
counts. Kill the collector, saturate its channel, and attempt opaque traffic in
separate runs; each must fail closed or record a health/coverage failure that
prevents complete-observation status. Only a clean run may advertise the
verified profile's required event-family coverage.

## Milestone 5 — Provider protocols and correlation (Phase 4)

- [ ] **P4.1** Complete provider-native decoders and adapters for supported
  request, response, streaming, tool-call, finish-reason, and usage shapes.
  In particular, the current Anthropic chunk normalizer rejects streaming;
  support it with stateful assembly and explicit provenance.
- [ ] **P4.2** Add trusted local MCP stdio supervision and remote MCP HTTP
  observation, with raw and normalized evidence tied to tool intent and effects.
- [ ] **P4.3** Correlate model/tool intent to processes, files, IPC, DNS, flows,
  HTTP exchanges, and verifier effects. Record correlation strength and raw
  provenance without changing source facts. Add per-actor, provider, model,
  call, and tool projections and navigation through `/v1` for CLI and web.

**Acceptance gate:** Run a harness that makes streaming calls to
each supported provider fixture, invokes both stdio and HTTP MCP tools, and
causes process, file, and network effects. Starting from a tool call in the
CLI and browser, an analyst must be able to follow correlation links to the
effects and exact raw records, then navigate back. Exported provider-native
bytes and OpenAI-compatible projections must agree; reported usage must match
the fixture, and absent usage must remain absent. An ambiguous effect must
carry a weaker correlation label rather than a fabricated causal link.

## Milestone 6 — Public verification and admission (Phase 5)

- [ ] **P5.1** Sign and validate capability, observation-plan, health, and run
  evidence documents against a configured trust root and key-rotation policy.
  The existing local development key remains development-only.
- [ ] **P5.2** Build a standalone verifier that consumes an exported bundle,
  checks signatures, artifact hashes, raw and event chains, source coverage,
  lineage, plaintext reconstruction, boundary reconciliation, and profile
  eligibility, and emits a reproducible reasoned report. Set
  `verifiedEligible` only after all checks pass.
- [ ] **P5.3** Define evidence tiers and enforce verified-profile admission in
  results/leaderboard paths while retaining the benchmark result for ineligible
  runs. Test forged workload logs, direct egress, alternate DNS, certificate
  pinning, QUIC/custom encryption, missing TLS keys, stream gaps, sensor
  termination, buffer overflow, clock skew, and collector interruption.

**Acceptance gate:** Produce a clean verified-profile run, export
its bundle, and have the standalone verifier check it in a fresh process using
the configured public trust root. The resulting report must admit the run and
the result/leaderboard API must show its verified tier. For each adversarial
case listed above, execute or alter a full run and reverify its exported
bundle: admission must fail with a specific reason, while the completed
benchmark result remains accessible. A forged signature, changed artifact,
missing raw record, or development-key signature must fail even when the API
previously reported success. Reverification of an unchanged bundle must yield
the same decision and evidence hashes.

## Milestone 7 — Second backend validation (Phase 6)

- [ ] **P6.1** Implement Firecracker lifecycle with guest system and plaintext
  sensors and independent host TAP monitoring; declare its true capabilities.
- [ ] **P6.2** Run equivalent workloads on Firecracker and gVisor. Require the
  same logical `TrackedEvent` contract, byte-for-byte `network/plaintext`
  representation, bundle format, and standalone verification workflow while
  preserving backend-specific acquisition and capability differences.

**Acceptance gate:** Run the same provider-and-tool workload on
both backends through the CLI, export both bundles, and verify them with the
same standalone verifier and trust policy. Their logical event families,
provider projections, artifacts, and reconstructed plaintext bytes must match
the fixture; each report must truthfully describe its backend-specific sensor
and capability evidence. Inject one guest-sensor loss and one host-boundary
loss on Firecracker. Both must fail admission, and VM teardown must leave no
live run resources while preserving the evidence for audit.

## Change discipline

For every contract change, update the Go types, matching `schemas/` files,
golden fixtures, and compatibility tests together. Do not rewrite golden files
implicitly during tests. Keep raw evidence immutable, assign global sequence
numbers only in the trusted appender, and never infer provider usage when it
was not reported.
