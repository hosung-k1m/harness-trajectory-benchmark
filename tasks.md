# Remaining implementation tasks

This plan starts from the working tree as inspected on 2026-09-21. The delivery
criteria come from [architecture-handoff.md](architecture-handoff.md), especially
Section 19, and the current limitations are recorded in [README.md](README.md).
Each checkbox is an incremental, reviewable change. Complete tasks in order
within a milestone; keep the CLI and web UI on the same `/v1` API. Run
`make check` for each code change and add the relevant failure tests before
claiming a verification capability.

**Phase 1 scope decision:** Finish the control-plane and evidence pipeline
with deterministic mock-data end-to-end tests. Real gVisor implementation and
runtime provisioning are Phase 2 work. Mock acquisition must remain explicitly
labelled and must never confer verified-execution eligibility.

**Success-criteria rule:** Phase 1 acceptance starts the real control-plane
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

## Historical audit before persistence/export and mock-data acceptance

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

**End-to-end success criteria:** Start the server in a fresh data directory;
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

**End-to-end success criteria:** On the development host, use a test-only
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

- [ ] **P2.1** Implement gVisor lifecycle with per-run cgroup, network
  namespace, veth pair, filesystem scope, and artifact scope.
- [ ] **P2.2** Ingest `runsc --strace` and runtime logs as best-effort raw system
  evidence, plus Netstack, host-veth, and backend-specific plaintext evidence.
  Reuse the shared appender, normalizers, verifier, and manifest format.
- [ ] **P2.3** Run the same benchmark under the local-process compatibility
  baseline and the gVisor backend, and compare both against the mock-data
  contract fixtures; document expected capability differences and keep
  debug-log-derived coverage marked best effort.

**End-to-end success criteria:** Run the deterministic workload on gVisor
through the public API. Compare its logical workload/model events and expected
artifacts against the mock-data contract fixtures, and compare
process/stdout/stderr behavior with the local-process compatibility baseline.
The gVisor bundle must replay and reconstruct captured plaintext byte-for-byte,
while its report marks debug-log system observation as best effort. Stopping
the gVisor run must release its cgroup, namespace, veth, and filesystem scope
while retaining sealed evidence. Do not infer real network-capture parity from
the local-process baseline.

## Milestone 4 — Structured gVisor observation (Phase 3)

- [ ] **P3.1** Replace debug-text parsing with structured Sentry records and
  stable process, file, pipe, socket, and flow identities.
- [ ] **P3.2** Instrument Netstack DNS, loopback, connections, packets, and byte
  counters. Transport records over a protected collector channel with explicit
  sequence, backpressure, drop, and shutdown accounting.
- [ ] **P3.3** Add fail-closed plaintext capture and reconciliation for each
  allowed protocol, plus synchronous process, file, and connection enforcement
  hooks. Prove the required event families are complete before upgrading the
  gVisor capability profile.

**End-to-end success criteria:** Exercise process creation, file access, DNS,
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

**End-to-end success criteria:** Run a harness that makes streaming calls to
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

**End-to-end success criteria:** Produce a clean verified-profile run, export
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

**End-to-end success criteria:** Run the same provider-and-tool workload on
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
