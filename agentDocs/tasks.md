# Delivery status and next tasks

This file tracks delivery. [architecture.md](architecture.md)
defines the design; [trackedEvents.md](trackedEvents.md) defines the existing
conversation events. Status reviewed: 2026-09-23.

| Phase | Outcome | Status |
| --- | --- | --- |
| 0 | Contracts, schemas, deterministic fixtures | Complete |
| 1 | Durable control plane, evidence export, mock end-to-end gate | Complete |
| 2 | gVisor execution and best-effort raw capture | Complete |
| 3 | Parse captured system/network data into TrackedEvents and trajectory views | **Next** |
| 4 | Fill observation gaps and prove coverage | Planned |
| 5 | Provider/MCP semantics and intent-to-effect correlation | Planned |
| 6 | Independent verification, admission, and second backend | Planned |

## Completed foundation

- A shared `/v1` control plane serves the CLI and small web view. Run state,
  lifecycle events, and evidence persist across restart. The appender owns
  gap-free TrackedEvent sequence numbers. A test-only mock path exercises
  normalization, projections, export, and the API/CLI end-to-end flow.
- The gVisor backend executes run-scoped containers and retains SecCheck
  protobuf frames, runsc logs, stdout/stderr, resource samples, workspace
  snapshots, packet captures, network configuration, and mitmproxy's
  `gateway-flows.mitm` plus rendered gateway/DNS text. Raw sources and
  artifacts are retained with capture-health information.
- A live gVisor run through `/v1` passed the Phase 2 acceptance check on
  2026-09-23. A separate stop run cleaned up its resources. The captured
  packet drops and veth startup gap were reported. Previous Phase 0 and 1
  gates passed with deterministic fixtures and real CLI/server subprocesses.

The gVisor TrackedEvent log currently contains lifecycle events, **not parsed
SecCheck or proxy observations**. The SecCheck payloads are stored as opaque
protobuf frames. The mitmproxy archive is retained, but its rendered text is
only a preview. `internal/projection` counts existing events; it does not
build a navigable system/network trajectory. The existing compatibility and
mock normalizers do not decode the gVisor inputs.

## Now: Phase 3, first useful trajectory

The first outcome is a view of what happened in a representative gVisor run:
processes and file activity from SecCheck, HTTP/DNS exchanges seen by
mitmproxy, and direct links back to the capture. Work against retained run
evidence first; integration with live-run sealing and verified admission
follows after the event mapping and view are useful.

- [ ] **P3.1 Make a small capture corpus.** Keep representative SecCheck
  frames and a mitmproxy archive with a complete HTTP request/response,
  DNS activity, empty flows, and partial/malformed cases. Record the gVisor
  event schema and mitmproxy version used. Sanitize secrets without changing
  the structure of test cases.
- [ ] **P3.2 Decode SecCheck.** Parse the protobuf payloads of
  `seccheck/frame` records into typed observations. Start with process
  lifecycle, file operations, and socket activity actually present in the
  corpus. Preserve native timestamps and IDs. Treat unknown fields or event
  kinds explicitly; use runsc text for context, not inferred facts.
- [ ] **P3.3 Decode the mitmproxy archive.** Use a pinned reader/exporter for
  `gateway-flows.mitm`. Extract flow identity, endpoints, HTTP method/path,
  status, timestamps, headers, and captured request/response body bytes.
  Extract DNS facts where supported. Represent missing responses, upgrades,
  and unsupported protocols honestly. Do not treat `gateway-plaintext.txt`
  or `dns.log` as the source of record.
- [ ] **P3.4 Map observations to TrackedEvents.** Produce the existing
  `process/*`, `file/*`, `network/*`, `http/*`, and `dns/*` types where
  their meanings fit. Set observation time separately from append time;
  use stable run-scoped identities when supported by the source; attach the
  raw frame or archive-flow reference and decoder version. Only emit
  `network/plaintext` for exact bytes and ordering the capture actually
  preserves. Keep missing or uncertain fields missing or labelled uncertain.
- [ ] **P3.5 Build a readable trajectory view.** Show events in canonical
  sequence with observed time, source, subject/flow, concise details, and a
  path to the captured evidence. Support filtering by process, flow, type,
  and time. Adapt DeepSeek Harness's `packages/client/ui-trajectory` ledger,
  timeline, inspector, search, and virtual-row code for the web view; add
  observation and evidence-link rows through a `/v1` adapter. Pin the upstream
  revision and preserve its license notice. Start with a derived log/view for
  retained runs and expose the same data through `/v1` for CLI and web use
  once the shape is settled.
- [ ] **P3.6 Connect the proven mapping to run finalization.** After the
  offline path works, append normalized candidates during gVisor completion,
  then finalize the log and bundle. The current driver seals before it reads
  backend evidence, so this step changes that order. Preserve a readable
  trajectory if one decoder fails, with an explicit source error. Keep
  restarts and exports consistent.

**First acceptance check (P3.1–P3.5):** Run a known workload that opens a
file and makes an HTTP request through mitmproxy. From the retained capture,
show its process/file and HTTP events in one view, filter by process or flow,
and open the corresponding SecCheck frame or proxy flow. The expected events
and details match the workload and captured bytes. Empty and malformed
inputs produce clear results without invented events. This check is about
usefulness and correctness of the trajectory, not verified-run eligibility.

**Integration check (P3.6):** The same view is available for a completed run
through the CLI and web on the shared API and survives restart. Normalized
events have appender-assigned sequence numbers and source references. A
decoder failure is visible while the raw capture remains inspectable.

## Later work

### Phase 4: observation coverage

- [ ] Add structured gVisor/Netstack collection for DNS, loopback, socket
  lifecycle, and process/file/IPC activity missing from the current sensors.
  Improve startup coverage and account for drops and collector interruptions.
- [ ] Capture complete, destination-preserving plaintext for supported
  protocols and reconcile it with boundary flows. Define enforcement and
  incomplete-capture behavior before claiming complete observation.

### Phase 5: protocol meaning and correlation

- [ ] Decode provider-native requests, responses, streams, and reported usage
  into pinned OpenAI-compatible `model/*` events. Preserve native data and
  leave unreported usage unavailable. Complete Anthropic streaming support.
- [ ] Observe local and remote MCP traffic; link model/tool intent to process,
  file, IPC, DNS, flow, and HTTP effects. Record correlation strength and
  make the links navigable through `/v1`.

### Phase 6: verification and portability

- [ ] Build an independent verifier with a configured trust root that checks
  signatures, artifact and event integrity, raw-to-event lineage, actual
  coverage, and plaintext reconciliation before admission.
- [ ] Validate the logical event, bundle, and verification contracts on a
  second isolated backend while preserving its distinct trust limits.

## Change discipline

For contract changes, update Go types, matching `schemas/`, fixtures, and
compatibility tests together. Never rewrite golden fixtures during tests.
Run `make check` for code changes and the affected end-to-end gate.
