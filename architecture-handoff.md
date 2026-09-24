# Execution-Backend-Agnostic Agent Benchmark Architecture

Status: target architecture; implementation snapshot through Phase 2 (2026-09-23)

Normative trajectory contract: [`trackedEvents.md`](trackedEvents.md)

Initial execution backend: gVisor

Planned backends: Firecracker, Kata Containers, native containers, and other isolated runtimes

Implementation language: Go

## 1. Purpose

Build a public agent-harness benchmarking platform that can run arbitrary harnesses and model providers while producing a trustworthy, replayable account of each run.

The application is agent-native. Its primary automation surface is a Go CLI designed for use by coding agents, benchmark harnesses, scripts, and CI systems. A web UI provides a human-facing surface for configuring runs, monitoring execution, exploring trajectories, inspecting evidence, and comparing results. The CLI and web UI use the same versioned control-plane API and authorization model; neither has a private execution path.

The target platform must capture:

- the complete harness conversation trajectory defined by `trackedEvents.md`;
- backend-observed process, filesystem, IPC, resource, DNS, and network activity;
- the complete plaintext byte stream entering and leaving the sandbox, independent of the on-wire encryption scheme;
- workload stdout, stderr, runtime logs, guest or sandbox logs, and sensor health;
- model requests, responses, retries, and provider-reported usage;
- benchmark inputs, outputs, artifacts, resource use, and verifier results; and
- cryptographic evidence binding the harness, environment, policy, telemetry, trajectory, and result.

There is one normalized append-only run log: the **TrackedEvent log**. There is not a second canonical event format. Backend-specific sensors emit immutable raw evidence, versioned normalizers translate that evidence into additional `TrackedEvent` types, and one trusted appender assigns the final global sequence number.

Raw evidence remains separate from the TrackedEvent log so that normalization can be audited and replayed.

The current implementation is a development platform, not yet this complete
capture system. Its completed slices and the boundary between implemented and
planned behavior are summarized in [Section 4.2](#42-current-implementation).

## 2. Bounded claim

The platform should make this claim:

> Within the run's declared capability profile, every external system interaction mediated by the execution backend was observed by a measured sensor. Every raw observation was either normalized into the append-only TrackedEvent log or represented by an explicit, hash-linked batch event. Sensor loss, unsupported paths, and attempted bypasses are recorded in that same log and affect verification eligibility.

The target platform must not claim to record private in-memory computation or
every CPU instruction. Verified profiles will require plaintext completeness
for network traffic that crosses the sandbox boundary.

**Current boundary:** The local-process compatibility backend and the Phase 2
gVisor backend are both ineligible for verified status. The gVisor backend
captures best-effort raw observations and explicitly records known gaps, but
does not normalize backend observations into system `TrackedEvent`s or prove
complete plaintext capture. See [Section 4.2](#42-current-implementation) and
the acceptance record in [`tasks.md`](tasks.md).

"All network activity" means the complete plaintext content sent out of or received by the sandbox, together with connection and protocol metadata. Ciphertext alone does not satisfy this requirement. The mechanism that obtains plaintext may be transparent TLS interception that preserves the original destination, TLS key extraction and reconstruction, pre-encryption/post-decryption instrumentation, a trusted guest component, or another backend-specific method. A backend that cannot produce plaintext for a connection must deny that connection or mark the run ineligible for verification.

"System logs" includes more than application log files. It covers process lifecycle, filesystem operations, IPC, signals, resource measurements, workload stdout and stderr, backend/runtime audit output, guest or sandbox logs where applicable, policy decisions, and sensor-health records.

## 3. Design principles

1. **`trackedEvents.md` is the trajectory contract.** Existing harness event types and their semantics remain authoritative.
2. **One ordered run log.** Harness events, observed system events, plaintext network events, verifier events, and health events share one append-only sequence.
3. **Backends produce evidence, not private trajectory formats.** Backend adapters normalize native observations into the common TrackedEvent envelope.
4. **Go is the implementation language.** Runtime interfaces, schemas, collectors, normalizers, and verification tooling are implemented in Go.
5. **Raw evidence is immutable.** Every normalized observation points to the exact raw record or raw-record batch from which it was derived.
6. **Plaintext is mandatory at the sandbox boundary.** Ciphertext and packet metadata may corroborate transport, but they never substitute for captured plaintext.
7. **Network representation is backend-neutral.** Every backend emits the same ordered plaintext stream or datagram format regardless of how it acquired or decrypted the bytes.
8. **Observation and enforcement are separate capabilities.** A backend may observe an operation without being able to synchronously deny it.
9. **Coverage is evidence.** Capability declarations, active observation plans, health counters, gaps, and drops are part of the signed result.
10. **Intent is not action.** `tool/call` describes model or harness intent. Process, file, IPC, network, protocol-normalizer, and verifier events describe observed effects.
11. **Provider-reported usage wins.** Missing usage fields remain unavailable; estimates never silently replace provider data.
12. **Remote LLM calls use an OpenAI-compatible schema.** Provider-specific wire formats are normalized to one versioned OpenAI Chat Completions representation.
13. **The trusted appender owns order.** Sensors own only their per-source sequence. They never assign the global TrackedEvent `seq`.
14. **Leaderboard validity is stricter than run completion.** A completed harness run can be excluded from verified rankings when required evidence is missing.

## 4. System shape

The data path is:

```text
Benchmark control plane
  <- agent-native CLI
  <- web UI
  -> ExecutionBackend + RunSpec
  -> backend-native sensors --------------------+
  -> plaintext capture and protocol decoders ---+--> raw evidence collector
  -> harness trajectory adapter ----------------+          |
  -> trusted benchmark verifier ----------------+          v
                                                    versioned normalizers
                                                             |
                                                             v
                                                single TrackedEvent appender
                                                             |
                                    +------------------------+--------------------+
                                    v                        v                    v
                              tracked-events.jsonl      indexes/views       signed manifest
```

The raw evidence collector durably stores exact source frames before acknowledging them. Normalizers may operate online for live visibility and may be rerun offline for validation. The authoritative published log is sealed only after all required sources have stopped and the appender has drained their records.

## 4.1 Product interfaces

### Agent-native CLI

The CLI is the complete platform interface, not a thin convenience wrapper. Every operation required to create, execute, inspect, verify, export, and compare benchmark runs must be available without a browser.

CLI contract:

- non-interactive operation is supported for every command;
- inputs can be supplied through flags, files, stdin, and stable identifiers;
- machine output is available as versioned JSON or JSONL, with human-readable output as an optional presentation mode;
- stdout contains requested data and stderr contains diagnostics;
- stable exit codes distinguish validation, execution, policy, telemetry, verification, and infrastructure failures;
- commands are composable and avoid prompts when all required values were supplied;
- long-running commands support event streaming, resumable follow, cancellation, and timeout controls;
- mutating commands accept idempotency keys where retries could otherwise duplicate work;
- secrets are referenced through configured secret providers and are not exposed in arguments, output, or logs;
- local artifact and TrackedEvent exports preserve exact hashes and evidence references; and
- CLI version, API version, and schema compatibility are discoverable programmatically.

Initial command families:

```text
benchmark harness ...
benchmark suite ...
benchmark run create|start|stop|status|follow|list
benchmark trajectory get|stream|export
benchmark evidence inspect|verify|export
benchmark result show|compare
benchmark backend list|capabilities|health
benchmark schema show|validate
```

Agents should be able to discover command and schema contracts using `--help`, `schema show`, and structured capability output rather than scraping prose or terminal formatting.

### Web UI

The web UI is the primary human interaction surface. It provides:

- harness, benchmark, backend, and run configuration;
- live run state, logs, plaintext network activity, model exchanges, tool calls, and sensor health;
- trajectory timelines joining intent with observed system and network effects;
- evidence coverage, gaps, provenance, and verification status;
- token, latency, resource, and benchmark-result analysis;
- comparisons across harnesses, models, providers, backends, and runs; and
- artifact inspection and export.

The web UI consumes the same API and live event stream as the CLI. UI-specific state is limited to presentation preferences, saved views, and annotations. Run configuration, execution, evidence, and verification semantics live in the control plane.

### Shared control-plane API

The CLI and web UI depend on one versioned API that provides:

- declarative run creation from `RunSpec`;
- lifecycle commands with idempotent mutation semantics;
- streaming run status and TrackedEvents;
- paginated trajectory, evidence, artifact, and result queries;
- backend capability and health discovery;
- schema and API version negotiation; and
- consistent authentication, authorization, audit, and rate-limit behavior.

The web UI must not introduce operations that cannot be performed through the CLI and API. This keeps the platform automatable by agents and prevents browser-only benchmark workflows.

## 4.2 Current implementation

The implementation through Phase 2 has three completed slices:

- **Contracts and deterministic fixtures (Phase 0):** versioned Go contracts,
  pinned JSON Schemas, golden and negative fixtures, event replay and
  projections, plaintext stream assembly, raw-chain validation, and verified
  profile checks.
- **Durable control plane and mock-data acceptance (Phase 1):** a shared `/v1`
  API used by the CLI and `/web/`, persistent run and idempotency state, a
  single-writer TrackedEvent log, local-process execution, evidence signing and
  bundle export/validation, and test-only mock observations for end-to-end
  coverage. Mock evidence validates pipeline behavior; it does not establish
  real isolation or capture.
- **Best-effort gVisor capture (Phase 2):** `DispatchDriver` routes
  `gvisor-container` runs to the gVisor adapter. The adapter manages a
  per-run Docker container using the pinned `runsc-benchmark` runtime inside a
  Lima VM, with a run-scoped network and workspace. It retains runsc logs,
  SecCheck frames, stdout/stderr, resource samples, workspace snapshots,
  network configuration, bridge and host-veth packet captures, and available
  DNS and gateway artifacts as independently chained raw evidence. A signed
  raw-only bundle binds the retained artifacts, capture health, and run
  manifest. Collector gaps degrade the evidence while allowing the workload
  to complete, subject to execution failures.

The control plane still appends and seals run-lifecycle TrackedEvents for
gVisor runs, but the backend's system and network observations remain raw; the
Phase 2 bundle does not claim they were normalized into the event log. The
compatibility backend has process/output evidence but runs on the host and is
not a sandbox. The standalone `make codex-interactive` launcher is an
operational gVisor session with its own retained files; it is not a control
plane run or a signed benchmark evidence bundle.

The current evidence is useful for development and capture experiments, but it
does not meet the target verified profile. Known gaps include startup coverage
on the host veth, proxy bypass, unsupported protocols and opaque encryption,
incomplete DNS/gateway visibility, and the absence of structured gVisor
normalization and fail-closed capture. Phases 3–6 address those gaps and
additional backend, protocol, correlation, and admission work.
[`tasks.md`](tasks.md) remains the source of truth for milestone status and
acceptance evidence.

## 5. Contracts

### 5.1 Existing TrackedEvent envelope

The event envelope in `trackedEvents.md` is retained:

```go
type TrackedEvent struct {
	Seq             uint64          `json:"seq"`
	Time            int64           `json:"time"`
	Type            string          `json:"type"`
	Data            json.RawMessage `json:"data"`
	Ignorable       bool            `json:"ignorable,omitempty"`
	SourceEventSeqs []uint64        `json:"sourceEventSeqs,omitempty"`
	SurfaceOp       json.RawMessage `json:"surfaceOp,omitempty"`
}
```

`SurfaceOp` is validated as the existing JSON union: the string `"append"` or an object containing `{ "op": "replace", "start": ..., "end": ... }`. The Go package provides typed constructors and validation while preserving the established wire shape.

Contract rules:

- `seq` is a gap-free, strictly increasing integer assigned by the run's sole appender.
- `time` is Unix epoch milliseconds at append time, preserving the meaning defined in `trackedEvents.md`.
- Backend observation time is carried separately in `data.observation` because collection and normalization can be delayed.
- Existing core conversation events retain their current `data` shapes.
- New backend, system, network, protocol, benchmark, and health event types set `ignorable: true` so older conversation replayers can safely skip them.
- `sourceEventSeqs` refers only to earlier TrackedEvent sequence numbers. Raw sensor lineage belongs in `data.evidence`.
- `surfaceOp` is used only for conversation-surface construction and compaction. Observed system and network events do not alter the model surface.
- Once appended, an event is never rewritten. Corrections are new events that identify the superseded or corrected event.

### 5.2 Observation payload

Every event normalized from backend, plaintext-capture, protocol-decoder, runtime, or verifier evidence uses this common payload base:

```go
type ObservationData[T any] struct {
	RunID       string       `json:"runId"`
	Source      Source       `json:"source"`
	Observation Observation  `json:"observation"`
	Subject     *Subject     `json:"subject,omitempty"`
	Outcome     *Outcome     `json:"outcome,omitempty"`
	Correlation *Correlation `json:"correlation,omitempty"`
	Evidence    Evidence     `json:"evidence"`
	Details     T            `json:"details"`
}

type Source struct {
	SensorID      string `json:"sensorId"`
	SensorType    string `json:"sensorType"`
	Backend       string `json:"backend"`
	BackendVersion string `json:"backendVersion"`
	BootID        string `json:"bootId"`
	SourceSeq     uint64 `json:"sourceSeq"`
	TrustDomain   string `json:"trustDomain"`
}

type Observation struct {
	MonotonicNS *uint64    `json:"monotonicNs"`
	WallTime    *time.Time `json:"wallTime"`
	ClockID     string     `json:"clockId"`
	ReceivedTime time.Time `json:"receivedTime"`
}

type Subject struct {
	ProcessID        string `json:"processId,omitempty"`
	ParentProcessID  string `json:"parentProcessId,omitempty"`
	Executable       string `json:"executable,omitempty"`
	ExecutableSHA256 string `json:"executableSha256,omitempty"`
	ActorID          string `json:"actorId,omitempty"`
}

type Outcome struct {
	Result  string `json:"result"`
	Errno   *int   `json:"errno,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type Correlation struct {
	FlowID          string `json:"flowId,omitempty"`
	TLSSessionID    string `json:"tlsSessionId,omitempty"`
	HTTPRequestID   string `json:"httpRequestId,omitempty"`
	ModelExchangeID string `json:"modelExchangeId,omitempty"`
	MCPSessionID    string `json:"mcpSessionId,omitempty"`
	ToolCallID      string `json:"toolCallId,omitempty"`
	TraceID         string `json:"traceId,omitempty"`
}

type Evidence struct {
	RawRecordSHA256  string `json:"rawRecordSha256"`
	RawStreamID      string `json:"rawStreamId"`
	RawSourceSeqStart uint64 `json:"rawSourceSeqStart"`
	RawSourceSeqEnd  uint64 `json:"rawSourceSeqEnd"`
	NormalizerSHA256 string `json:"normalizerSha256"`
	NormalizerVersion string `json:"normalizerVersion"`
	ObservationLayer string `json:"observationLayer"`
	ObservationMethod string `json:"observationMethod"`
}
```

The source identity key `(sensorId, bootId, sourceSeq)` is used for ingestion idempotency. The event's `seq` remains the only global run order.

### 5.3 Stable logical identities

OS identifiers can be reused. Normalizers therefore assign stable run-scoped logical identities:

- `processId`;
- `fileId`;
- `pipeId`;
- `socketId`;
- `flowId`;
- `tlsSessionId`;
- `httpRequestId`;
- `modelExchangeId`;
- `mcpSessionId`; and
- `toolCallId`.

Native PIDs, file descriptors, inodes, ports, and provider request IDs remain available in event details, but are not the primary identity.

### 5.4 RawRecord

Every sensor emits a framed record before normalization:

```go
type RawRecord struct {
	RunID               string     `json:"runId"`
	SensorID            string     `json:"sensorId"`
	BootID              string     `json:"bootId"`
	SourceSeq           uint64     `json:"sourceSeq"`
	ObservedMonotonicNS *uint64    `json:"observedMonotonicNs"`
	ObservedWallTime    *time.Time `json:"observedWallTime"`
	RecordType          string     `json:"recordType"`
	Encoding            string     `json:"encoding"`
	Payload             []byte     `json:"payload"`
	PreviousRecordSHA256 string    `json:"previousRecordSha256"`
	RecordSHA256        string     `json:"recordSha256"`
}
```

Hashing uses exact framed bytes, not reserialized JSON. A sensor restart creates a new `bootId`, emits a restart event, and continues with a new source chain. Missing source sequence numbers must produce `sensor/gap` rather than being hidden.

### 5.5 Backend lifecycle

```go
type ExecutionBackend interface {
    Describe(context.Context) (CapabilityManifest, error)
    Prepare(context.Context, RunSpec, ObservationPlan) (RunHandle, error)
    Start(context.Context, RunHandle) (StartedRun, error)
    Wait(context.Context, RunHandle) (ExitStatus, error)
    Stop(context.Context, RunHandle, StopReason) error
    Snapshot(context.Context, RunHandle) (RunSnapshot, error)
    FinalizeEvidence(context.Context, RunHandle) (BackendEvidence, SensorHealth, error)
    Destroy(context.Context, RunHandle) error
}
```

`Prepare` must fail when the selected backend cannot satisfy a required observation or enforcement capability. `Destroy` occurs only after required telemetry is drained or the failure to drain has been recorded.

### 5.6 ObservationPlan

The control plane resolves benchmark requirements against the backend capability manifest before execution:

```go
type ObservationRequirement struct {
	EventFamily           string `json:"eventFamily"`
	MinimumObservation    string `json:"minimumObservation"`
	MinimumEnforcement    string `json:"minimumEnforcement"`
	Retention             string `json:"retention"`
	RequiredForVerifiedRun bool  `json:"requiredForVerifiedRun"`
}

type ObservationPlan struct {
	SchemaVersion      string                   `json:"schemaVersion"`
	Requirements       []ObservationRequirement `json:"requirements"`
	SensorConfigs      []json.RawMessage        `json:"sensorConfigs"`
	PlaintextRequired  bool                     `json:"plaintextRequired"`
	PreserveDestinations bool                   `json:"preserveDestinations"`
	OpaqueTrafficPolicy string                  `json:"opaqueTrafficPolicy"`
}
```

The resolved plan and its digest are appended near `run/start` and included in the signed run manifest.

For verified runs, `PlaintextRequired` and `PreserveDestinations` are always `true`, and `OpaqueTrafficPolicy` is always `deny`.

### 5.7 Backend-neutral plaintext network format

Every backend emits `network/plaintext` events with the same Go payload. This is the lossless network contract; HTTP, MCP, and model events are derived protocol projections.

```go
type NetworkPlaintext struct {
	Boundary     string           `json:"boundary"` // sandbox
	CapturePoint string           `json:"capturePoint"`
	ConnectionID string           `json:"connectionId"`
	StreamID     string           `json:"streamId"`
	Transport    string           `json:"transport"` // tcp, udp, quic, icmp, raw-ip
	Direction    string           `json:"direction"` // ingress or egress
	Sequence     uint64           `json:"sequence"`
	Offset       *uint64          `json:"offset,omitempty"`
	EndOfStream  bool             `json:"endOfStream,omitempty"`
	Source       NetworkEndpoint  `json:"source"`
	Destination  NetworkEndpoint  `json:"destination"`
	Protocol     ProtocolIdentity `json:"protocol"`
	Payload      CapturedBytes    `json:"payload"`
	Capture      PlaintextCapture `json:"capture"`
}

type NetworkEndpoint struct {
	IP       string `json:"ip,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

type ProtocolIdentity struct {
	Name      string `json:"name"`              // raw, dns, http, websocket, grpc, etc.
	Version   string `json:"version,omitempty"`
	MediaType string `json:"mediaType,omitempty"`
}

type CapturedBytes struct {
	Encoding    string         `json:"encoding"` // utf8 or base64
	Inline      string         `json:"inline,omitempty"`
	Artifact    *ArtifactSlice `json:"artifact,omitempty"`
	Length      uint64         `json:"length"`
	SHA256      string         `json:"sha256"`
}

type ArtifactSlice struct {
	ArtifactID string `json:"artifactId"`
	Offset     uint64 `json:"offset"`
	Length     uint64 `json:"length"`
}

type PlaintextCapture struct {
	Method                   string `json:"method"`
	Backend                  string `json:"backend"`
	OriginalSecurityProtocol string `json:"originalSecurityProtocol,omitempty"`
	KeyMaterialDigest        string `json:"keyMaterialDigest,omitempty"`
	Verified                 bool   `json:"verified"`
}
```

Contract rules:

- `Payload` contains plaintext only. Ciphertext is never substituted into this field.
- `direction` is always relative to the named `boundary`; the required boundary is `sandbox`.
- `capturePoint` identifies the measured component that obtained the plaintext.
- Stream chunks are ordered by `(boundary, connectionId, streamId, direction, sequence)` and reconstructed by `offset`.
- Datagram protocols use one event per datagram and omit `offset`.
- Inline and artifact-backed payloads are semantically identical; large payloads normally use immutable artifact slices.
- `length` and `sha256` cover the exact plaintext bytes before JSON encoding.
- The authoritative evidence contains the complete plaintext, including headers and bodies. Redaction is permitted only in a derived public projection, never in the captured source or its digest.
- Plaintext artifacts are encrypted at rest with a per-run data key and protected by evidence-access policy; the signed manifest binds the plaintext digest and encrypted artifact digest.
- Capture methods are extensible but initially include `tls-termination`, `session-key-reconstruction`, `pre-encryption-hook`, `post-decryption-hook`, `guest-plaintext-tap`, and `native-plaintext`.
- Every connection that crosses the sandbox boundary must reconcile to a complete sequence of plaintext events in both directions.
- TCP retransmission and packet fragmentation are transport details; the standard record contains the reassembled plaintext byte stream exactly once.
- On-wire sensors retain packet headers, flow identity, timing, and byte counts for completeness checks. Ciphertext payload is discarded after online reconciliation; it is neither the analysis record nor accepted as captured network content.
- If plaintext capture fails after a connection begins, the backend stops or denies the connection, appends `network/plaintext-failure`, and makes the run ineligible for verified admission.

### 5.8 OpenAI-compatible remote LLM format

All remote LLM calls are observed in their provider-native plaintext form and then converted to a versioned OpenAI-compatible Chat Completions projection. The initial schema identifier is `openai.chat-completions.v1`.

The platform does not replace, redirect, or configure the harness's LLM endpoint. The harness keeps its own destination hostname, URL, protocol, credentials, SDK, provider request shape, and provider response shape. Plaintext acquisition is transparent to endpoint selection. After capture, a provider protocol adapter decodes the native exchange and emits the standard OpenAI-compatible representation.

The normalized events are:

- `model/request`: an OpenAI-compatible chat-completion request containing `model`, `messages`, tools, tool choice, sampling parameters, stop conditions, response format, and streaming options;
- `model/stream-chunk`: one OpenAI-compatible `chat.completion.chunk` object for each normalized streaming delta;
- `model/response`: one OpenAI-compatible `chat.completion` object containing choices, assistant messages, tool calls, finish reasons, model identity, and usage when present; and
- `model/usage`: the authoritative disjoint usage projection defined later in this document.

```go
type OpenAICompatibleExchange struct {
	Schema          string          `json:"schema"`
	Provider        string          `json:"provider"`
	ProviderModel   string          `json:"providerModel"`
	Endpoint        string          `json:"endpoint"`
	RequestID       string          `json:"requestId,omitempty"`
	ModelExchangeID string          `json:"modelExchangeId"`
	Body            json.RawMessage `json:"body"`
	Extensions      json.RawMessage `json:"extensions,omitempty"`
}
```

`Body` must validate against the pinned `openai.chat-completions.v1` JSON Schema. `Extensions` carries provider fields that have no OpenAI-compatible equivalent, namespaced by provider. It cannot alter the meaning of standard fields.

Provider protocol adapters preserve two linked representations:

1. the exact provider-native plaintext request and response in `network/plaintext`; and
2. the normalized OpenAI-compatible `model/*` events.

This makes normalization auditable and prevents provider-specific information loss from being confused with the original network evidence. The schema is pinned and vendored in the repository; upstream API evolution requires a new local schema version rather than silently changing historical interpretation.

The pinned contract follows the official OpenAI Chat Completions request, `chat.completion` response, and `chat.completion.chunk` streaming object shapes: [OpenAI Chat API reference](https://developers.openai.com/api/reference/resources/chat).

## 6. Event vocabulary

### 6.1 Existing harness events remain canonical

Do not introduce parallel `agent.*` events for information already covered by `trackedEvents.md`:

| Meaning | Existing event |
|---|---|
| Turn lifecycle | `turn/start`, `turn/end` |
| Human or injected context | `user/message` |
| Model configuration | `request/header`, `request/context` |
| Model retry | `llm/retry` |
| Generation lifecycle | `step/start`, `assistant/chunk`, `assistant/message`, `step/end` |
| Tool intent and result | `tool/call`, `tool/result` |
| Context replacement | `compaction/start`, `compaction/summary`, `compaction/end` |
| Seed boundary | `session/end-seed` |

Harness-specific adapters may add narrowly scoped ignorable events, but must not duplicate authoritative core events.

### 6.2 Run and backend lifecycle

- `run/start`
- `run/observation-plan`
- `backend/prepared`
- `backend/started`
- `backend/stopped`
- `backend/snapshot`
- `run/finish`

### 6.3 Sensor health

- `sensor/start`
- `sensor/heartbeat`
- `sensor/stop`
- `sensor/restart`
- `sensor/gap`
- `sensor/drop`
- `sensor/saturation`
- `sensor/parse-failure`
- `sensor/clock-skew`
- `sensor/bypass-attempt`

Health events are first-class TrackedEvents. A separate summarized `SensorHealth` artifact is derived from them and signed for efficient validation.

### 6.4 Process, system, and resources

- `process/create`
- `process/exec`
- `process/exit`
- `process/signal`
- `process/credential-change`
- `resource/sample`
- `policy/decision`
- `system/log`
- `stdio/chunk`

`system/log` preserves facility, severity, unit or component, stream, structured fields, and message according to retention policy. `stdio/chunk` records workload stdout and stderr without pretending they are trusted system observations.

### 6.5 Filesystem

- `file/open`
- `file/read`
- `file/write`
- `file/close`
- `file/rename`
- `file/delete`
- `file/metadata-change`
- `file/executable-map`
- `file/snapshot-diff`

Metadata is recorded by default. Content, content hashes, and before/after snapshots follow the benchmark retention policy.

### 6.6 IPC

- `ipc/pipe-create`
- `ipc/read`
- `ipc/write`
- `ipc/unix-connect`
- `ipc/unix-accept`
- `ipc/shared-memory`

### 6.7 Network

- `dns/query`
- `dns/response`
- `network/socket-create`
- `network/bind`
- `network/listen`
- `network/connect`
- `network/accept`
- `network/flow-open`
- `network/flow-update`
- `network/flow-close`
- `network/plaintext`
- `network/plaintext-failure`
- `network/packet-batch`
- `network/route-decision`
- `tls/session`
- `http/request`
- `http/response`

The normalized log must represent every captured network record. Plaintext content uses `network/plaintext`; high-volume on-wire packet metadata may additionally use `network/packet-batch` events containing the source sequence range, packet count, byte count, time bounds, flow IDs, and digest of the retained packet metadata. Packet batching is transport corroboration and never replaces plaintext capture.

For verified runs, plaintext, packet, and flow collection must report zero unaccounted gaps. The plaintext byte count in each direction must reconcile with the backend's application-side or decrypted stream accounting.

### 6.8 Provider and MCP protocols

- `model/request`
- `model/stream-chunk`
- `model/response`
- `model/usage`
- `mcp/request`
- `mcp/response`
- `mcp/notification`
- `mcp/tool-call`
- `mcp/tool-result`

The `model/*` bodies use `openai.chat-completions.v1`. These events are derived from observed provider-native plaintext or trusted MCP supervision and complement rather than replace `request/*`, `assistant/*`, and `tool/*`. For example, `tool/call` proves that the model requested a tool, while `mcp/tool-call` proves that a correlated JSON-RPC call crossed the MCP boundary.

### 6.9 Benchmark and evidence

- `benchmark/start`
- `benchmark/finish`
- `verifier/start`
- `verifier/result`
- `artifact/created`
- `evidence/checkpoint`
- `evidence/sealed`

## 7. Network observation contract

Every backend must capture the complete plaintext entering and leaving the sandbox. The backend chooses how to obtain it, but emits only the shared `NetworkPlaintext` contract. A verified run cannot contain an opaque connection.

Every backend must provide three complementary layers.

### 7.1 Backend network sensor

The backend network sensor observes all workload network namespaces or virtual interfaces, including:

- socket creation, bind, listen, connect, accept, and close;
- allowed and denied connection attempts;
- DNS queries and responses through the controlled resolver;
- loopback traffic where the backend exposes it;
- external ingress and egress packet metadata as an independent completeness check;
- flow direction, protocol, endpoints, byte and packet counts, and lifecycle;
- owning process where the backend can prove attribution; and
- attempts to bypass plaintext capture or use an unobserved resolver or route.

The host boundary sensor independently checks traffic leaving the sandbox, VM, or container. The backend sensor provides process attribution; the boundary sensor proves that every crossing was seen. Packet evidence is reconciled with plaintext stream evidence. A connection, packet flow, or byte count without corresponding plaintext becomes `network/plaintext-failure` and invalidates verified admission.

### 7.2 Plaintext acquisition layer

Each backend implements one or more plaintext acquisition methods:

- transparently intercept and re-originate TLS or another secure transport while preserving the harness's original destination and provider protocol;
- capture session keys and reconstruct the plaintext stream from the wire transcript;
- instrument supported TLS or transport libraries before encryption and after decryption;
- capture plaintext inside a measured guest component before it reaches the virtual NIC;
- capture natively plaintext protocols directly; or
- combine these methods when different processes or protocols require different treatment.

The method is recorded on every `network/plaintext` event. The backend capability manifest lists supported protocols, libraries, and failure modes for each method.

Unknown encryption, certificate pinning, uninstrumented custom cryptography, unsupported QUIC, or any other opaque channel is fail-closed in a verified run. The backend must prevent the bytes from crossing the boundary unless it can produce their plaintext record. Development profiles may allow such traffic only by making the run explicitly unverified.

Secrets and session keys used for reconstruction stay in the trusted collection plane. They are not written into the TrackedEvent log. A digest may be recorded to bind the reconstruction without disclosing the key material.

### 7.3 Provider protocol observation and normalization

The harness calls its own remote LLM endpoint exactly as it would outside the benchmark. The platform must not replace the endpoint with an OpenAI-compatible facade or require provider-specific harness configuration.

After the backend obtains plaintext, a provider protocol observer:

- identifies the provider protocol from destination, HTTP path, headers, and body shape;
- parses provider-native HTTP/1.1, HTTP/2, streaming, WebSocket, or other supported frames;
- correlates native requests, responses, retries, errors, and latency;
- extracts provider-reported input, output, cache-read, cache-write, and reasoning usage;
- retains the exact provider-native plaintext in protected evidence;
- emits separately derived sanitized public projections when required;
- converts the native exchange into `openai.chat-completions.v1` `model/*` events; and
- emits explicit parse-failure, unsupported-protocol, and normalization-failure events.

Endpoint preservation is a verified invariant. The recorded destination hostname, IP, port, SNI or equivalent server name, and HTTP authority are compared with the harness-observed request. Transparent interception is permitted only when it preserves the intended remote endpoint and provider semantics. It may observe or decrypt the exchange, but it must not substitute a platform LLM endpoint or change the harness's provider request.

If transparent TLS interception is used, its private CA key remains outside the workload; the workload may receive a run-scoped public trust certificate. Other backends may obtain plaintext through session keys or pre-encryption/post-decryption hooks without changing trust configuration.

### 7.4 Plaintext completeness reconciliation

Before sealing a run, the verifier checks:

- every boundary flow maps to a plaintext connection or an explicitly denied attempt;
- each plaintext stream is gap-free in both directions;
- plaintext byte counts and hashes match the acquisition sensor's totals;
- the harness's original remote destination and provider-native request semantics were preserved;
- HTTP, MCP, and model projections cite the plaintext events from which they were decoded;
- every remote LLM exchange has a valid OpenAI-compatible normalized request and response or an explicit normalization failure; and
- there are no successful opaque connections.

Any failure makes the run unverified. Ciphertext capture cannot repair missing plaintext.

## 8. System observation contract

Every backend must expose or implement sensors for:

- process creation, exec, exit, signals, and credential changes;
- filesystem access and mutation;
- pipes, Unix sockets, and supported shared-memory IPC;
- CPU, memory, storage, process-count, and wall-clock resource use;
- workload stdout and stderr;
- sandbox, runtime, guest-kernel, audit, and policy logs available at that backend's trust boundary;
- policy allow and deny decisions; and
- sensor startup, shutdown, restart, loss, saturation, and parse failures.

Where a backend cannot observe an operation completely, `Prepare` rejects a verified profile that requires it. Development runs may proceed only with the downgrade represented in `run/observation-plan` and the final manifest.

Application-written logs are workload claims, not trusted evidence. Runtime or sensor logs are evidence only to the degree declared by their trust domain and capability.

## 9. Backend-specific monitoring

### 9.1 gVisor

Primary sensors:

- structured Sentry hooks for process, syscall, filesystem, signal, and IPC activity;
- Netstack hooks for sockets, DNS, loopback, connections, packets, and flows;
- host TC/eBPF or equivalent capture on the sandbox veth for independent boundary verification;
- transparent plaintext interception where possible, with supported pre-encryption/post-decryption hooks or session-key reconstruction for other allowed protocols; all methods preserve the harness-selected destination;
- controlled stdout and stderr sinks;
- runsc/Sentry/Gofer/runtime logs through a protected host collector;
- workspace snapshots before and after execution; and
- provider-native protocol observers and the shared OpenAI-compatible normalizer.

The first prototype may use `runsc --strace`, but the capability level for fields inferred from debug text is `best_effort`, not `complete`. Verified completeness requires stable structured hooks, explicit loss accounting, and plaintext reconciliation for every boundary flow.

### 9.2 Firecracker

Primary sensors:

- a measured guest collector using tracepoints/eBPF/audit or equivalent;
- guest process, filesystem, IPC, stdout, stderr, and system-log collection;
- a measured guest plaintext tap before encryption and after decryption, optionally supplemented by destination-preserving transparent interception;
- guest policy enforcement using BPF LSM or another measured mechanism;
- host TAP/TC capture for independent packet and flow verification;
- observed DNS and routes that preserve harness-selected destinations; and
- the same raw-record, normalizer, appender, evidence, and verifier contracts.

Guest collector health, plaintext stream totals, and the host TAP view are cross-checked. A missing guest collector or opaque TAP flow invalidates verified network coverage.

### 9.3 Kata Containers

Use the Firecracker pattern where Kata runs a VM: measured guest collector with a plaintext tap, host veth/TAP monitoring, observed DNS and routes, protected log channel, destination preservation, and shared contracts.

### 9.4 Native containers

Primary sensors:

- cgroup-aware eBPF tracepoints and LSM hooks for process, file, IPC, and socket activity;
- supported TLS-library hooks or session-key capture for pre-encryption and post-decryption bytes;
- namespace/veth TC capture for packet and flow verification;
- container stdout and stderr plus runtime and kernel audit logs;
- workspace snapshots; and
- observed DNS and routing plus transparent plaintext acquisition that preserves harness-selected endpoints.

Native containers generally have a weaker isolation boundary than microVM or gVisor backends. Their capability and trust manifest must preserve that distinction rather than presenting event-shape parity as security parity.

## 10. Correlation

Correlation produces new events or indexes; it never mutates source events. Sources are joined using descending evidence strength:

1. explicit trace, tool-call, MCP, HTTP, or provider request identifiers;
2. socket, flow, file descriptor, or pipe ownership;
3. process and child-process lineage;
4. content or artifact hashes; and
5. bounded temporal correlation.

Every inferred relationship records:

- the correlation method;
- confidence;
- source TrackedEvent sequence numbers;
- raw evidence IDs when relevant;
- timing distance for temporal joins; and
- correlator version and digest.

Low-confidence associations remain possibilities and are not promoted to causal facts.

## 11. Ordering and late records

The global `seq` defines durable replay order, not perfect physical simultaneity across clocks.

- Sensors preserve native order using `sourceSeq` and per-source hash chains.
- The appender assigns `seq` only after raw evidence is durable.
- `time` remains append time as required by `trackedEvents.md`.
- `data.observation.monotonicNs` and `wallTime` preserve source timing.
- Clock synchronization and skew estimates are recorded per sensor.
- A late record is appended at the tail; it is not inserted into earlier history.
- Projections may sort by observation time, but must retain `seq` and identify that they are views.
- Final sealing waits for required sources to stop and drain. A timeout produces explicit loss or incomplete-source events.

## 12. Token and cache accounting

Each physical provider request produces at most one authoritative `model/usage` event. Retries are separate physical requests and may share a logical model exchange ID.

```json
{
  "inputTokens": 1240,
  "outputTokens": 312,
  "cacheReadTokens": 800,
  "cacheWriteTokens": 100,
  "reasoningTokens": 55,
  "totalTokens": 1607,
  "quality": {
    "inputTokens": "provider_reported",
    "outputTokens": "provider_reported",
    "cacheReadTokens": "provider_reported",
    "cacheWriteTokens": "provider_reported",
    "reasoningTokens": "provider_reported",
    "totalTokens": "provider_reported"
  }
}
```

Allowed quality values are:

- `provider_reported`;
- `derived_from_provider_reported`;
- `harness_reported`;
- `client_estimated`; and
- `unavailable`.

The counters retain the disjoint semantics specified for `assistant/message` in `trackedEvents.md`. Missing values remain `null` and are never coerced to zero.

## 13. Capability and health manifests

Every backend publishes a signed `CapabilityManifest`. Each run resolves it into an actual `ObservationPlan` and final `SensorHealth` result.

Observation levels:

- `complete`;
- `conditional`;
- `best_effort`;
- `sampled`;
- `aggregated`; and
- `unsupported`.

Enforcement levels:

- `synchronous`;
- `eventual`;
- `audit_only`; and
- `unsupported`.

The health result includes:

- expected and observed source sequence ranges;
- gaps and duplicate records;
- kernel, guest, runtime, plaintext-capture, protocol-decoder, and appender drops;
- buffer saturation;
- parser and normalization failures;
- plaintext capture failures, stream gaps, and unreconciled boundary flows;
- unsupported protocol counts;
- content truncation or redaction;
- clock offset and skew estimates;
- attempted observation bypasses;
- source start, restart, drain, and stop status; and
- raw records not represented by normalized or batch events.

An event stream that looks valid is not sufficient. Verified eligibility depends on the declared capability plus actual run health.

## 14. Policy model

Policy is evaluated and enforced at the boundary that owns the operation:

| Policy | Enforcement point |
|---|---|
| Prompt, tool arguments, HTTP body | Observed and evaluated at the plaintext capture layer without changing the remote endpoint |
| Provider, hostname, IP, port, protocol | Backend network layer using the harness-selected destination |
| Process permitted to use network | Sentry, guest LSM, or container cgroup/LSM |
| Executable launch | Sentry, guest LSM, or host LSM |
| File access and mutation | Sentry, guest LSM, or host LSM |
| Resource limits | Host cgroup and backend limits |

Every decision appends a `policy/decision` event correlated to the attempted operation. Frequently executed checks use compiled or precomputed policy decisions where necessary; the policy artifact digest remains in every decision and in the run manifest.

## 15. Storage and cryptographic evidence

A sealed run has this logical layout:

```text
runs/<run-id>/
  run-spec.json
  observation-plan.json
  tracked-events.jsonl
  tracked-events.index
  raw/<sensor-id>/<boot-id>.frames
  artifacts/
  capability-manifest.json
  sensor-health.json
  evidence-manifest.json
  signature.json
```

Each sensor maintains an ordered raw-record hash chain:

```text
H0 = SHA-256(run-spec digest || observation-plan digest || sensor identity)
Hn = SHA-256(Hn-1 || exact raw record frame)
```

The appender also chains exact TrackedEvent frames. At completion:

1. stop and drain every required source;
2. append health and final lifecycle events;
3. close all raw source chains and the TrackedEvent chain;
4. verify that each raw source range is represented by normalized or batch events;
5. hash trajectory indexes, artifacts, snapshots, and verifier outputs;
6. bind backend, sensor, plaintext-capture, protocol-normalizer, policy, harness, benchmark, and schema digests;
7. compute a Merkle root over the retained artifacts and chain heads;
8. sign the evidence manifest with the platform key; and
9. attach host or TPM-backed attestation when available.

The public verifier must validate signatures, artifact hashes, source sequence continuity, raw-to-normalized coverage, normalizer identity, declared capabilities, actual health, and leaderboard eligibility without requiring provider credentials or unredacted content.

## 16. Failure semantics

Telemetry failure is never represented as ordinary success.

- If a required sensor fails before workload start, the backend does not start the workload.
- If a required sensor fails during execution, policy determines whether the workload is synchronously stopped or allowed to finish as an unverified run.
- A collector or appender backpressure condition must either stop the workload or produce an accounted drop; it must not silently discard evidence.
- Plaintext protocol parse failures preserve the raw plaintext evidence and append `sensor/parse-failure`.
- Normalizer failures preserve the raw record and append a failure event through a trusted fallback path.
- A crash-recovered active run receives an interrupted lifecycle event consistent with `turn/end` and run state.
- Sealing fails closed when required evidence cannot be reconciled.

## 17. Leaderboard admission

A run can enter a verified leaderboard only when:

- the harness artifact, benchmark inputs, backend, policies, and execution configuration are immutable and identified;
- the selected backend satisfied the required capability profile before start;
- every required sensor started, remained healthy, drained, and stopped cleanly;
- there are no unaccounted sequence gaps, drops, or raw records;
- every network byte entering or leaving the sandbox is represented as plaintext in the standard format;
- every boundary flow reconciles with a complete plaintext stream in both directions;
- no successful opaque connection occurred;
- endpoint-preservation checks prove that the harness contacted its configured remote provider rather than a substituted platform endpoint;
- every remote LLM exchange validates against the pinned OpenAI-compatible schema;
- provider usage coverage meets the benchmark profile;
- the verifier completed in its trusted environment;
- all retained artifacts match the evidence manifest; and
- the platform signature and any required host attestation validate.

Runs with weaker coverage remain useful for development under a clearly named evidence tier, but never appear equivalent to verified runs.

## 18. Repository boundaries

```text
cmd/
  benchmark/              # agent-native CLI
  controlplane/
  runner/
  collector/
  protocol-observer/
  verifier/

internal/
  schema/                 # Go structs plus generated JSON Schema
  api/                    # shared CLI and web control-plane API
  appender/               # sole global sequence allocator
  normalizer/
  correlation/
  evidence/
  policy/
  projection/

  backend/
    gvisor/
    firecracker/
    kata/
    container/

  sensor/
    gvisor_sentry/
    gvisor_netstack/
    guest_collector/
    linux_ebpf/
    host_network/
    plaintext/
    provider_protocol/
    mcp_supervisor/

  llmnormalizer/          # provider-native plaintext to OpenAI-compatible events

pkg/
  client/                 # Go client used by the CLI and integrations
  backend/                # public ExecutionBackend interface
  events/                 # public TrackedEvent and payload contracts

web/                      # human-facing UI using the shared API

schemas/
  control-api/
  tracked-events/
  openai-chat-completions-v1/
```

Use one Go module initially. Keep backend implementations under `internal` and expose only the contracts that external backend plugins actually need. JSON Schemas are generated or checked from the Go source of truth and committed for non-Go consumers and fixture validation.

## 19. Delivery tracking

This document defines the target architecture and contracts and records the
implemented system boundary in [Section 4.2](#42-current-implementation).
[`tasks.md`](tasks.md) remains the source of truth for phase status, task
completion, sequencing, dated acceptance evidence, and remaining gates. Update
the implementation snapshot when a phase materially changes the system shape;
do not duplicate detailed test logs or acceptance transcripts here.

## 20. Architectural decisions

Decisions established by this handoff:

1. The final append-only log is the TrackedEvent log defined by `trackedEvents.md`.
2. The earlier standalone canonical event envelope is removed.
3. Backend-native output is immutable raw evidence, not a competing public schema.
4. All normalized system, network, protocol, verifier, and health records extend the existing event vocabulary using slash-delimited types and `ignorable: true`.
5. One trusted appender owns global `seq`; sensor order is preserved separately.
6. Go is the implementation language for the platform and contracts.
7. The CLI is the complete agent-native automation surface and supports non-interactive structured operation.
8. The web UI is the human interaction surface for configuration, monitoring, exploration, and comparison.
9. The CLI and web UI use one versioned control-plane API; no benchmark capability is UI-only.
10. Every byte entering or leaving the sandbox must be captured as plaintext in the shared `NetworkPlaintext` format.
11. Ciphertext and packet metadata are corroborating evidence only and never satisfy network-content capture.
12. Plaintext acquisition varies by backend and may use termination, key reconstruction, instrumentation, or trusted guest capture.
13. Opaque traffic is denied in verified runs; a plaintext capture failure invalidates verification.
14. The harness keeps its own remote endpoint, SDK, credentials, and provider-native protocol; the platform does not substitute an OpenAI-compatible endpoint.
15. Provider protocol observers convert captured native requests, responses, and stream frames into pinned `openai.chat-completions.v1` events after capture.
16. Network coverage uses backend attribution plus an independent host boundary view, destination-preservation checks, and plaintext reconciliation.
17. Health and coverage failures are themselves events and can invalidate verification.
