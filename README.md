# Harness Trajectory Benchmark

This repository is implementing an execution-backend-agnostic agent benchmark.
The normative architecture is in
[`architecture-handoff.md`](architecture-handoff.md); the existing conversation
trajectory semantics are defined by [`trackedEvents.md`](trackedEvents.md).

The platform is delivered in numbered phases. Current phase status,
implementation tasks, and acceptance gates are maintained only in
[`tasks.md`](tasks.md).

Mock and local-process runs remain **ineligible for verified execution**.
The compatibility backend has no filesystem, DNS, boundary-flow, or plaintext
network sensor and cannot claim complete sandbox observation.

## Development

The project is a single Go module and requires Go 1.24 or newer. The Phase 0
schema check uses the pinned Python test dependency in `requirements-schema.txt`.

```sh
python3 -m pip install -r requirements-schema.txt
make check
make test-e2e
go run ./cmd/benchmark --help
```

`make test-e2e` builds the real CLI and control-plane binaries and runs the opt-in mock-data and restart subprocess gates. Regular `make check` does not run these opt-in tests. Fixtures and exported bundles are retained under ignored `dist/e2e/`. Browser behavior is outside this Make target; its acceptance status is recorded in `tasks.md`.

## Local development run

Start the API and web status view:

```sh
go run ./cmd/controlplane --listen 127.0.0.1:8080 --data-dir .benchmark
```

The server accepts loopback addresses only because authentication is not yet
implemented.

Create a JSON parameters file containing a strict compatibility-backend
configuration:

```json
{"backendConfig":{"type":"compat/local-process-v1","command":["/bin/sh","-c","printf hello"]}}
```

Then use the CLI with `BENCHMARK_API_URL=http://127.0.0.1:8080`:

```sh
go run ./cmd/benchmark run create --harness example --suite smoke --backend compat-local-process --parameters-file parameters.json
go run ./cmd/benchmark run start RUN_ID
go run ./cmd/benchmark run status RUN_ID
go run ./cmd/benchmark run follow RUN_ID --from-seq 0 --timeout 30s
go run ./cmd/benchmark trajectory export RUN_ID
go run ./cmd/benchmark evidence inspect RUN_ID
```

The web view is at `/web/`. `evidence verify RUN_ID` prints the recorded
verification report and exits with code 6 when the run is ineligible. The
local-process backend rejects `--verified` at creation. It executes the
configured program on the host in a dedicated working directory, not in a
security sandbox; use only trusted development workloads. Raw output and
process evidence stay under the data directory after completion. The
`evidence export RUN_ID` command writes the exact portable evidence bundle
published through `/v1`. Completed runs retain a sealed trajectory,
`evidence-manifest.json`, and `evidence-bundle.json` under `runs/RUN_ID/`.
The local Ed25519 key pair signs COSE Sign1 manifests for development integrity
checks, not production trust or verified-leaderboard admission.

Run catalog, lifecycle, evidence reports, and idempotency records persist
across restart. Interrupted runs reload explicitly as failed and ineligible
without duplicating terminal events. Offline validation requires an explicitly
trusted public key rather than accepting a key embedded in the bundle:

```sh
go run ./cmd/benchmark evidence validate --bundle evidence-bundle.json --public-key .benchmark/dev-signing-key.ed25519.pub --extract extracted-evidence
```

The deterministic mock-observation mode exercises real sequencing,
persistence, signing, export, and verification without establishing isolated
execution or real network capture. Delivery claims and browser acceptance
results are recorded in [`tasks.md`](tasks.md).

Repository conventions:

- `pkg/` contains contracts intended for integrations and backend plugins.
- `internal/` contains platform implementations and validators.
- `schemas/` contains pinned, versioned wire contracts for non-Go consumers.
- `testdata/` contains deterministic fixtures; tests must not rewrite golden
  files implicitly.
- Go files must pass `gofmt`, `go vet`, and `go test -race ./...`.
- Tests use the standard library, table-driven cases, and explicit fixtures.
- Contract changes require schema, fixture, and compatibility-test updates.

## Contract invariants

- There is one append-only `TrackedEvent` log with gap-free global sequence
  numbers assigned by a trusted appender.
- Raw sensor evidence is immutable and separately hash chained.
- Observation-backed events identify the exact raw evidence used to derive them.
- Verified profiles require destination-preserving plaintext capture and deny
  opaque traffic.
- Provider-native plaintext remains authoritative; OpenAI-compatible events are
  auditable normalized projections.
