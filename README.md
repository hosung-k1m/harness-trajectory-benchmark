# Harness Trajectory Benchmark

This repository implements the contract layer for an execution-backend-agnostic
agent benchmark. The normative architecture is in
[`architecture-handoff.md`](architecture-handoff.md); the existing conversation
trajectory semantics are defined by [`trackedEvents.md`](trackedEvents.md).

Phase 0 establishes the versioned Go contracts, schemas, fixtures, replay,
validation, evidence reconciliation, shared control-plane API, and agent-native
CLI. It intentionally does not run workloads or claim verified observation; the
first execution backend belongs to later phases.

## Development

The project is a single Go module and requires Go 1.24 or newer.

```sh
make check
go run ./cmd/benchmark --help
```

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
