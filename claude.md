# Harness Trajectory Benchmark - Agent Guide

This document provides architectural context, repository conventions, and developer guidelines for AI coding agents working on the `harness-trajectory-benchmark` codebase.

---

## 1. Overview & Purpose

`harness-trajectory-benchmark` is an execution-backend-agnostic benchmarking platform designed to run arbitrary agent harnesses and LLM providers while producing an auditable, replayable, and cryptographically verifiable account of each run.

The platform is **agent-native**: its primary automation interface is a non-interactive Go CLI intended for use by coding agents, benchmark harnesses, scripts, and CI systems.

### Core Documentation
- [`architecture-handoff.md`](architecture-handoff.md): The normative architecture specification for the platform.
- [`trackedEvents.md`](trackedEvents.md): Normative trajectory contract specifying all event types, data schemas, and lifecycle rules.
- [`README.md`](README.md): Quickstart and repository conventions.

---

## 2. Core Architectural Principles & Invariants

1. **One Ordered Run Log (`TrackedEvent`)**:
   - There is only one append-only run log with strictly increasing, gap-free sequence numbers (`seq: 1, 2, 3...`) assigned exclusively by a trusted appender.
   - Sensors and normalizers never assign the global `seq`.
2. **Raw Evidence is Immutable & Separate**:
   - Raw sensor records (network streams, syscalls, process traces, sensor health) are stored separately and independently hash-chained.
   - Every normalized `TrackedEvent` links back to the exact raw evidence record ID or hash from which it was derived.
3. **Plaintext Completeness at Sandbox Boundary**:
   - Every external network interaction must be captured in plaintext (e.g., transparent TLS interception, key extraction, pre/post-crypto tapping).
   - Opaque ciphertext or unobservable paths disqualify a run from verified status.
4. **Provider-Reported Usage is Authoritative**:
   - Token usage and billing metrics must reflect what providers report directly. Missing usage fields remain missing; estimates must never silently substitute for provider data.
5. **OpenAI-Compatible Wire Schema for Remote LLMs**:
   - Provider-specific wire formats are normalized to versioned OpenAI Chat Completions representations (`schemas/openai-chat-completions-v1/`).
6. **Intent vs. Action**:
   - Events like `tool/call` describe model or harness *intent*.
   - System events (process, filesystem, network, verifier) describe observed *effects*.
7. **Unified Control-Plane API**:
   - The agent-native CLI and any web UI share the exact same versioned HTTP control-plane API (`/v1`). Neither has private backchannels.

---

## 3. Repository Structure

```text
.
├── architecture-handoff.md   # Normative architectural design document
├── trackedEvents.md          # Trajectory event definitions & semantics
├── README.md                 # Project overview and quick start
├── Makefile                  # Build and test automation
├── go.mod                    # Single Go module (Go 1.24+, zero external dependencies)
├── cmd/
│   └── benchmark/            # Agent-native control-plane CLI binary
├── pkg/                      # Public contracts for integrations and backends
│   ├── backend/              # Execution backend interfaces & capability contracts
│   ├── client/               # Go SDK client for the control-plane API
│   └── events/               # Core TrackedEvent models and envelope validation
├── internal/                 # Platform implementation, normalizers, and validators
│   ├── api/                  # Control-plane HTTP API server & endpoints
│   ├── eventlog/             # Sequence validation, gap detection, monotonicity checks
│   ├── evidence/             # Raw sensor evidence handling & run evidence manifests
│   ├── openaivalidator/      # Validator for OpenAI chat completion formats
│   ├── plaintext/            # Plaintext stream assembler & reassembly
│   ├── profile/              # Capability profiles & verification eligibility
│   ├── projection/           # Trajectory projections and analysis
│   ├── replay/               # Deterministic event log replayer
│   └── verification/         # Verification engine, audit checks, golden verifiers
├── schemas/                  # Pinned, versioned JSON Schema wire contracts
│   ├── control-api/          # Control-plane API request/response schemas
│   ├── evidence/             # Raw record & manifest schemas
│   ├── openai-chat-completions-v1/ # OpenAI wire schemas & fixtures
│   └── tracked-events/       # TrackedEvent v1 JSON schema
└── testdata/
    └── golden/               # Deterministic golden test fixtures (do NOT edit implicitly)
```

---

## 4. Development Workflow & Commands

The project uses standard Go tooling with Go 1.24+.

### Essential Commands

```bash
# Run all quality checks (formatting check, vet, race-enabled tests)
make check

# Run tests
make test

# Run tests with race detection (mandatory before committing)
make test-race

# Format code according to Go standards
make fmt

# Verify code formatting without making changes
make fmt-check

# Run static analysis
make vet

# Build all packages
make build

# Run the CLI
go run ./cmd/benchmark --help
go run ./cmd/benchmark --version
```

### CLI Conventions & Exit Codes
The CLI (`cmd/benchmark`) is non-interactive and uses deterministic exit codes:
- `0`: Success (`exitOK`)
- `2`: Validation failure (`exitValidation`)
- `3`: Execution failure (`exitExecution`)
- `4`: Policy violation (`exitPolicy`)
- `5`: Telemetry / sensor failure (`exitTelemetry`)
- `6`: Verification failure (`exitVerification`)
- `7`: Infrastructure failure (`exitInfrastructure`)

Machine output is emitted to `stdout` as JSON/JSONL, while diagnostics and errors are printed to `stderr`.

---

## 5. Coding & Testing Standards

- **Standard Library First**: Zero external dependencies unless explicitly justified and approved.
- **Strict Formatting**: All Go code must pass `gofmt` without warnings.
- **Race Detection**: All tests must pass cleanly under `go test -race ./...`.
- **Table-Driven Tests**: Write table-driven tests with explicit test cases and descriptive subtest names using `t.Run()`.
- **Fixture Determinism**: Never mutate files in `testdata/` or golden fixtures implicitly during test runs.
- **Contract & Schema Synchronization**: If a contract or event model changes in `pkg/` or `internal/`, corresponding JSON schemas under `schemas/` and golden fixtures under `testdata/` must be updated and validated.

---

## 6. Go Coding Conventions

All coding in Go will follow these conventions:

### 1. Thou Shalt Be Boring

* **Embrace Idiomatic Conformity:** Go relies heavily on community consensus, automated formatting (`gofmt`), and standard patterns. Writing "Go-like" code means opting for the standard approach over stylish or intricate implementations.
* **Avoid Magic and Hidden Magic:** Avoid features that introduce implicit behavior, such as `init()` functions, package imports with side effects, or struct embedding used purely to inherit methods invisibly. Explicit code is far easier to audit and maintain.
* **The "You Don't Want to Do That" Signal:** If a task feels frustrating or overly complex in Go, it is usually language-level feedback that your architectural approach is flawed. Instead of pulling in heavy third-party abstractions to bypass it, simplify the design.

### 2. Thou Shalt Test First

* **Enforce Clean Architecture Early:** Writing test cases before writing application logic forces you to address dependencies immediately. If a function is hard to test because it makes network calls or writes to the file system, you are forced to redesign it using dependency injection (e.g., passing an `io.Writer` or standard interface).
* **Decouple Business Logic from Delivery:** By designing for testability upfront, logic stays detached from transport layers (like HTTP handlers or CLI interfaces). HTTP handlers end up serving purely as thin wrappers that extract parameters, execute business functions, and format responses.

### 3. Thou Shalt Test Behaviours, Not Functions

* **Test Inputs and Outputs, Not Execution Paths:** Rather than attempting to mock heavy external systems (like remote APIs or databases), split complex functions into isolated, predictable sub-tasks.
* **Pure Logic Is Easy to Validate:** Focus on verifying specific behavior—such as whether a function builds an API URL correctly or maps a SQL result set into a Go struct. These can be tested in isolation using pure Go values without invoking real databases or HTTP servers.

### 4. Thou Shalt Not Create Paperwork

* **Minimize Consumer Overhead:** Library consumers should not need to execute multi-step setup sequences (e.g., creating constructors, instantiating options structs, and then calling `Run()`) just to execute a basic task.
* **Provide Smart Defaults:** Strive for single-line entry points (e.g., `game.Run()`) that work out of the box. Use patterns like functional options to allow customization only when needed, moving all boilerplate and configuration handling inside your library.

### 5. Thou Shalt Not Kill the Program

* **Return Errors, Don't Exit:** Libraries and sub-packages should never force an application to stop running by calling `os.Exit`, `log.Fatal`, or `panic`. Control over program execution belongs strictly to the top-level application (`main`).
* **Prevent Implicit Panics:** Guard against runtime crashes—such as indexing empty slices, writing to nil maps, or failing type assertions—by explicitly checking conditions and returning descriptive `error` values up the call stack.

### 6. Thou Shalt Not Leak Resources

* **Guaranteed Cleanup with `defer`:** Releasing resources (memory, file descriptors, database connections) should be wired up immediately upon allocation using `defer` to ensure cleanup runs regardless of execution path or early returns.
* **Manage Goroutine Lifecycles:** Every goroutine launched must have a clearly defined termination point owned by the function that started it. Use primitives like `sync.WaitGroup`, `errgroup`, and `context.Context` to manage concurrency and signal cancellations safely.

### 7. Thou Shalt Not Restrict User Choice

* **Accept Interfaces:** Design function inputs around minimal interfaces (like `io.Writer` or `fs.FS`) rather than concrete types like `*os.File`. This makes your functions re-usable with network connections, buffers, or custom types.
* **Return Structs:** Functions should return concrete struct types. Returning broad interfaces restricts what methods callers can invoke without performing extra type assertions ("paperwork").
* **Maintain Backwards Compatibility:** Avoid locking code to features introduced only in the absolute newest Go release; supporting the last two major versions ensures broader usability.

### 8. Thou Shalt Set Boundaries

* **Encapsulate Domain Logic via Adapters:** Keep external schemas, database representations, and third-party API models from bleeding into your core program logic. Use boundary functions/adapters to translate external data into internal Go domain structs.
* **Sanitize at the Perimeter:** Validate all incoming data at the boundary. Once data clears the adapter layer, the rest of the application can safely process it without repeating validity checks or error parsing.

### 9. Thou Shalt Not Use Interfaces Internally

* **Avoid `any` / `interface{}` inside Internal Modules:** Dynamic typing obscures data shapes and requires constant type assertions or type switches, undermining compile-time safety.
* **Don't Over-Engineered Mocks:** Avoid creating interface abstractions solely to enable unit test mocks. Instead, test concrete implementations or write simple pure functions.
* **Keep `context.Value` strictly for Request Scopes:** Do not use `context.Value` as an untyped container for optional arguments or dependencies; reserve contexts strictly for deadlines, signals, and cancellation.

### 10. Thou Shalt Not Blindly Follow Commandments, But Instead Think for Thyself

* **Rules Are Context-Dependent:** Best practices are guidelines, not absolute laws. Every trade-off depends on your project's domain, scale, and operational requirements.
* **Understand the "Why":** Blindly applying rules without understanding their underlying rationale leads to fragile architecture. Evaluate the specific trade-offs of your implementation rather than relying on blanket advice.

