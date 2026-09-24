package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

// Store is deliberately small: it provides a contract-test implementation, not execution.
type Store struct {
	mu          sync.Mutex
	runs        map[string]Run
	events      map[string][]Event
	eventLogs   map[string]EventLog
	newEventLog EventLogFactory
	driver      RunDriver
	evidence    map[string]EvidenceReport
	idempotency map[string]idempotencyRecord
	root        string
	persistErr  error
}

// EventLog is the optional durable appender boundary used by the control
// plane. internal/appender.Appender satisfies it without importing that
// implementation into the HTTP package.
type EventLog interface {
	Append(Event) (Event, error)
	Snapshot() []Event
}

// EventLogFactory creates the per-run trusted log after a run has an ID.
// Returning an error prevents creation; callers own lifecycle/cleanup of logs.
type EventLogFactory func(Run) (EventLog, error)

// RunDriver connects control-plane lifecycle requests to an execution backend.
// It intentionally exposes no evidence or verification semantics; those are
// recorded only by their dedicated integrations.
type RunDriver interface {
	Prepare(context.Context, Run) error
	Start(context.Context, string) error
	Stop(context.Context, string, string) error
}

type idempotencyRecord struct {
	run     Run
	request string
	failure *APIError
}

func NewStore() *Store {
	return NewStoreWithDependencies(nil, nil)
}

// NewStoreWithEventLogFactory constructs a Store whose events are delegated
// to a durable trusted appender when the factory is supplied.
func NewStoreWithEventLogFactory(factory EventLogFactory) *Store {
	return NewStoreWithDependencies(factory, nil)
}

// NewStoreWithRunDriver constructs an in-memory Store with an optional
// execution driver. NewStore remains suitable for API-only tests.
func NewStoreWithRunDriver(driver RunDriver) *Store {
	return NewStoreWithDependencies(nil, driver)
}

// NewStoreWithDependencies accepts both optional Phase 1 integration seams.
func NewStoreWithDependencies(factory EventLogFactory, driver RunDriver) *Store {
	return &Store{runs: map[string]Run{}, events: map[string][]Event{}, eventLogs: map[string]EventLog{}, newEventLog: factory, driver: driver, evidence: map[string]EvidenceReport{}, idempotency: map[string]idempotencyRecord{}}
}

func (s *Store) create(req CreateRunRequest) (Run, error) {
	return s.createContext(context.Background(), req)
}

func (s *Store) createContext(ctx context.Context, req CreateRunRequest) (Run, error) {
	if req.Spec.SchemaVersion != "v1" || req.Spec.Harness == "" || req.Spec.Suite == "" || req.Spec.Backend == "" {
		return Run{}, &APIError{"validation", "spec requires schemaVersion v1, harness, suite, and backend"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.latchedLocked(); err != nil {
		return Run{}, err
	}
	if req.IdempotencyKey != "" {
		key := "create:" + req.IdempotencyKey
		request := createRequestFingerprint(req)
		if prior, ok := s.idempotency[key]; ok {
			if prior.request != request {
				return Run{}, &APIError{"conflict", "idempotency key was used for a different request"}
			}
			if prior.failure != nil {
				return Run{}, prior.failure
			}
			return prior.run, nil
		}
	}
	now := time.Now().UTC()
	id, err := newRunID()
	if err != nil {
		return Run{}, fmt.Errorf("generate run ID: %w", err)
	}
	r := Run{ID: id, Spec: req.Spec, Status: "created", CreatedAt: now, UpdatedAt: now}
	if s.root != "" {
		return s.createDurableLocked(ctx, r, req)
	}
	if s.driver != nil {
		if err := s.driver.Prepare(ctx, r); err != nil {
			return Run{}, executionError("prepare run", err)
		}
	}
	var log EventLog
	if s.newEventLog != nil {
		log, err = s.newEventLog(r)
		if err != nil {
			s.abortPrepared(r.ID)
			return Run{}, fmt.Errorf("create event log: %w", err)
		}
		if log == nil {
			s.abortPrepared(r.ID)
			return Run{}, &APIError{"internal", "event log factory returned nil"}
		}
	}
	if log != nil {
		s.eventLogs[r.ID] = log
	}
	s.runs[r.ID] = r
	s.events[r.ID] = nil
	s.evidence[r.ID] = EvidenceReport{RunID: r.ID, Status: "not_collected"}
	if req.IdempotencyKey != "" {
		s.idempotency["create:"+req.IdempotencyKey] = idempotencyRecord{run: r, request: createRequestFingerprint(req)}
	}
	return r, nil
}

// createDurableLocked reserves the run's trusted log and persists the created
// state before the driver is asked to prepare, so a crash cannot leave an
// unrecorded backend reservation. Callers must hold s.mu.
func (s *Store) createDurableLocked(ctx context.Context, r Run, req CreateRunRequest) (Run, error) {
	var log EventLog
	if s.newEventLog != nil {
		created, err := s.newEventLog(r)
		if err != nil {
			return Run{}, fmt.Errorf("create event log: %w", err)
		}
		if created == nil {
			return Run{}, &APIError{"internal", "event log factory returned nil"}
		}
		log = created
	}
	if log != nil {
		s.eventLogs[r.ID] = log
	}
	s.runs[r.ID] = r
	s.events[r.ID] = nil
	s.evidence[r.ID] = EvidenceReport{RunID: r.ID, Status: "not_collected"}
	if req.IdempotencyKey != "" {
		s.idempotency["create:"+req.IdempotencyKey] = idempotencyRecord{run: r, request: createRequestFingerprint(req)}
	}
	if err := s.persistLocked(r.ID); err != nil {
		return Run{}, &APIError{"infrastructure", "persist created run: " + err.Error()}
	}
	if s.driver == nil {
		return r, nil
	}
	if err := s.driver.Prepare(ctx, r); err != nil {
		prepareErr := executionError("prepare run", err)
		failed := s.runs[r.ID]
		failed.Status = "failed"
		failed.UpdatedAt = time.Now().UTC()
		s.runs[r.ID] = failed
		report := s.evidence[r.ID]
		report.Status = "verification_recorded"
		report.Verification = &VerificationResult{Status: "verification_error", Eligible: false, Summary: "run reservation failed: " + err.Error(), CheckedAt: time.Now().UTC()}
		s.evidence[r.ID] = report
		if req.IdempotencyKey != "" {
			key := "create:" + req.IdempotencyKey
			record := s.idempotency[key]
			record.run = failed
			record.failure = prepareErr
			s.idempotency[key] = record
		}
		if persistErr := s.persistLocked(r.ID); persistErr != nil {
			return Run{}, &APIError{"infrastructure", "persist failed run reservation: " + persistErr.Error()}
		}
		return Run{}, prepareErr
	}
	return r, nil
}

func newRunID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "run-" + hex.EncodeToString(random[:]), nil
}

func (s *Store) abortPrepared(id string) {
	if driver, ok := s.driver.(interface {
		Abort(context.Context, string) error
	}); ok {
		_ = driver.Abort(context.Background(), id)
	}
}

// Close releases per-run appender descriptors after the HTTP server has
// stopped accepting requests. It does not delete retained trajectory data.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	for _, log := range s.eventLogs {
		if closer, ok := log.(io.Closer); ok {
			if err := closer.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// SealRun prevents late appends after a completed run has drained. Durable
// appenders persist the seal; in-memory contract-test stores have no seal.
func (s *Store) SealRun(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return &APIError{"not_found", "run not found"}
	}
	if run.Status != "completed" && run.Status != "failed" && run.Status != "stopped" {
		return &APIError{"conflict", "only terminal runs can be sealed"}
	}
	if log, ok := s.eventLogs[id]; ok {
		if sealer, ok := log.(interface{ Seal() error }); ok {
			return sealer.Seal()
		}
	}
	return nil
}

// RunHashHead returns the exact-frame chain head of a durable run log.
func (s *Store) RunHashHead(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[id]; !ok {
		return "", &APIError{"not_found", "run not found"}
	}
	log, ok := s.eventLogs[id]
	if !ok {
		return "", errors.New("run has no durable event log")
	}
	hasher, ok := log.(interface{ HashHead() string })
	if !ok {
		return "", errors.New("durable event log has no hash head")
	}
	return hasher.HashHead(), nil
}
func (s *Store) mutate(id string, m LifecycleMutation) (Run, error) {
	return s.mutateContext(context.Background(), id, m)
}

func (s *Store) mutateContext(ctx context.Context, id string, m LifecycleMutation) (Run, error) {
	if m.Action != "start" && m.Action != "stop" {
		return Run{}, &APIError{"validation", "action must be start or stop"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.latchedLocked(); err != nil {
		return Run{}, err
	}
	r, ok := s.runs[id]
	if !ok {
		return Run{}, &APIError{"not_found", "run not found"}
	}
	key := "mutation:" + id + ":" + m.IdempotencyKey
	if m.IdempotencyKey != "" {
		request := lifecycleFingerprint(m)
		if prior, ok := s.idempotency[key]; ok {
			if prior.request != request {
				return Run{}, &APIError{"conflict", "idempotency key was used for a different request"}
			}
			if prior.failure != nil {
				return Run{}, prior.failure
			}
			return prior.run, nil
		}
	}
	if m.Action == "start" && r.Status != "created" {
		return Run{}, &APIError{"conflict", "only created runs can start"}
	}
	if m.Action == "stop" && r.Status != "running" {
		return Run{}, &APIError{"conflict", "only running runs can stop"}
	}
	if s.driver == nil {
		return s.finishMutationLocked(id, r, key, m)
	}
	if m.Action == "start" {
		if s.root == "" {
			if err := s.driver.Start(ctx, id); err != nil {
				return Run{}, executionError("start run", err)
			}
			return s.finishMutationLocked(id, r, key, m)
		}
		reserved, err := s.finishMutationLocked(id, r, key, m)
		if err != nil {
			return Run{}, err
		}
		if err := s.driver.Start(ctx, id); err != nil {
			startErr := executionError("start run", err)
			r2 := s.runs[id]
			data, _ := json.Marshal(map[string]string{"reason": "start dispatch failed", "status": "failed"})
			if _, appendErr := s.appendLocked(id, events.TrackedEvent{Type: "run/finish", Data: data, Ignorable: true}); appendErr != nil {
				return Run{}, appendErr
			}
			r2.Status = "failed"
			r2.UpdatedAt = time.Now().UTC()
			s.runs[id] = r2
			if m.IdempotencyKey != "" {
				s.idempotency[key] = idempotencyRecord{run: r2, request: lifecycleFingerprint(m), failure: startErr}
			}
			if persistErr := s.persistLocked(id); persistErr != nil {
				return Run{}, &APIError{"infrastructure", "persist failed start dispatch: " + persistErr.Error()}
			}
			return Run{}, startErr
		}
		return reserved, nil
	}
	r.Status = "stopping"
	r.UpdatedAt = time.Now().UTC()
	s.runs[id] = r
	if m.IdempotencyKey != "" {
		s.idempotency[key] = idempotencyRecord{run: r, request: lifecycleFingerprint(m)}
	}
	if err := s.persistLocked(id); err != nil {
		return Run{}, &APIError{"infrastructure", "persist stopping run: " + err.Error()}
	}
	if err := s.driver.Stop(ctx, id, m.Reason); err != nil {
		stopErr := executionError("stop run", err)
		r2 := s.runs[id]
		r2.Status = "running"
		r2.UpdatedAt = time.Now().UTC()
		s.runs[id] = r2
		if m.IdempotencyKey != "" {
			s.idempotency[key] = idempotencyRecord{run: r2, request: lifecycleFingerprint(m), failure: stopErr}
		}
		if persistErr := s.persistLocked(id); persistErr != nil {
			return Run{}, &APIError{"infrastructure", "persist failed stop dispatch: " + persistErr.Error()}
		}
		return Run{}, stopErr
	}
	return r, nil
}

// finishMutationLocked applies the event append, status transition,
// idempotency record, and durable persist for a mutation that needs no
// asynchronous driver dispatch. Callers must hold s.mu.
func (s *Store) finishMutationLocked(id string, r Run, key string, m LifecycleMutation) (Run, error) {
	eventType := "run/start"
	status := "running"
	if m.Action == "stop" {
		eventType = "run/finish"
		status = "stopped"
	}
	data, _ := json.Marshal(map[string]string{"reason": m.Reason, "status": status})
	if _, err := s.appendLocked(id, events.TrackedEvent{Type: eventType, Data: data, Ignorable: true}); err != nil {
		return Run{}, err
	}
	r.Status = status
	r.UpdatedAt = time.Now().UTC()
	s.runs[id] = r
	if m.IdempotencyKey != "" {
		s.idempotency[key] = idempotencyRecord{run: r, request: lifecycleFingerprint(m)}
	}
	if err := s.persistLocked(id); err != nil {
		return Run{}, &APIError{"infrastructure", "persist lifecycle mutation: " + err.Error()}
	}
	return r, nil
}

// Complete records a natural backend completion. It is intentionally separate
// from Stop: a user-requested stop is already terminal and must not emit a
// second run/finish event when the backend reaper subsequently returns.
func (s *Store) Complete(id, status, reason string) (Run, error) {
	if status != "completed" && status != "failed" {
		return Run{}, &APIError{"validation", "completion status must be completed or failed"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.latchedLocked(); err != nil {
		return Run{}, err
	}
	r, ok := s.runs[id]
	if !ok {
		return Run{}, &APIError{"not_found", "run not found"}
	}
	if r.Status == "stopped" || r.Status == "completed" || r.Status == "failed" {
		return r, nil
	}
	if r.Status != "running" && r.Status != "stopping" {
		return Run{}, &APIError{"conflict", "only running runs can complete"}
	}
	if r.Status == "stopping" {
		status = "stopped"
	}
	data, _ := json.Marshal(map[string]string{"reason": reason, "status": status})
	if _, err := s.appendLocked(id, events.TrackedEvent{Type: "run/finish", Data: data, Ignorable: true}); err != nil {
		return Run{}, err
	}
	r.Status = status
	r.UpdatedAt = time.Now().UTC()
	s.runs[id] = r
	if err := s.persistLocked(id); err != nil {
		return Run{}, &APIError{"infrastructure", "persist run completion: " + err.Error()}
	}
	return r, nil
}

func executionError(operation string, err error) *APIError {
	return &APIError{"execution", operation + ": " + err.Error()}
}
func (s *Store) get(id string) (Run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	return r, ok
}
func (s *Store) list() []Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Run, 0, len(s.runs))
	for _, r := range s.runs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (s *Store) runEvents(id string) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if log, ok := s.eventLogs[id]; ok {
		return log.Snapshot()
	}
	return append([]Event(nil), s.events[id]...)
}

// AppendEvent is the narrow trusted-appender integration point. Callers
// provide an unsequenced normalized event; Store assigns its global sequence.
// It is intentionally not exposed as an HTTP mutation endpoint.
func (s *Store) AppendEvent(id string, event Event) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.latchedLocked(); err != nil {
		return Event{}, err
	}
	if _, ok := s.runs[id]; !ok {
		return Event{}, &APIError{"not_found", "run not found"}
	}
	return s.appendLocked(id, event)
}

func (s *Store) appendLocked(id string, event Event) (Event, error) {
	if event.Seq != 0 {
		return Event{}, &APIError{"validation", "event seq is assigned only by the trusted appender"}
	}
	if event.Time != 0 {
		return Event{}, &APIError{"validation", "event time is assigned only by the trusted appender"}
	}
	if log, ok := s.eventLogs[id]; ok {
		appended, err := log.Append(event)
		if err != nil {
			return Event{}, fmt.Errorf("append tracked event: %w", err)
		}
		return appended, nil
	}
	event.Seq = uint64(len(s.events[id]) + 1)
	event.Time = time.Now().UTC().UnixMilli()
	if err := events.ValidateEvent(event); err != nil {
		return Event{}, &APIError{"validation", "invalid tracked event: " + err.Error()}
	}
	s.events[id] = append(s.events[id], event)
	return event, nil
}

// Events returns a snapshot suitable for projections and exporters.
func (s *Store) Events(id string) ([]Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[id]; !ok {
		return nil, false
	}
	if log, ok := s.eventLogs[id]; ok {
		return log.Snapshot(), true
	}
	return append([]Event(nil), s.events[id]...), true
}

// ExportEvents preserves exact durable JSONL frames when the selected log
// supports it; contract-test stores fall back to deterministic JSONL encoding.
func (s *Store) ExportEvents(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[id]; !ok {
		return nil, &APIError{"not_found", "run not found"}
	}
	events := s.events[id]
	if log, ok := s.eventLogs[id]; ok {
		if exporter, ok := log.(interface{ Export() ([]byte, error) }); ok {
			return exporter.Export()
		}
		events = log.Snapshot()
	}
	var result strings.Builder
	for _, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		result.Write(encoded)
		result.WriteByte('\n')
	}
	return []byte(result.String()), nil
}

// SetEvidenceVerification records an outcome produced by an external verifier.
// The Store does not manufacture an outcome from lifecycle or event data.
func (s *Store) SetEvidenceVerification(id string, verification VerificationResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.latchedLocked(); err != nil {
		return err
	}
	if _, ok := s.runs[id]; !ok {
		return &APIError{"not_found", "run not found"}
	}
	if verification.Status == "" {
		return &APIError{"validation", "verification status is required"}
	}
	if verification.CheckedAt.IsZero() {
		verification.CheckedAt = time.Now().UTC()
	}
	report := s.evidence[id]
	report.Verification = &verification
	if verification.Status == "verified" && verification.Eligible {
		report.Status = "verified"
	} else {
		report.Status = "verification_recorded"
	}
	s.evidence[id] = report
	if err := s.persistLocked(id); err != nil {
		return &APIError{"infrastructure", "persist evidence publication: " + err.Error()}
	}
	return nil
}

func (s *Store) evidenceReport(id string) (EvidenceReport, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	report, ok := s.evidence[id]
	return report, ok
}

// Runs returns a snapshot of every run known to the store.
func (s *Store) Runs() []Run { return s.list() }

// Evidence returns the evidence report currently recorded for a run.
func (s *Store) Evidence(id string) (EvidenceReport, bool) { return s.evidenceReport(id) }

// ExportEvidence returns the exact published evidence bundle bytes for a
// terminal run with a recorded verification result. Stores without a
// persistence root report the export as unsupported.
func (s *Store) ExportEvidence(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == "" {
		return nil, &APIError{"execution", "evidence bundle export requires a persistent control-plane store"}
	}
	run, ok := s.runs[id]
	if !ok {
		return nil, &APIError{"not_found", "run not found"}
	}
	if run.Status != "completed" && run.Status != "failed" && run.Status != "stopped" {
		return nil, &APIError{"conflict", "run has not reached a terminal state"}
	}
	if s.evidence[id].Verification == nil {
		return nil, &APIError{"conflict", "evidence bundle is not yet published"}
	}
	bundle, err := os.ReadFile(filepath.Join(s.root, "runs", id, "evidence-bundle.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, &APIError{"conflict", "evidence bundle is not yet published"}
	}
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

func createRequestFingerprint(v CreateRunRequest) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func lifecycleFingerprint(v LifecycleMutation) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func NewHandler(store *Store) http.Handler {
	if store == nil {
		store = NewStore()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/web" && r.URL.Path != "/web/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			method(w, http.MethodGet)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, webUIHTML)
	})
	mux.HandleFunc("/v1/compatibility", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			method(w, http.MethodGet)
			return
		}
		writeJSON(w, http.StatusOK, Compatibility{APIVersions: []string{"v1"}, Schemas: []string{OpenAIChatCompletionsSchema}, StreamingFormat: []string{"application/x-ndjson", "text/event-stream"}})
	})
	mux.HandleFunc("/v1/schemas", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			method(w, http.MethodGet)
			return
		}
		writeJSON(w, http.StatusOK, Page[string]{Items: []string{"control-api.v1", OpenAIChatCompletionsSchema}})
	})
	mux.HandleFunc("/v1/backends", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			method(w, http.MethodGet)
			return
		}
		writeJSON(w, http.StatusOK, Page[CapabilityManifest]{Items: []CapabilityManifest{
			{
				Backend: "compat-local-process", Version: "phase1", SchemaVersion: "v1",
				Capabilities: []string{"process:best_effort", "workload/stdout:complete", "workload/stderr:complete", "network/plaintext:unsupported"},
			},
			{
				Backend: "gvisor-container", Version: "phase2.1", SchemaVersion: "v1",
				Capabilities: []string{"process:best_effort", "filesystem:best_effort", "dns:best_effort", "network/packets:best_effort", "network/plaintext:best_effort"},
			},
		}})
	})
	mux.HandleFunc("/v1/runs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req CreateRunRequest
			if err := decode(r, &req); err != nil {
				bad(w, err)
				return
			}
			if req.IdempotencyKey == "" {
				req.IdempotencyKey = r.Header.Get("Idempotency-Key")
			}
			run, err := store.createContext(r.Context(), req)
			respond(w, http.StatusCreated, run, err)
			return
		}
		if r.Method == http.MethodGet {
			items := store.list()
			offset, limit, err := pagination(r)
			if err != nil {
				bad(w, err)
				return
			}
			if offset > len(items) {
				bad(w, fmt.Errorf("cursor is beyond available results"))
				return
			}
			end := len(items)
			if limit <= len(items)-offset {
				end = offset + limit
			}
			p := Page[Run]{Items: items[offset:end]}
			if end < len(items) {
				p.NextCursor = strconv.Itoa(end)
			}
			writeJSON(w, http.StatusOK, p)
			return
		}
		method(w, http.MethodGet+", "+http.MethodPost)
	})
	mux.HandleFunc("/v1/runs/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/runs/"), "/")
		if len(parts) < 1 || parts[0] == "" {
			http.NotFound(w, r)
			return
		}
		id := parts[0]
		if len(parts) == 1 {
			if r.Method != http.MethodGet {
				method(w, http.MethodGet)
				return
			}
			run, ok := store.get(id)
			if !ok {
				respond(w, 0, nil, &APIError{"not_found", "run not found"})
				return
			}
			writeJSON(w, http.StatusOK, run)
			return
		}
		if len(parts) == 2 && parts[1] == "lifecycle" {
			if r.Method != http.MethodPost {
				method(w, http.MethodPost)
				return
			}
			var m LifecycleMutation
			if err := decode(r, &m); err != nil {
				bad(w, err)
				return
			}
			if m.IdempotencyKey == "" {
				m.IdempotencyKey = r.Header.Get("Idempotency-Key")
			}
			run, err := store.mutateContext(r.Context(), id, m)
			respond(w, http.StatusOK, run, err)
			return
		}
		if len(parts) == 2 && parts[1] == "events" {
			if r.Method != http.MethodGet {
				method(w, http.MethodGet)
				return
			}
			if _, ok := store.get(id); !ok {
				respond(w, 0, nil, &APIError{"not_found", "run not found"})
				return
			}
			events := store.runEvents(id)
			if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
				w.Header().Set("Content-Type", "text/event-stream")
				for _, e := range events {
					b, _ := json.Marshal(e)
					fmt.Fprintf(w, "event: tracked\ndata: %s\n\n", b)
				}
				return
			}
			w.Header().Set("Content-Type", "application/x-ndjson")
			for _, e := range events {
				_ = json.NewEncoder(w).Encode(e)
			}
			return
		}
		if len(parts) == 2 && parts[1] == "trajectory" {
			if r.Method != http.MethodGet {
				method(w, http.MethodGet)
				return
			}
			trajectoryPage(w, r, store, id)
			return
		}
		if len(parts) == 3 && parts[1] == "trajectory" && parts[2] == "export" {
			if r.Method != http.MethodGet {
				method(w, http.MethodGet)
				return
			}
			exportEvents(w, store, id)
			return
		}
		if len(parts) == 2 && parts[1] == "evidence" {
			if r.Method != http.MethodGet {
				method(w, http.MethodGet)
				return
			}
			report, ok := store.evidenceReport(id)
			if !ok {
				respond(w, 0, nil, &APIError{"not_found", "run not found"})
				return
			}
			writeJSON(w, http.StatusOK, report)
			return
		}
		if len(parts) == 3 && parts[1] == "evidence" && parts[2] == "export" {
			if r.Method != http.MethodGet {
				method(w, http.MethodGet)
				return
			}
			bundle, err := store.ExportEvidence(id)
			if err != nil {
				respond(w, 0, nil, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", `attachment; filename="evidence-bundle.json"`)
			_, _ = w.Write(bundle)
			return
		}
		http.NotFound(w, r)
	})
	return mux
}

func trajectoryPage(w http.ResponseWriter, r *http.Request, store *Store, id string) {
	events, ok := store.Events(id)
	if !ok {
		respond(w, 0, nil, &APIError{"not_found", "run not found"})
		return
	}
	offset, limit, err := pagination(r)
	if err != nil {
		bad(w, err)
		return
	}
	if offset > len(events) {
		bad(w, fmt.Errorf("cursor is beyond available results"))
		return
	}
	end := len(events)
	if limit <= len(events)-offset {
		end = offset + limit
	}
	page := Page[Event]{Items: events[offset:end]}
	if end < len(events) {
		page.NextCursor = strconv.Itoa(end)
	}
	writeJSON(w, http.StatusOK, page)
}

func exportEvents(w http.ResponseWriter, store *Store, id string) {
	frames, err := store.ExportEvents(id)
	if err != nil {
		respond(w, 0, nil, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+`-trajectory.jsonl"`)
	_, _ = w.Write(frames)
}

const webUIHTML = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Benchmark runs</title><style>body{font:15px system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}button{margin-left:.5rem}li{margin:.5rem 0}pre{background:#f5f5f5;padding:1rem;overflow:auto}fieldset{margin:1rem 0}textarea{width:100%;font-family:monospace}</style><h1>Benchmark runs</h1><p><button id="refresh">Refresh</button></p><p id="state">Loading…</p><ul id="runs"></ul><fieldset><legend>New run</legend><p>Harness: <input id="harness" value="h"> Suite: <input id="suite" value="s"> Backend: <input id="backend" value="compat-local-process"></p><p>Backend config (JSON):</p><textarea id="backendConfig" rows="3">{"type":"compat/local-process-v1","command":["/bin/sh","-c","printf hello"]}</textarea><p><button id="create">Create</button> <button id="start" disabled>Start</button> <button id="stop" disabled>Stop</button></p></fieldset><h2 id="detail-title">Trajectory</h2><p id="evidence"></p><p id="export"></p><pre id="events">Select a run to inspect its published trajectory.</pre><script>(async()=>{const state=document.querySelector('#state'),runs=document.querySelector('#runs'),events=document.querySelector('#events'),title=document.querySelector('#detail-title'),evidence=document.querySelector('#evidence'),exportp=document.querySelector('#export'),start=document.querySelector('#start'),stop=document.querySelector('#stop');let selected=null;function api(path,opts){return fetch(path,opts).then(r=>{if(!r.ok)return r.text().then(t=>{throw new Error(t)});return r})}async function refresh(){try{const r=await api('/v1/runs');const page=await r.json();state.textContent=page.items.length+' run(s)';runs.textContent='';for(const run of page.items){const li=document.createElement('li'),button=document.createElement('button');li.textContent=run.id+' — '+run.status+' ('+run.spec.harness+' / '+run.spec.suite+')';li.dataset.runId=run.id;button.textContent='Select';button.onclick=()=>show(run.id);li.append(button);runs.append(li)}}catch(e){state.textContent='Unable to load runs: '+e.message}}async function show(id){selected=id;start.disabled=false;stop.disabled=false;title.textContent='Trajectory: '+id;events.textContent='Loading…';evidence.textContent='';exportp.textContent='';try{const r=await api('/v1/runs/'+encodeURIComponent(id)+'/events',{headers:{Accept:'application/x-ndjson'}});events.textContent=await r.text()||'No published events.'}catch(e){events.textContent='Unable to load trajectory: '+e.message}try{const r=await api('/v1/runs/'+encodeURIComponent(id)+'/evidence');const report=await r.json();const v=report.verification;let text='Evidence: '+report.status;if(v){text+=' — '+v.status+(v.summary?': '+v.summary:'');if(v.trackedEventChainHead)text+=' head='+v.trackedEventChainHead;if(v.eventCount)text+=' events='+v.eventCount}evidence.textContent=text;const link=document.createElement('a');link.href='/v1/runs/'+encodeURIComponent(id)+'/evidence/export';link.textContent='Download evidence bundle';exportp.append(link)}catch(e){evidence.textContent='Evidence: '+e.message}}document.querySelector('#refresh').onclick=refresh;document.querySelector('#create').onclick=async()=>{try{const cfg=JSON.parse(document.querySelector('#backendConfig').value);const r=await api('/v1/runs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({spec:{schemaVersion:'v1',harness:document.querySelector('#harness').value,suite:document.querySelector('#suite').value,backend:document.querySelector('#backend').value,parameters:{backendConfig:cfg}}})});const run=await r.json();await refresh();await show(run.id)}catch(e){state.textContent='Create failed: '+e.message}};start.onclick=()=>mutate('start');stop.onclick=()=>mutate('stop');async function mutate(action){if(!selected)return;try{await api('/v1/runs/'+encodeURIComponent(selected)+'/lifecycle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:action})});await refresh();await show(selected)}catch(e){state.textContent=action+' failed: '+e.message}}await refresh()})()</script></html>`

func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("request body must contain exactly one JSON document")
		}
		return err
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func bad(w http.ResponseWriter, e error) { respond(w, 0, nil, &APIError{"validation", e.Error()}) }
func respond(w http.ResponseWriter, status int, v any, e error) {
	if e == nil {
		writeJSON(w, status, v)
		return
	}
	ae, ok := e.(*APIError)
	if !ok {
		ae = &APIError{"internal", e.Error()}
	}
	code := http.StatusBadRequest
	if ae.Code == "not_found" {
		code = http.StatusNotFound
	}
	if ae.Code == "conflict" {
		code = http.StatusConflict
	}
	if ae.Code == "execution" || ae.Code == "internal" {
		code = http.StatusInternalServerError
	}
	if ae.Code == "infrastructure" {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"error": ae})
}
func pagination(r *http.Request) (int, int, error) {
	q := r.URL.Query()
	offset := 0
	limit := 100
	if raw, ok := q["cursor"]; ok && len(raw) > 0 {
		if len(raw) != 1 {
			return 0, 0, fmt.Errorf("cursor must be specified once")
		}
		if raw[0] != "" {
			v, err := strconv.ParseUint(raw[0], 10, strconv.IntSize)
			if err != nil {
				return 0, 0, fmt.Errorf("cursor must be a non-negative integer")
			}
			offset = int(v)
		}
	}
	if raw, ok := q["limit"]; ok && len(raw) > 0 {
		if len(raw) != 1 {
			return 0, 0, fmt.Errorf("limit must be specified once")
		}
		if raw[0] != "" {
			v, err := strconv.ParseUint(raw[0], 10, strconv.IntSize)
			if err != nil || v == 0 || v > 100 {
				return 0, 0, fmt.Errorf("limit must be an integer from 1 to 100")
			}
			limit = int(v)
		}
	}
	return offset, limit, nil
}
func method(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": map[string]string{"code": "method_not_allowed", "message": "method not allowed"}})
}
