// Package compat implements the deliberately limited Phase 1 local-process
// compatibility backend. It is useful for development, but cannot admit a
// verified run because it has no filesystem, DNS, boundary-network, or
// plaintext-network sensor.
//
// A workload is supplied by exactly one ObservationPlan.SensorConfigs entry
// with this strict JSON shape (unknown fields are rejected):
//
//	{"type":"compat/local-process-v1","command":["/path/to/program","arg"],"env":{"NAME":"value"}}
//
// command must be non-empty and contains no empty elements. The process always
// runs in the isolated directory allocated by Prepare; configuration cannot
// select a host working directory.
package compat

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
)

const sensorID = "compat-local-process"

// Config configures storage for isolated run directories. RootDir defaults to
// the system temporary directory when empty.
type Config struct{ RootDir string }

// Backend implements backend.ExecutionBackend.
type Backend struct {
	root string
	mu   sync.Mutex
	runs map[string]*run
}

// New constructs a compatibility backend. It does not create RootDir until a
// run is prepared.
func New(config Config) *Backend {
	return &Backend{root: config.RootDir, runs: make(map[string]*run)}
}

// NewBackend is an explicit spelling retained for callers that prefer a
// constructor named after the public contract.
func NewBackend(config Config) *Backend { return New(config) }

var _ backend.ExecutionBackend = (*Backend)(nil)

func manifest() backend.CapabilityManifest {
	return backend.CapabilityManifest{
		SchemaVersion: "v1", Backend: "compat-local-process", Version: "phase1", TrustDomain: "host-process",
		Capabilities: []backend.Capability{
			{EventFamily: "process", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "raw", Details: map[string]string{"scope": "workload process only"}},
			{EventFamily: "workload/stdout", Observation: backend.ObservationComplete, Enforcement: backend.EnforcementAuditOnly, Retention: "raw"},
			{EventFamily: "workload/stderr", Observation: backend.ObservationComplete, Enforcement: backend.EnforcementAuditOnly, Retention: "raw"},
			{EventFamily: "filesystem", Observation: backend.ObservationUnsupported, Enforcement: backend.EnforcementUnsupported, Retention: "none"},
			{EventFamily: "dns", Observation: backend.ObservationUnsupported, Enforcement: backend.EnforcementUnsupported, Retention: "none"},
			{EventFamily: "network/flow", Observation: backend.ObservationUnsupported, Enforcement: backend.EnforcementUnsupported, Retention: "none"},
			{EventFamily: "network/plaintext", Observation: backend.ObservationUnsupported, Enforcement: backend.EnforcementUnsupported, Retention: "none", Details: map[string]string{"reason": "no boundary TLS/plaintext interception"}},
		},
	}
}

func (b *Backend) Describe(context.Context) (backend.CapabilityManifest, error) {
	m := manifest()
	d, err := digestJSON(m)
	if err != nil {
		return backend.CapabilityManifest{}, err
	}
	m.Digest = d
	return m, nil
}

// RawRecords returns a defensive copy of the immutable raw evidence accumulated
// for a run. It is intentionally outside ExecutionBackend: the interface owns
// lifecycle only, while normalizers may use this read-only compatibility hook.
func (b *Backend) RawRecords(ctx context.Context, h backend.RunHandle) ([]evidence.RawRecord, error) {
	r, err := b.valid(h)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]evidence.RawRecord, len(r.records))
	for i, record := range r.records {
		out[i] = record
		out[i].Payload = append([]byte(nil), record.Payload...)
	}
	return out, nil
}

// RunDirectory returns the isolated directory allocated by Prepare. Consumers
// must treat it as read-only; Destroy removes it.
func (b *Backend) RunDirectory(ctx context.Context, h backend.RunHandle) (string, error) {
	r, err := b.valid(h)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return r.dir, nil
}

type workloadConfig struct {
	Type    string            `json:"type"`
	Command []string          `json:"command"`
	Env     map[string]string `json:"env,omitempty"`
}

func decodeConfig(configs []json.RawMessage) (workloadConfig, error) {
	var found *workloadConfig
	for _, raw := range configs {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var config workloadConfig
		if err := dec.Decode(&config); err != nil {
			return workloadConfig{}, fmt.Errorf("invalid compat sensor config: %w", err)
		}
		if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return workloadConfig{}, errors.New("invalid compat sensor config: trailing JSON")
		}
		if config.Type != "compat/local-process-v1" {
			continue
		}
		if found != nil {
			return workloadConfig{}, errors.New("observation plan has multiple compat/local-process-v1 configs")
		}
		found = &config
	}
	if found == nil {
		return workloadConfig{}, errors.New("observation plan requires one compat/local-process-v1 sensor config")
	}
	if len(found.Command) == 0 || strings.TrimSpace(found.Command[0]) == "" {
		return workloadConfig{}, errors.New("compat command must have a program")
	}
	for _, arg := range found.Command {
		if arg == "" {
			return workloadConfig{}, errors.New("compat command cannot contain empty arguments")
		}
	}
	for k := range found.Env {
		if k == "" || strings.Contains(k, "=") {
			return workloadConfig{}, fmt.Errorf("invalid compat environment variable %q", k)
		}
	}
	return *found, nil
}

func (b *Backend) Prepare(ctx context.Context, spec backend.RunSpec, plan backend.ObservationPlan) (backend.RunHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if spec.Verified {
		return nil, errors.New("compat-local-process cannot execute verified runs: plaintext boundary capture is unsupported")
	}
	m, err := b.Describe(ctx)
	if err != nil {
		return nil, err
	}
	if err := backend.ValidatePlanAgainstManifest(plan, m, false); err != nil {
		return nil, err
	}
	config, err := decodeConfig(plan.SensorConfigs)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.runs[spec.RunID]; exists {
		return nil, fmt.Errorf("run %q is already prepared", spec.RunID)
	}
	base := b.root
	if base == "" {
		base = os.TempDir()
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(base, safeName(spec.RunID)+"-")
	if err != nil {
		return nil, err
	}
	r := &run{backend: b, spec: spec, plan: plan, config: config, dir: dir, bootID: randomID(), done: make(chan struct{}), state: statePrepared}
	r.specDigest, err = digestJSON(spec)
	if err == nil {
		r.planDigest, err = digestJSON(plan)
	}
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	r.rawPath = filepath.Join(dir, "raw-records.bin")
	r.stdoutPath, r.stderrPath = filepath.Join(dir, "stdout.log"), filepath.Join(dir, "stderr.log")
	for _, p := range []string{r.rawPath, r.stdoutPath, r.stderrPath} {
		if err := touchPrivate(p); err != nil {
			_ = os.RemoveAll(dir)
			return nil, err
		}
	}
	r.seed, err = evidence.ChainSeed(r.specDigest, r.planDigest, sensorID, r.bootID)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	b.runs[spec.RunID] = r
	return r, nil
}

func (b *Backend) Start(ctx context.Context, h backend.RunHandle) (backend.StartedRun, error) {
	r, err := b.valid(h)
	if err != nil {
		return backend.StartedRun{}, err
	}
	if err := ctx.Err(); err != nil {
		return backend.StartedRun{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != statePrepared {
		return backend.StartedRun{}, fmt.Errorf("cannot start run in %s state", r.state)
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	cmd := exec.CommandContext(r.ctx, r.config.Command[0], r.config.Command[1:]...)
	cmd.Dir = r.dir
	cmd.Env = mergeEnv(os.Environ(), r.config.Env)
	cmd.Stdout = runWriter{run: r, path: r.stdoutPath, kind: "workload/stdout"}
	cmd.Stderr = runWriter{run: r, path: r.stderrPath, kind: "workload/stderr"}
	if err := cmd.Start(); err != nil {
		r.cancel()
		return backend.StartedRun{}, err
	}
	r.cmd, r.startedAt, r.state = cmd, time.Now().UTC(), stateStarted
	if err := r.appendLocked("process/start", []byte(fmt.Sprintf("pid=%d command=%s", cmd.Process.Pid, r.config.Command[0]))); err != nil {
		_ = cmd.Process.Kill()
		r.cancel()
		return backend.StartedRun{}, err
	}
	go r.reap()
	return backend.StartedRun{RunID: r.spec.RunID, StartedAt: r.startedAt}, nil
}

func (b *Backend) Wait(ctx context.Context, h backend.RunHandle) (backend.ExitStatus, error) {
	r, err := b.valid(h)
	if err != nil {
		return backend.ExitStatus{}, err
	}
	r.mu.Lock()
	if r.state == statePrepared {
		r.mu.Unlock()
		return backend.ExitStatus{}, errors.New("run has not started")
	}
	done := r.done
	r.mu.Unlock()
	select {
	case <-ctx.Done():
		return backend.ExitStatus{}, ctx.Err()
	case <-done:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exit, nil
}

func (b *Backend) Stop(ctx context.Context, h backend.RunHandle, reason backend.StopReason) error {
	r, err := b.valid(h)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	if r.state == statePrepared {
		r.state = stateStopped
		r.exit = backend.ExitStatus{Code: -1, Reason: string(reason), ExitedAt: time.Now().UTC()}
		close(r.done)
		r.mu.Unlock()
		return nil
	}
	if r.state == stateExited || r.state == stateStopped {
		r.mu.Unlock()
		return nil
	}
	r.state = stateStopping
	cancel, process := r.cancel, r.cmd.Process
	r.mu.Unlock()
	cancel()
	if process != nil {
		_ = process.Kill()
	}
	return nil
}

func (b *Backend) Snapshot(ctx context.Context, h backend.RunHandle) (backend.RunSnapshot, error) {
	r, err := b.valid(h)
	if err != nil {
		return backend.RunSnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return backend.RunSnapshot{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == stateDestroyed {
		return backend.RunSnapshot{}, errors.New("run is destroyed")
	}
	payload, err := json.Marshal(struct {
		RunID     string    `json:"runId"`
		State     string    `json:"state"`
		CreatedAt time.Time `json:"createdAt"`
	}{r.spec.RunID, string(r.state), time.Now().UTC()})
	if err != nil {
		return backend.RunSnapshot{}, err
	}
	d := backend.SHA256Hex(payload)
	path := filepath.Join(r.dir, "snapshot-"+d+".json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return backend.RunSnapshot{}, err
	}
	if err := r.appendLocked("runtime/snapshot", payload); err != nil {
		return backend.RunSnapshot{}, err
	}
	return backend.RunSnapshot{ID: d, Digest: d, CreatedAt: time.Now().UTC()}, nil
}

func (b *Backend) FinalizeEvidence(ctx context.Context, h backend.RunHandle) (backend.BackendEvidence, backend.SensorHealth, error) {
	r, err := b.valid(h)
	if err != nil {
		return backend.BackendEvidence{}, backend.SensorHealth{}, err
	}
	if err := ctx.Err(); err != nil {
		return backend.BackendEvidence{}, backend.SensorHealth{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == stateStarted || r.state == stateStopping {
		return backend.BackendEvidence{}, backend.SensorHealth{}, errors.New("cannot finalize evidence before process exits")
	}
	if r.state == statePrepared {
		return backend.BackendEvidence{}, backend.SensorHealth{}, errors.New("cannot finalize evidence before process starts")
	}
	if r.finalized {
		return r.evidence, r.health, nil
	}
	if err := r.appendLocked("sensor/health", []byte("network/plaintext unsupported; run is not verification eligible")); err != nil {
		return backend.BackendEvidence{}, backend.SensorHealth{}, err
	}
	head, err := evidence.ValidateChain(r.records, r.seed)
	if err != nil {
		return backend.BackendEvidence{}, backend.SensorHealth{}, err
	}
	artifacts, err := fileDigests(r.dir)
	if err != nil {
		return backend.BackendEvidence{}, backend.SensorHealth{}, err
	}
	ids := make([]string, len(artifacts))
	for i, a := range artifacts {
		ids[i] = a.Path
	}
	d, err := digestJSON(struct {
		Artifacts []evidence.ArtifactDigest `json:"artifacts"`
		Head      string                    `json:"head"`
	}{artifacts, head})
	if err != nil {
		return backend.BackendEvidence{}, backend.SensorHealth{}, err
	}
	r.evidence = backend.BackendEvidence{ArtifactIDs: ids, RawChainHeads: map[string]string{sensorID: head}, Digest: d}
	end := uint64(len(r.records))
	start := uint64(0)
	if end > 0 {
		start = 1
	}
	r.health = backend.SensorHealth{SchemaVersion: "v1", Sources: []backend.SensorSourceHealth{{SensorID: sensorID, BootID: r.bootID, ExpectedStart: start, ExpectedEnd: end, ObservedStart: start, ObservedEnd: end, Drops: r.captureDrops, ParseFailures: r.appendFailures, PlaintextFailures: 1, Started: true, Drained: true, Stopped: true}}, AppenderDrops: r.appendFailures}
	r.finalized = true
	return r.evidence, r.health, nil
}

func (b *Backend) Destroy(ctx context.Context, h backend.RunHandle) error {
	r, err := b.valid(h)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	state := r.state
	r.mu.Unlock()
	if state == stateStarted || state == stateStopping {
		if err := b.Stop(ctx, h, "destroy"); err != nil {
			return err
		}
		select {
		case <-r.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.mu.Lock()
	if r.state == stateDestroyed {
		r.mu.Unlock()
		return nil
	}
	r.state = stateDestroyed
	r.mu.Unlock()
	b.mu.Lock()
	delete(b.runs, r.spec.RunID)
	b.mu.Unlock()
	return os.RemoveAll(r.dir)
}

func (b *Backend) valid(h backend.RunHandle) (*run, error) {
	r, ok := h.(*run)
	if !ok || r == nil || r.backend != b {
		return nil, errors.New("invalid compatibility backend run handle")
	}
	b.mu.Lock()
	current := b.runs[r.spec.RunID]
	b.mu.Unlock()
	if current != r {
		return nil, errors.New("unknown or destroyed compatibility backend run handle")
	}
	return r, nil
}

type runState string

const (
	statePrepared  runState = "prepared"
	stateStarted   runState = "started"
	stateStopping  runState = "stopping"
	stateStopped   runState = "stopped"
	stateExited    runState = "exited"
	stateDestroyed runState = "destroyed"
)

type run struct {
	backend                                                                    *Backend
	spec                                                                       backend.RunSpec
	plan                                                                       backend.ObservationPlan
	config                                                                     workloadConfig
	dir, rawPath, stdoutPath, stderrPath, bootID, specDigest, planDigest, seed string
	mu                                                                         sync.Mutex
	state                                                                      runState
	ctx                                                                        context.Context
	cancel                                                                     context.CancelFunc
	cmd                                                                        *exec.Cmd
	startedAt                                                                  time.Time
	exit                                                                       backend.ExitStatus
	done                                                                       chan struct{}
	records                                                                    []evidence.RawRecord
	finalized                                                                  bool
	evidence                                                                   backend.BackendEvidence
	health                                                                     backend.SensorHealth
	// These counters are only written while r.mu is held. A raw append failure
	// means persistence did not acknowledge the observation; it is never hidden.
	captureDrops   uint64
	appendFailures uint64
}

func (r *run) RunID() string { return r.spec.RunID }

// runWriter is used directly by os/exec, avoiding a pipe-reader goroutine
// that could race Cmd.Wait and lose final output.
type runWriter struct {
	run        *run
	path, kind string
}

func (w runWriter) Write(p []byte) (int, error) {
	w.run.mu.Lock()
	defer w.run.mu.Unlock()
	chunk := append([]byte(nil), p...)
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		w.run.captureDrops++
	} else {
		_, writeErr := f.Write(chunk)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			w.run.captureDrops++
		}
	}
	if err := w.run.appendLocked(w.kind, chunk); err != nil {
		w.run.appendFailures++
	}
	// Do not turn a telemetry loss into a workload I/O failure. Health carries
	// the explicit loss and verification admission rejects it.
	return len(p), nil
}
func (r *run) reap() {
	err := r.cmd.Wait()
	r.mu.Lock()
	defer r.mu.Unlock()
	code, reason := 0, "exited"
	if err != nil {
		code, reason = -1, "failed"
		if e, ok := err.(*exec.ExitError); ok {
			code, reason = e.ExitCode(), "exited"
		}
	}
	if r.state == stateStopping {
		reason = "stopped"
	}
	r.exit = backend.ExitStatus{Code: code, Reason: reason, ExitedAt: time.Now().UTC()}
	r.state = stateExited
	if appendErr := r.appendLocked("process/exit", []byte(fmt.Sprintf("code=%d reason=%s", code, reason))); appendErr != nil {
		r.appendFailures++
	}
	close(r.done)
}
func (r *run) appendLocked(kind string, payload []byte) error {
	now := time.Now().UTC()
	seq := uint64(len(r.records) + 1)
	prev := ""
	if seq > 1 {
		prev = r.records[len(r.records)-1].RecordSHA256
	}
	record := evidence.RawRecord{RunID: r.spec.RunID, SensorID: sensorID, BootID: r.bootID, SourceSeq: seq, ObservedWallTime: &now, RecordType: kind, Encoding: "binary", Payload: append([]byte(nil), payload...), PreviousRecordSHA256: prev}
	hash, err := record.ComputedHash()
	if err != nil {
		return err
	}
	record.RecordSHA256 = hash
	frame, err := record.Frame()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(r.rawPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(frame)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	r.records = append(r.records, record)
	return nil
}

func touchPrivate(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}
func safeName(v string) string {
	v = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, v)
	if v == "" {
		return "run"
	}
	return v
}
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
func digestJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func mergeEnv(base []string, values map[string]string) []string {
	set := make(map[string]string, len(base)+len(values))
	for _, e := range base {
		if k, v, ok := strings.Cut(e, "="); ok {
			set[k] = v
		}
	}
	for k, v := range values {
		set[k] = v
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+set[k])
	}
	return out
}
func fileDigests(root string) ([]evidence.ArtifactDigest, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := make([]evidence.ArtifactDigest, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, evidence.ArtifactDigest{Path: e.Name(), SHA256: backend.SHA256Hex(b), Size: uint64(len(b))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
