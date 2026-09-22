package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const persistedStateVersion = "v1"

var errPersistenceLatched = errors.New("control-plane persistence latched after an earlier failure; restart required")

type persistedRun struct {
	SchemaVersion string                          `json:"schemaVersion"`
	Run           Run                             `json:"run"`
	Evidence      EvidenceReport                  `json:"evidence"`
	Idempotency   map[string]persistedIdempotency `json:"idempotency"`
}

type persistedIdempotency struct {
	Run     Run       `json:"run"`
	Request string    `json:"request"`
	Failure *APIError `json:"failure,omitempty"`
}

func OpenStore(root string, factory EventLogFactory, driver RunDriver) (*Store, error) {
	if root == "" {
		return nil, errors.New("persistence root is required")
	}
	s := NewStoreWithDependencies(factory, driver)
	s.root = root
	runsDir := filepath.Join(root, "runs")
	entries, err := os.ReadDir(runsDir)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read runs directory: %w", err)
	}
	fail := func(err error) (*Store, error) {
		_ = s.Close()
		return nil, err
	}
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(runsDir, entry.Name()))
		if err != nil {
			return fail(fmt.Errorf("inspect run catalog entry %q: %w", entry.Name(), err))
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fail(fmt.Errorf("run catalog entry %q is not a real directory", entry.Name()))
		}
		id := entry.Name()
		if err := validPersistedRunID(id); err != nil {
			return fail(fmt.Errorf("invalid persisted run ID %q", id))
		}
		dir := filepath.Join(runsDir, id)
		statePath := filepath.Join(dir, "state.json")
		stateInfo, err := os.Lstat(statePath)
		if err != nil {
			return fail(fmt.Errorf("run %q is missing state.json: legacy or incomplete catalog entry: %w", id, err))
		}
		if stateInfo.Mode()&os.ModeSymlink != 0 || !stateInfo.Mode().IsRegular() {
			return fail(fmt.Errorf("run %q state.json is not a regular file", id))
		}
		raw, err := os.ReadFile(statePath)
		if err != nil {
			return fail(fmt.Errorf("read run %q state: %w", id, err))
		}
		var state persistedRun
		if err := json.Unmarshal(raw, &state); err != nil {
			return fail(fmt.Errorf("decode run %q state: %w", id, err))
		}
		if err := validatePersistedRun(id, state); err != nil {
			return fail(fmt.Errorf("run %q state: %w", id, err))
		}
		logPath := filepath.Join(dir, "tracked-events.jsonl")
		logInfo, err := os.Lstat(logPath)
		if err != nil {
			return fail(fmt.Errorf("run %q is missing its trajectory log: %w", id, err))
		}
		if logInfo.Mode()&os.ModeSymlink != 0 || !logInfo.Mode().IsRegular() {
			return fail(fmt.Errorf("run %q trajectory log is not a regular file", id))
		}
		if factory == nil {
			return fail(fmt.Errorf("run %q requires an event log factory to restore", id))
		}
		log, err := factory(state.Run)
		if err != nil {
			return fail(fmt.Errorf("restore run %q trajectory: %w", id, err))
		}
		if log == nil {
			return fail(fmt.Errorf("event log factory returned nil for run %q", id))
		}
		s.eventLogs[id] = log
		s.runs[id] = state.Run
		s.events[id] = nil
		s.evidence[id] = state.Evidence
		for key, record := range state.Idempotency {
			if record.Run.ID != id {
				return fail(fmt.Errorf("run %q idempotency key %q references run %q", id, key, record.Run.ID))
			}
			if prior, exists := s.idempotency[key]; exists {
				failureConflict := (prior.failure == nil) != (record.Failure == nil) ||
					(prior.failure != nil && record.Failure != nil && *prior.failure != *record.Failure)
				if prior.request != record.Request || prior.run.ID != record.Run.ID || failureConflict {
					return fail(fmt.Errorf("idempotency key %q has conflicting records", key))
				}
				continue
			}
			s.idempotency[key] = idempotencyRecord{run: record.Run, request: record.Request, failure: record.Failure}
		}
	}
	if err := s.recoverPersistedRuns(); err != nil {
		return fail(err)
	}
	return s, nil
}

func (s *Store) recoverPersistedRuns() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	ids := make([]string, 0, len(s.runs))
	for id := range s.runs {
		ids = append(ids, id)
	}
	for _, id := range ids {
		run := s.runs[id]
		log := s.eventLogs[id]
		sealed := false
		if probe, ok := log.(interface{ Sealed() bool }); ok {
			sealed = probe.Sealed()
		}
		terminal := run.Status == "stopped" || run.Status == "completed" || run.Status == "failed"
		if terminal && sealed && s.evidence[id].Verification != nil {
			continue
		}
		var logEvents []Event
		if log != nil {
			logEvents = log.Snapshot()
		}
		finished := false
		for _, event := range logEvents {
			if event.Type == "run/finish" {
				finished = true
				break
			}
		}
		if !finished {
			data, _ := json.Marshal(map[string]string{"reason": "interrupted", "status": "failed"})
			if _, err := s.appendLocked(id, Event{Type: "run/finish", Data: data, Ignorable: true}); err != nil {
				return fmt.Errorf("recover run %q: %w", id, err)
			}
		}
		run.Status = "failed"
		run.UpdatedAt = now
		s.runs[id] = run
		report := s.evidence[id]
		report.RunID = id
		report.Status = "verification_recorded"
		report.Verification = &VerificationResult{Status: "interrupted", Eligible: false, Summary: "control plane restarted before evidence finalization", CheckedAt: now}
		s.evidence[id] = report
		if sealer, ok := log.(interface{ Seal() error }); ok {
			if err := sealer.Seal(); err != nil {
				return fmt.Errorf("seal recovered run %q: %w", id, err)
			}
		}
		if err := s.persistLocked(id); err != nil {
			return err
		}
	}
	return nil
}

func validPersistedRunID(id string) error {
	if id == "" || len(id) > 128 {
		return fmt.Errorf("invalid run ID %q", id)
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return fmt.Errorf("invalid run ID %q", id)
	}
	return nil
}

func validatePersistedRun(id string, state persistedRun) error {
	if state.SchemaVersion != persistedStateVersion {
		return fmt.Errorf("unsupported state schemaVersion %q", state.SchemaVersion)
	}
	run := state.Run
	if run.ID != id {
		return fmt.Errorf("state run ID %q does not match directory", run.ID)
	}
	if run.Spec.SchemaVersion != "v1" || run.Spec.Harness == "" || run.Spec.Suite == "" || run.Spec.Backend == "" {
		return errors.New("state has invalid run spec")
	}
	switch run.Status {
	case "created", "running", "stopping", "stopped", "completed", "failed":
	default:
		return fmt.Errorf("state has unknown run status %q", run.Status)
	}
	if run.CreatedAt.IsZero() || run.UpdatedAt.IsZero() || run.UpdatedAt.Before(run.CreatedAt) {
		return errors.New("state has invalid run timestamps")
	}
	if state.Evidence.RunID != id || state.Evidence.Status == "" {
		return errors.New("state has mismatched evidence report")
	}
	if state.Evidence.Verification != nil && state.Evidence.Verification.Status == "" {
		return errors.New("state has a verification result without status")
	}
	return nil
}

func (s *Store) persistLocked(id string) error {
	if s.root == "" {
		return nil
	}
	if s.persistErr != nil {
		return s.persistErr
	}
	if err := s.writeState(id); err != nil {
		s.persistErr = err
		return err
	}
	return nil
}

func (s *Store) latchedLocked() error {
	if s.persistErr != nil {
		return &APIError{"infrastructure", errPersistenceLatched.Error()}
	}
	return nil
}

func (s *Store) writeState(id string) error {
	state := persistedRun{
		SchemaVersion: persistedStateVersion,
		Run:           s.runs[id],
		Evidence:      s.evidence[id],
		Idempotency:   map[string]persistedIdempotency{},
	}
	for key, record := range s.idempotency {
		if record.run.ID == id {
			state.Idempotency[key] = persistedIdempotency{Run: record.run, Request: record.request, Failure: record.failure}
		}
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	dir := filepath.Join(s.root, "runs", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, "state.json")); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := dirFile.Sync(); err != nil {
		_ = dirFile.Close()
		return err
	}
	return dirFile.Close()
}
