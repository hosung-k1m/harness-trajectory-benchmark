package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/appender"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

func testFactory(root string) EventLogFactory {
	return func(run Run) (EventLog, error) {
		return appender.Open(filepath.Join(root, "runs", run.ID, "tracked-events.jsonl"))
	}
}

func createRunWithRequest(t *testing.T, s *Store, request CreateRunRequest) Run {
	t.Helper()
	return createRunAndDecode(t, s, request)
}

var testSpec = RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "compat", Parameters: map[string]json.RawMessage{}, Verified: true}

func createRunAndDecode(t *testing.T, s *Store, request CreateRunRequest) Run {
	t.Helper()
	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/v1/runs", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	NewHandler(s).ServeHTTP(w, req)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("create: %s", w.Body.String())
	}
	var run Run
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	return run
}

func TestOpenStoreRoundTripPreservesRunsAndIdempotency(t *testing.T) {
	root := t.TempDir()
	open := func() *Store {
		s, err := OpenStore(root, testFactory(root), nil)
		if err != nil {
			t.Fatalf("OpenStore: %v", err)
		}
		return s
	}
	s := open()
	spec := testSpec
	run := createRunWithRequest(t, s, CreateRunRequest{Spec: spec, IdempotencyKey: "k1"})
	if _, err := s.mutate(run.ID, LifecycleMutation{Action: "start", IdempotencyKey: "key-start"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEvidenceVerification(run.ID, VerificationResult{Status: "ineligible", Eligible: false, Summary: "x", EventCount: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Complete(run.ID, "completed", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := s.SealRun(run.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := open()
	defer reopened.Close()
	got, ok := reopened.get(run.ID)
	if !ok || got.Status != "completed" || got.Spec.Harness != "h" {
		t.Fatalf("restored run = %#v ok=%v", got, ok)
	}
	exported, ok := reopened.Events(run.ID)
	if !ok || len(exported) != 2 || exported[0].Type != "run/start" || exported[1].Type != "run/finish" {
		t.Fatalf("events = %#v ok=%v", exported, ok)
	}
	report, ok := reopened.Evidence(run.ID)
	if !ok || report.Verification == nil || report.Verification.EventCount != 2 {
		t.Fatalf("evidence = %#v ok=%v", report, ok)
	}
	again := createRunAndDecode(t, reopened, CreateRunRequest{Spec: spec, IdempotencyKey: "k1"})
	if again.ID != run.ID {
		t.Fatalf("idempotent create returned %s want %s", again.ID, run.ID)
	}
	conflict := func(request CreateRunRequest) bool {
		body, _ := json.Marshal(request)
		req := httptest.NewRequest(http.MethodPost, "/v1/runs", strings.NewReader(string(body)))
		w := httptest.NewRecorder()
		NewHandler(reopened).ServeHTTP(w, req)
		return w.Code == http.StatusConflict
	}
	if !conflict(CreateRunRequest{Spec: RunSpec{SchemaVersion: "v1", Harness: "changed", Suite: "s", Backend: "compat", Parameters: map[string]json.RawMessage{}, Verified: true}, IdempotencyKey: "k1"}) {
		t.Fatal("mismatched idempotency key did not conflict")
	}
	if _, err := reopened.mutate(run.ID, LifecycleMutation{Action: "start"}); err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("restart on completed run err=%v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	third := open()
	defer third.Close()
	thirdRun, ok := third.get(run.ID)
	if !ok || thirdRun.Status != "completed" {
		t.Fatalf("second restart run = %#v ok=%v", thirdRun, ok)
	}
	exported, _ = third.Events(run.ID)
	if len(exported) != 2 {
		t.Fatalf("duplicate events after second restart: %#v", exported)
	}
}

func TestOpenStoreRecoversInterruptedRunsOnce(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, s *Store) Run
		wantSeq int
	}{
		{"running", func(t *testing.T, s *Store) Run {
			run := createRunWithRequest(t, s, CreateRunRequest{Spec: testSpec})
			if _, err := s.mutate(run.ID, LifecycleMutation{Action: "start"}); err != nil {
				t.Fatal(err)
			}
			return run
		}, 2},
		{"created", func(t *testing.T, s *Store) Run {
			return createRunWithRequest(t, s, CreateRunRequest{Spec: testSpec})
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			s, err := OpenStore(root, testFactory(root), nil)
			if err != nil {
				t.Fatal(err)
			}
			run := tc.prepare(t, s)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			reopened, err := OpenStore(root, testFactory(root), nil)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			got, ok := reopened.get(run.ID)
			if !ok || got.Status != "failed" {
				t.Fatalf("status = %s", got.Status)
			}
			report, _ := reopened.Evidence(run.ID)
			if report.Verification == nil || report.Verification.Status != "interrupted" || report.Verification.Eligible {
				t.Fatalf("verification = %#v", report.Verification)
			}
			eventsList, ok := reopened.Events(run.ID)
			if !ok {
				t.Fatal("run events missing")
			}
			if len(eventsList) != tc.wantSeq || eventsList[len(eventsList)-1].Type != "run/finish" || !strings.Contains(string(eventsList[len(eventsList)-1].Data), `"reason":"interrupted"`) {
				t.Fatalf("events = %#v", eventsList)
			}
			log, err := appender.Open(filepath.Join(root, "runs", run.ID, "tracked-events.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := log.Append(events.TrackedEvent{Type: "x", Data: json.RawMessage(`{}`)}); !errors.Is(err, appender.ErrSealed) {
				t.Fatalf("append after recovery seal err=%v", err)
			}
			log.Close()

			state, err := os.ReadFile(filepath.Join(root, "runs", run.ID, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			var persisted map[string]any
			if err := json.Unmarshal(state, &persisted); err != nil {
				t.Fatal(err)
			}
			if persisted["run"].(map[string]any)["status"] != "failed" {
				t.Fatalf("persisted state = %s", state)
			}

			again, err := OpenStore(root, testFactory(root), nil)
			if err != nil {
				t.Fatalf("second reopen: %v", err)
			}
			eventsAgain, _ := again.Events(run.ID)
			if len(eventsAgain) != tc.wantSeq {
				t.Fatalf("second recovery appended events: %#v", eventsAgain)
			}
			again.Close()
			reopened.Close()
		})
	}
}

func TestOpenStoreRejectsCorruptCatalog(t *testing.T) {
	seed := func(t *testing.T, root string) string {
		s, err := OpenStore(root, testFactory(root), nil)
		if err != nil {
			t.Fatal(err)
		}
		run := createRunWithRequest(t, s, CreateRunRequest{Spec: testSpec, IdempotencyKey: "k1"})
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		return run.ID
	}
	for _, tc := range []struct {
		name    string
		corrupt func(t *testing.T, root string, runID string)
	}{
		{"invalid directory name", func(t *testing.T, root, runID string) {
			if err := os.MkdirAll(filepath.Join(root, "runs", "Bad_ID"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing state", func(t *testing.T, root, runID string) {
			dir := filepath.Join(root, "runs", "run-legacy")
			os.MkdirAll(dir, 0o700)
			os.WriteFile(filepath.Join(dir, "tracked-events.jsonl"), nil, 0o600)
		}},
		{"symlink run dir", func(t *testing.T, root, runID string) {
			os.Symlink(filepath.Join(root, "runs", runID), filepath.Join(root, "runs", "run-link"))
		}},
		{"malformed state", func(t *testing.T, root, runID string) {
			os.WriteFile(filepath.Join(root, "runs", runID, "state.json"), []byte("{"), 0o600)
		}},
		{"run id mismatch", func(t *testing.T, root, runID string) {
			dir := filepath.Join(root, "runs", runID)
			state, _ := os.ReadFile(filepath.Join(dir, "state.json"))
			var persisted map[string]any
			json.Unmarshal(state, &persisted)
			persisted["run"].(map[string]any)["id"] = "run-other"
			encoded, _ := json.Marshal(persisted)
			os.WriteFile(filepath.Join(dir, "state.json"), encoded, 0o600)
		}},
		{"corrupt trajectory", func(t *testing.T, root, runID string) {
			f, err := os.OpenFile(filepath.Join(root, "runs", runID, "tracked-events.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(f, "{not json")
			f.Close()
		}},
		{"conflicting idempotency", func(t *testing.T, root, runID string) {
			dir := filepath.Join(root, "runs", runID)
			state, _ := os.ReadFile(filepath.Join(dir, "state.json"))
			var persisted map[string]any
			json.Unmarshal(state, &persisted)
			idem := persisted["idempotency"].(map[string]any)
			for key, entry := range idem {
				mutated := entry.(map[string]any)
				mutated["request"] = `{"different":true}`
				idem[key] = mutated
			}
			if len(idem) == 0 {
				t.Fatal("seed run has no idempotency records")
			}
			other := filepath.Join(root, "runs", "run-other")
			os.MkdirAll(other, 0o700)
			persisted["run"].(map[string]any)["id"] = "run-other"
			encoded, _ := json.Marshal(persisted)
			os.WriteFile(filepath.Join(other, "state.json"), encoded, 0o600)
			os.WriteFile(filepath.Join(other, "tracked-events.jsonl"), nil, 0o600)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			runID := seed(t, root)
			tc.corrupt(t, root, runID)
			s, err := OpenStore(root, testFactory(root), nil)
			if err == nil {
				s.Close()
				t.Fatal("corrupt catalog accepted")
			}
		})
	}
}

type stubDriver struct {
	prepareCalls  atomic.Int32
	startCalls    atomic.Int32
	stopCalls     atomic.Int32
	prepareErr    error
	startErr      error
	stopErr       error
	startEntered  chan struct{}
	startReleased chan struct{}
}

func (d *stubDriver) Prepare(context.Context, Run) error {
	d.prepareCalls.Add(1)
	return d.prepareErr
}

func (d *stubDriver) Start(context.Context, string) error {
	d.startCalls.Add(1)
	if d.startEntered != nil {
		close(d.startEntered)
		<-d.startReleased
	}
	return d.startErr
}

func (d *stubDriver) Stop(context.Context, string, string) error {
	d.stopCalls.Add(1)
	return d.stopErr
}

func TestLifecycleDispatchIsSerializedUnderStoreLock(t *testing.T) {
	driver := &stubDriver{startEntered: make(chan struct{}), startReleased: make(chan struct{})}
	root := t.TempDir()
	s, err := OpenStore(root, testFactory(root), driver)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	run := createRunAndDecode(t, s, CreateRunRequest{Spec: testSpec})
	startDone := make(chan error, 1)
	go func() {
		_, err := s.mutate(run.ID, LifecycleMutation{Action: "start"})
		startDone <- err
	}()
	<-driver.startEntered
	stopDone := make(chan error, 1)
	go func() {
		_, err := s.mutate(run.ID, LifecycleMutation{Action: "stop"})
		stopDone <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if got := driver.stopCalls.Load(); got != 0 {
		t.Fatalf("stop dispatched while start was blocked: %d", got)
	}
	close(driver.startReleased)
	if err := <-startDone; err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := <-stopDone; err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := s.Complete(run.ID, "completed", "stopped"); err != nil {
		t.Fatal(err)
	}
	got, ok := s.get(run.ID)
	if !ok || got.Status != "stopped" {
		t.Fatalf("run = %#v", got)
	}
	eventsList, _ := s.Events(run.ID)
	if len(eventsList) != 2 || eventsList[0].Type != "run/start" || eventsList[1].Type != "run/finish" {
		t.Fatalf("events = %#v", eventsList)
	}
}

func TestFailedStopDoesNotResurrectOrReterminalize(t *testing.T) {
	driver := &stubDriver{stopErr: errors.New("stop unavailable")}
	s := NewStoreWithRunDriver(driver)
	defer s.Close()
	run := createRunAndDecode(t, s, CreateRunRequest{Spec: testSpec})
	if _, err := s.mutate(run.ID, LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.mutate(run.ID, LifecycleMutation{Action: "stop", IdempotencyKey: "stop-1"}); err == nil {
		t.Fatal("stop succeeded")
	}
	got, _ := s.get(run.ID)
	if got.Status != "running" {
		t.Fatalf("status after failed stop = %s", got.Status)
	}
	if _, err := s.mutate(run.ID, LifecycleMutation{Action: "stop", IdempotencyKey: "stop-1"}); err == nil {
		t.Fatal("replayed stop succeeded")
	} else if !strings.Contains(err.Error(), "stop unavailable") {
		t.Fatalf("replayed stop error = %v", err)
	}
	if driver.stopCalls.Load() != 1 {
		t.Fatalf("stop redispatched: %d", driver.stopCalls.Load())
	}
	if _, err := s.Complete(run.ID, "completed", "exited"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.get(run.ID)
	if got.Status != "completed" {
		t.Fatalf("status = %s", got.Status)
	}
	eventsList, _ := s.Events(run.ID)
	finishes := 0
	for _, e := range eventsList {
		if e.Type == "run/finish" {
			finishes++
		}
	}
	if finishes != 1 {
		t.Fatalf("run/finish count = %d in %#v", finishes, eventsList)
	}
}

func TestDurableFailedPrepareAndStartReplayErrorAcrossRestart(t *testing.T) {
	for _, tc := range []struct {
		name    string
		driver  func() *stubDriver
		mutate  bool
		key     string
		wantMsg string
	}{
		{"prepare", func() *stubDriver { return &stubDriver{prepareErr: errors.New("no capacity")} }, false, "create-1", "no capacity"},
		{"start", func() *stubDriver { return &stubDriver{startErr: errors.New("dispatch refused")} }, true, "start-1", "dispatch refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			driver := tc.driver()
			s, err := OpenStore(root, testFactory(root), driver)
			if err != nil {
				t.Fatal(err)
			}
			request := CreateRunRequest{Spec: testSpec}
			if !tc.mutate {
				request.IdempotencyKey = tc.key
			}
			body, _ := json.Marshal(request)
			create := func() (int, Run, string) {
				req := httptest.NewRequest(http.MethodPost, "/v1/runs", strings.NewReader(string(body)))
				w := httptest.NewRecorder()
				NewHandler(s).ServeHTTP(w, req)
				var run Run
				var payload map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &payload)
				_ = json.Unmarshal(w.Body.Bytes(), &run)
				message := ""
				if ae, ok := payload["error"].(map[string]any); ok {
					message, _ = ae["message"].(string)
				}
				return w.Code, run, message
			}
			code, run, message := create()
			if run.ID == "" {
				if runs := s.Runs(); len(runs) == 1 {
					run = runs[0]
				}
				if run.ID == "" {
					t.Fatal("failed create retained no run")
				}
			}
			if tc.mutate {
				if code != http.StatusOK && code != http.StatusCreated {
					t.Fatalf("create: %d %s", code, message)
				}
				if _, err := s.mutate(run.ID, LifecycleMutation{Action: "start", IdempotencyKey: tc.key}); err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("start err=%v", err)
				}
				if _, err := s.mutate(run.ID, LifecycleMutation{Action: "start", IdempotencyKey: tc.key}); err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("replayed start err=%v", err)
				}
				if driver.startCalls.Load() != 1 {
					t.Fatalf("start redispatched: %d", driver.startCalls.Load())
				}
			} else {
				if code == http.StatusOK || code == http.StatusCreated || !strings.Contains(message, tc.wantMsg) {
					t.Fatalf("create code=%d message=%q", code, message)
				}
				code, _, message = create()
				if code == http.StatusOK || code == http.StatusCreated || !strings.Contains(message, tc.wantMsg) {
					t.Fatalf("replayed create code=%d message=%q", code, message)
				}
				if driver.prepareCalls.Load() != 1 {
					t.Fatalf("prepare redispatched: %d", driver.prepareCalls.Load())
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			reopened, err := OpenStore(root, testFactory(root), driver)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			defer reopened.Close()
			if tc.mutate {
				if _, err := reopened.mutate(run.ID, LifecycleMutation{Action: "start", IdempotencyKey: tc.key}); err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("post-restart start err=%v", err)
				}
				if driver.startCalls.Load() != 1 {
					t.Fatalf("start redispatched after restart: %d", driver.startCalls.Load())
				}
			} else {
				req := httptest.NewRequest(http.MethodPost, "/v1/runs", strings.NewReader(string(body)))
				w := httptest.NewRecorder()
				NewHandler(reopened).ServeHTTP(w, req)
				var payload map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &payload)
				message := ""
				if ae, ok := payload["error"].(map[string]any); ok {
					message, _ = ae["message"].(string)
				}
				if w.Code == http.StatusOK || w.Code == http.StatusCreated || !strings.Contains(message, tc.wantMsg) {
					t.Fatalf("post-restart create code=%d message=%q", w.Code, message)
				}
				if driver.prepareCalls.Load() != 1 {
					t.Fatalf("prepare redispatched after restart: %d", driver.prepareCalls.Load())
				}
			}
			eventsList, _ := reopened.Events(run.ID)
			finishes := 0
			for _, e := range eventsList {
				if e.Type == "run/finish" {
					finishes++
				}
			}
			if finishes != 1 {
				t.Fatalf("expected exactly one run/finish on %s: %#v", run.ID, eventsList)
			}
		})
	}
}

func TestPersistedStoreRejectsMutationAfterPersistenceFailure(t *testing.T) {
	root := t.TempDir()
	s, err := OpenStore(root, testFactory(root), nil)
	if err != nil {
		t.Fatal(err)
	}
	run := createRunWithRequest(t, s, CreateRunRequest{Spec: testSpec})
	if err := os.Chmod(filepath.Join(root, "runs", run.ID), 0o500); err != nil {
		t.Skipf("chmod unsupported: %v", err)
	}
	if _, err := s.mutate(run.ID, LifecycleMutation{Action: "start"}); err == nil {
		t.Fatal("mutation succeeded despite persistence failure")
	}
	if _, err := s.mutate(run.ID, LifecycleMutation{Action: "stop"}); err == nil {
		t.Fatal("latched store accepted further mutation")
	}
	os.Chmod(filepath.Join(root, "runs", run.ID), 0o700)
	s.Close()
}
