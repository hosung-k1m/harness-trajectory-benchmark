package controlplane_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/appender"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/backend/compat"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/controlplane"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/client"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

func TestCompatDriverHTTPVerticalSlice(t *testing.T) {
	for _, tc := range []struct {
		name       string
		command    []string
		wantStatus string
	}{
		{"success", []string{"/bin/sh", "-c", "printf out; printf err >&2"}, "completed"},
		{"failure", []string{"/bin/sh", "-c", "printf err >&2; exit 7"}, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, closeDriver := newClient(t)
			defer closeDriver()
			run := createAndStart(t, c, tc.command, false)
			got := waitTerminal(t, c, run.ID)
			if got.Status != tc.wantStatus {
				t.Fatalf("status=%q want %q", got.Status, tc.wantStatus)
			}
			events, err := c.Events(context.Background(), run.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, typ := range []string{"process/exec", "process/exit", "stdio/chunk", "sensor/stop", "run/finish"} {
				if count(events, typ) == 0 {
					t.Fatalf("missing %s in %#v", typ, events)
				}
			}
			report := waitEvidence(t, c, run.ID)
			if report.Status != "verification_recorded" || report.Verification.Eligible || report.Verification.Status != "ineligible" {
				t.Fatalf("unexpected evidence report: %#v", report)
			}
			if report.Verification.EventCount != uint64(len(events)) {
				t.Fatalf("event count = %d, want %d", report.Verification.EventCount, len(events))
			}
		})
	}
}

func TestCompatDriverStopDoesNotDuplicateFinish(t *testing.T) {
	c, closeDriver := newClient(t)
	defer closeDriver()
	run := createAndStart(t, c, []string{"/bin/sh", "-c", "sleep 2"}, false)
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "stop", Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	got := waitTerminal(t, c, run.ID)
	if got.Status != "stopped" {
		t.Fatalf("status=%q", got.Status)
	}
	report := waitEvidence(t, c, run.ID)
	allEvents, err := c.Events(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if finish := count(allEvents, "run/finish"); finish != 1 {
		t.Fatalf("run/finish count=%d events=%#v", finish, allEvents)
	}
	if report.Verification == nil || report.Verification.EventCount != uint64(len(allEvents)) {
		t.Fatalf("verification event count does not cover drained events: %#v", report.Verification)
	}
}

func TestCompatDriverDurableSealBindsVerificationAndManifest(t *testing.T) {
	workloads := t.TempDir()
	dataDir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	driver := controlplane.NewCompatDriver(compat.New(compat.Config{RootDir: workloads}))
	if err := driver.ConfigureManifest(dataDir, privateKey); err != nil {
		t.Fatal(err)
	}
	factory := func(run api.Run) (api.EventLog, error) {
		return appender.Open(filepath.Join(dataDir, "runs", run.ID, "tracked-events.jsonl"))
	}
	store := api.NewStoreWithDependencies(factory, driver)
	if err := driver.BindStore(store); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.NewHandler(store))
	defer server.Close()
	defer func() {
		if err := driver.Close(); err != nil {
			t.Error(err)
		}
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()
	c := client.New(server.URL)

	run := createAndStart(t, c, []string{"/bin/sh", "-c", "printf durable"}, false)
	if got := waitTerminal(t, c, run.ID); got.Status != "completed" {
		t.Fatalf("status=%q", got.Status)
	}
	report := waitEvidence(t, c, run.ID)
	if report.Verification == nil || report.Verification.Status != "ineligible" {
		t.Fatalf("unexpected evidence report: %#v", report)
	}
	allEvents, err := c.Events(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if allEvents[len(allEvents)-1].Type != "run/finish" {
		t.Fatalf("last event = %q", allEvents[len(allEvents)-1].Type)
	}
	if report.Verification.EventCount != uint64(len(allEvents)) {
		t.Fatalf("event count = %d, want %d", report.Verification.EventCount, len(allEvents))
	}
	sealed, err := appender.Open(filepath.Join(dataDir, "runs", run.ID, "tracked-events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sealed.Close() }()
	if !sealed.Sealed() {
		t.Fatal("durable log is not sealed")
	}
	if report.Verification.TrackedEventChainHead != sealed.HashHead() {
		t.Fatalf("reported chain head = %q, log head = %q", report.Verification.TrackedEventChainHead, sealed.HashHead())
	}
	manifestBytes, err := os.ReadFile(filepath.Join(dataDir, "runs", run.ID, "evidence-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidence.RunEvidenceManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := evidence.VerifyManifestSignature(manifest, publicKey); err != nil {
		t.Fatalf("manifest signature invalid: %v", err)
	}
	if manifest.TrackedEventChainHead != sealed.HashHead() {
		t.Fatalf("manifest chain head = %q, log head = %q", manifest.TrackedEventChainHead, sealed.HashHead())
	}
	if _, err := sealed.Append(events.TrackedEvent{Type: "session/end-seed", Data: json.RawMessage(`{}`)}); !errors.Is(err, appender.ErrSealed) {
		t.Fatalf("late append error = %v, want ErrSealed", err)
	}
	if _, err := store.AppendEvent(run.ID, events.TrackedEvent{Type: "session/end-seed", Data: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("store accepted a late append on a sealed run")
	}
}

func TestCompatDriverDurableStopCoversDrainedEvents(t *testing.T) {
	workloads := t.TempDir()
	dataDir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	driver := controlplane.NewCompatDriver(compat.New(compat.Config{RootDir: workloads}))
	if err := driver.ConfigureManifest(dataDir, privateKey); err != nil {
		t.Fatal(err)
	}
	factory := func(run api.Run) (api.EventLog, error) {
		return appender.Open(filepath.Join(dataDir, "runs", run.ID, "tracked-events.jsonl"))
	}
	store := api.NewStoreWithDependencies(factory, driver)
	if err := driver.BindStore(store); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.NewHandler(store))
	defer server.Close()
	defer func() {
		if err := driver.Close(); err != nil {
			t.Error(err)
		}
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()
	c := client.New(server.URL)

	run := createAndStart(t, c, []string{"/bin/sh", "-c", "sleep 2"}, false)
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "stop", Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if got := waitTerminal(t, c, run.ID); got.Status != "stopped" {
		t.Fatalf("status=%q", got.Status)
	}
	report := waitEvidence(t, c, run.ID)
	allEvents, err := c.Events(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if finish := count(allEvents, "run/finish"); finish != 1 {
		t.Fatalf("run/finish count=%d events=%#v", finish, allEvents)
	}
	if report.Verification == nil || report.Verification.EventCount != uint64(len(allEvents)) {
		t.Fatalf("verification event count does not cover drained events: %#v", report.Verification)
	}
}

func TestCompatDriverRestartValidatesPersistedBundles(t *testing.T) {
	workloads := t.TempDir()
	dataDir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	driver := controlplane.NewCompatDriver(compat.New(compat.Config{RootDir: workloads}))
	if err := driver.ConfigureManifest(dataDir, privateKey); err != nil {
		t.Fatal(err)
	}
	factory := func(run api.Run) (api.EventLog, error) {
		return appender.Open(filepath.Join(dataDir, "runs", run.ID, "tracked-events.jsonl"))
	}
	store, err := api.OpenStore(dataDir, factory, driver)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.BindStore(store); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.NewHandler(store))
	c := client.New(server.URL)
	run := createAndStart(t, c, []string{"/bin/sh", "-c", "printf restarted"}, false)
	if got := waitTerminal(t, c, run.ID); got.Status != "completed" {
		t.Fatalf("status=%q", got.Status)
	}
	report := waitEvidence(t, c, run.ID)
	exported, err := c.ExportEvidence(context.Background(), run.ID)
	if err != nil || len(exported) == 0 {
		t.Fatalf("export: %v", err)
	}
	server.Close()
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restarted := controlplane.NewCompatDriver(compat.New(compat.Config{RootDir: workloads}))
	if err := restarted.ConfigureManifest(dataDir, privateKey); err != nil {
		t.Fatal(err)
	}
	restored, err := api.OpenStore(dataDir, factory, restarted)
	if err != nil {
		t.Fatalf("OpenStore after restart: %v", err)
	}
	if err := restarted.BindStore(restored); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ValidatePersistedBundles(); err != nil {
		t.Fatalf("persisted bundle validation: %v", err)
	}
	defer func() {
		_ = restarted.Close()
		_ = restored.Close()
	}()
	var got api.Run
	for _, candidate := range restored.Runs() {
		if candidate.ID == run.ID {
			got = candidate
		}
	}
	if got.Status != "completed" {
		t.Fatalf("restored run = %#v", got)
	}
	restoredReport, ok := restored.Evidence(run.ID)
	if !ok || restoredReport.Verification == nil || restoredReport.Verification.TrackedEventChainHead != report.Verification.TrackedEventChainHead {
		t.Fatalf("restored evidence = %#v ok=%v", restoredReport, ok)
	}
	if manifestBytes, err := os.ReadFile(filepath.Join(dataDir, "runs", run.ID, "evidence-manifest.json")); err != nil {
		t.Fatal(err)
	} else {
		var manifest evidence.RunEvidenceManifest
		if err := json.Unmarshal(manifestBytes, &manifest); err != nil || evidence.VerifyManifestSignature(manifest, publicKey) != nil {
			t.Fatalf("manifest invalid: %v", err)
		}
	}
	if bundleBytes, err := restored.ExportEvidence(run.ID); err != nil || !bytes.Equal(bundleBytes, exported) {
		t.Fatalf("restored export err=%v", err)
	}
}

func produceDurableRun(t *testing.T) (dataDir, workloads string, privateKey ed25519.PrivateKey, runID string) {
	t.Helper()
	workloads = t.TempDir()
	dataDir = t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	driver := controlplane.NewCompatDriver(compat.New(compat.Config{RootDir: workloads}))
	if err := driver.ConfigureManifest(dataDir, privateKey); err != nil {
		t.Fatal(err)
	}
	factory := func(run api.Run) (api.EventLog, error) {
		return appender.Open(filepath.Join(dataDir, "runs", run.ID, "tracked-events.jsonl"))
	}
	store, err := api.OpenStore(dataDir, factory, driver)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.BindStore(store); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.NewHandler(store))
	c := client.New(server.URL)
	run := createAndStart(t, c, []string{"/bin/sh", "-c", "printf durable"}, false)
	if got := waitTerminal(t, c, run.ID); got.Status != "completed" {
		t.Fatalf("status=%q", got.Status)
	}
	waitEvidence(t, c, run.ID)
	server.Close()
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return dataDir, workloads, privateKey, run.ID
}

func reopenDurable(t *testing.T, dataDir, workloads string, privateKey ed25519.PrivateKey) (*api.Store, *controlplane.CompatDriver, error) {
	t.Helper()
	driver := controlplane.NewCompatDriver(compat.New(compat.Config{RootDir: workloads}))
	if err := driver.ConfigureManifest(dataDir, privateKey); err != nil {
		t.Fatal(err)
	}
	factory := func(run api.Run) (api.EventLog, error) {
		return appender.Open(filepath.Join(dataDir, "runs", run.ID, "tracked-events.jsonl"))
	}
	store, err := api.OpenStore(dataDir, factory, driver)
	if err != nil {
		return nil, nil, err
	}
	if err := driver.BindStore(store); err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	if err := driver.ValidatePersistedBundles(); err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	return store, driver, nil
}

func TestRestartRejectsTamperedPersistedState(t *testing.T) {
	reseal := func(t *testing.T, dataDir, runID string) {
		t.Helper()
		path := filepath.Join(dataDir, "runs", runID, "tracked-events.jsonl")
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		_, head, err := appender.ValidateFrames(content)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".sealed", []byte(head+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name    string
		corrupt func(t *testing.T, dataDir, runID string)
	}{
		{"live trajectory mutated and resealed", func(t *testing.T, dataDir, runID string) {
			path := filepath.Join(dataDir, "runs", runID, "tracked-events.jsonl")
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mutated := bytes.Replace(content, []byte(`"status":"completed"`), []byte(`"status":"completeD"`), 1)
			if bytes.Equal(mutated, content) {
				t.Fatal("trajectory mutation did not apply")
			}
			if err := os.WriteFile(path, mutated, 0o600); err != nil {
				t.Fatal(err)
			}
			reseal(t, dataDir, runID)
		}},
		{"catalog spec mutated", func(t *testing.T, dataDir, runID string) {
			statePath := filepath.Join(dataDir, "runs", runID, "state.json")
			raw, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}
			var state map[string]any
			if err := json.Unmarshal(raw, &state); err != nil {
				t.Fatal(err)
			}
			state["run"].(map[string]any)["spec"].(map[string]any)["harness"] = "tampered"
			encoded, _ := json.Marshal(state)
			if err := os.WriteFile(statePath, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"stored verification mutated", func(t *testing.T, dataDir, runID string) {
			statePath := filepath.Join(dataDir, "runs", runID, "state.json")
			raw, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}
			var state map[string]any
			if err := json.Unmarshal(raw, &state); err != nil {
				t.Fatal(err)
			}
			state["evidence"].(map[string]any)["verification"].(map[string]any)["eligible"] = true
			encoded, _ := json.Marshal(state)
			if err := os.WriteFile(statePath, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"disk manifest mutated", func(t *testing.T, dataDir, runID string) {
			path := filepath.Join(dataDir, "runs", runID, "evidence-manifest.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var manifest map[string]any
			if err := json.Unmarshal(raw, &manifest); err != nil {
				t.Fatal(err)
			}
			manifest["runId"] = "run-forged"
			encoded, _ := json.Marshal(manifest)
			if err := os.WriteFile(path, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"bundle replaced by symlink", func(t *testing.T, dataDir, runID string) {
			path := filepath.Join(dataDir, "runs", runID, "evidence-bundle.json")
			target := filepath.Join(dataDir, "runs", runID, "state.json")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"manifest replaced by symlink", func(t *testing.T, dataDir, runID string) {
			path := filepath.Join(dataDir, "runs", runID, "evidence-manifest.json")
			target := filepath.Join(dataDir, "runs", runID, "state.json")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir, workloads, privateKey, runID := produceDurableRun(t)
			tc.corrupt(t, dataDir, runID)
			store, driver, err := reopenDurable(t, dataDir, workloads, privateKey)
			if err == nil {
				_ = store.Close()
				_ = driver.Close()
				t.Fatal("tampered persisted state was accepted")
			}
		})
	}
}

func TestRestartRejectsOversizedPersistedEvidence(t *testing.T) {
	dataDir, workloads, privateKey, runID := produceDurableRun(t)
	path := filepath.Join(dataDir, "runs", runID, "evidence-bundle.json")
	if err := os.WriteFile(path, make([]byte, (64<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	store, driver, err := reopenDurable(t, dataDir, workloads, privateKey)
	if err == nil {
		_ = store.Close()
		_ = driver.Close()
		t.Fatal("oversized persisted evidence was accepted")
	}
	if !strings.Contains(err.Error(), "exceeding") {
		t.Fatalf("err=%v", err)
	}
}

func TestRestartSkipsUnpublishedFailedRun(t *testing.T) {
	dataDir, workloads, privateKey, runID := produceDurableRun(t)
	dir := filepath.Join(dataDir, "runs", runID)
	stateRaw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(stateRaw, &state); err != nil {
		t.Fatal(err)
	}
	failedID := "run-failedunpublished"
	other := filepath.Join(dataDir, "runs", failedID)
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tracked-events.jsonl", "tracked-events.jsonl.sealed"} {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(other, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state["run"].(map[string]any)["id"] = failedID
	state["run"].(map[string]any)["status"] = "failed"
	state["evidence"].(map[string]any)["runId"] = failedID
	state["evidence"].(map[string]any)["verification"] = map[string]any{"status": "verification_error", "eligible": false, "summary": "evidence finalization failed", "checkedAt": "2026-01-01T00:00:00Z"}
	state["idempotency"] = map[string]any{}
	encoded, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(other, "state.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	store, driver, err := reopenDurable(t, dataDir, workloads, privateKey)
	if err != nil {
		t.Fatalf("restart with unpublished failed run: %v", err)
	}
	defer func() {
		_ = driver.Close()
		_ = store.Close()
	}()
	report, ok := store.Evidence(failedID)
	if !ok || report.Verification == nil || report.Verification.Status != "verification_error" || report.Verification.Eligible {
		t.Fatalf("unpublished run evidence = %#v", report.Verification)
	}
}

func TestCompatDriverRejectsVerifiedRun(t *testing.T) {
	c, closeDriver := newClient(t)
	defer closeDriver()
	config, _ := json.Marshal(map[string]any{"type": "compat/local-process-v1", "command": []string{"/bin/sh", "-c", "true"}})
	_, err := c.CreateRun(context.Background(), client.CreateRunRequest{Spec: client.RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "compat-local-process", Verified: true, Parameters: map[string]json.RawMessage{"backendConfig": config}}})
	apiErr, ok := err.(*client.APIError)
	if !ok || apiErr.Code != "execution" {
		t.Fatalf("error=%v", err)
	}
}

func TestCompatDriverRetainsEvidenceAfterCompletionAndShutdown(t *testing.T) {
	root := t.TempDir()
	driver := controlplane.NewCompatDriver(compat.New(compat.Config{RootDir: root}))
	store := api.NewStoreWithRunDriver(driver)
	if err := driver.BindStore(store); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.NewHandler(store))
	c := client.New(server.URL)
	run := createAndStart(t, c, []string{"/bin/sh", "-c", "printf retained"}, false)
	if got := waitTerminal(t, c, run.ID); got.Status != "completed" {
		t.Fatalf("status=%q", got.Status)
	}
	server.Close()
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("run directories=%v err=%v", entries, err)
	}
	for _, name := range []string{"raw-records.bin", "stdout.log", "stderr.log"} {
		if _, err := os.Stat(filepath.Join(root, entries[0].Name(), name)); err != nil {
			t.Fatalf("retained %s: %v", name, err)
		}
	}
}

func newClient(t *testing.T) (*client.Client, func()) {
	t.Helper()
	driver := controlplane.NewCompatDriver(compat.New(compat.Config{RootDir: t.TempDir()}))
	store := api.NewStoreWithRunDriver(driver)
	if err := driver.BindStore(store); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.NewHandler(store))
	return client.New(server.URL), func() {
		server.Close()
		if err := driver.Close(); err != nil {
			t.Error(err)
		}
	}
}

func createAndStart(t *testing.T, c *client.Client, command []string, verified bool) client.Run {
	t.Helper()
	config, err := json.Marshal(map[string]any{"type": "compat/local-process-v1", "command": command})
	if err != nil {
		t.Fatal(err)
	}
	run, err := c.CreateRun(context.Background(), client.CreateRunRequest{Spec: client.RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "compat-local-process", Verified: verified, Parameters: map[string]json.RawMessage{"backendConfig": config}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	return run
}

func waitTerminal(t *testing.T, c *client.Client, id string) client.Run {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		run, err := c.GetRun(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if run.Status == "completed" || run.Status == "failed" || run.Status == "stopped" {
			return run
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("run %s did not reach a terminal status", id)
	return client.Run{}
}

func waitEvidence(t *testing.T, c *client.Client, id string) client.EvidenceReport {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		report, err := c.Evidence(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if report.Verification != nil {
			return report
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("run %s did not record a verification result", id)
	return client.EvidenceReport{}
}

func count(events []events.TrackedEvent, typ string) int {
	n := 0
	for _, event := range events {
		if event.Type == typ {
			n++
		}
	}
	return n
}
