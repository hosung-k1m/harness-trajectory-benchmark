package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/appender"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/client"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

func TestDurableEventLogFactoryRecoversSequence(t *testing.T) {
	factory, err := durableEventLogFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run := api.Run{ID: "run-000001"}
	first, err := factory(run)
	if err != nil {
		t.Fatal(err)
	}
	appended, err := first.Append(seed())
	if err != nil {
		t.Fatal(err)
	}
	if appended.Seq != 1 {
		t.Fatalf("first sequence = %d, want 1", appended.Seq)
	}
	if err := first.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}

	second, err := factory(run)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.(io.Closer).Close() })
	appended, err = second.Append(seed())
	if err != nil {
		t.Fatal(err)
	}
	if appended.Seq != 2 {
		t.Fatalf("recovered sequence = %d, want 2", appended.Seq)
	}
}

func TestDurableEventLogFactoryRejectsUnsafeRunIDs(t *testing.T) {
	factory, err := durableEventLogFactory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "../outside", "run/child", "run space", "Run-000001"} {
		t.Run(id, func(t *testing.T) {
			if _, err := factory(api.Run{ID: id}); err == nil {
				t.Fatal("factory accepted unsafe ID")
			}
		})
	}
}

func TestSanitizeRunID(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want string
	}{
		{"run-000001", "run-000001"},
		{"a0-z", "a0-z"},
		{"run_1", ""},
	} {
		t.Run(tc.id, func(t *testing.T) {
			got, err := sanitizeRunID(tc.id)
			if tc.want == "" {
				if err == nil {
					t.Fatal("sanitizeRunID accepted invalid ID")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("sanitizeRunID(%q) = %q, %v", tc.id, got, err)
			}
		})
	}
}

func TestValidateListenAddressRequiresLoopback(t *testing.T) {
	for _, tc := range []struct {
		address string
		valid   bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"localhost:8080", true},
		{"0.0.0.0:8080", false},
		{"[::]:8080", false},
		{":8080", false},
		{"invalid", false},
	} {
		t.Run(tc.address, func(t *testing.T) {
			if err := validateListenAddress(tc.address); (err == nil) != tc.valid {
				t.Fatalf("validateListenAddress(%q) = %v", tc.address, err)
			}
		})
	}
}

func TestDevelopmentSigningKeyPersistsAndRejectsMismatchedPublicKey(t *testing.T) {
	root := t.TempDir()
	first, err := developmentSigningKey(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := developmentSigningKey(root)
	if err != nil || string(first) != string(second) {
		t.Fatalf("development signing key changed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "dev-signing-key.ed25519.pub"), make([]byte, ed25519.PublicKeySize), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := developmentSigningKey(root); err == nil {
		t.Fatal("accepted mismatched development public key")
	}
}

func seed() events.TrackedEvent {
	return events.TrackedEvent{Type: "session/end-seed", Data: json.RawMessage(`{}`)}
}

func TestControlPlaneEndToEndDurableCompatibilityRun(t *testing.T) {
	root := t.TempDir()
	store, driver, err := newControlPlane(root)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.NewHandler(store))
	defer server.Close()
	defer store.Close()
	defer driver.Close()

	c := client.New(server.URL)
	config := json.RawMessage(`{"type":"compat/local-process-v1","command":["/bin/sh","-c","printf p1-out; printf p1-err >&2"]}`)
	created, err := c.CreateRun(context.Background(), client.CreateRunRequest{Spec: client.RunSpec{
		SchemaVersion: "v1", Harness: "harness", Suite: "suite", Backend: "compat-local-process",
		Parameters: map[string]json.RawMessage{"backendConfig": config},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lifecycle(context.Background(), created.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		run, err := c.GetRun(context.Background(), created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if run.Status == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run remained %q", run.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}

	trajectory, err := c.Events(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"run/start": false, "process/exec": false, "process/exit": false, "stdio/chunk": false, "sensor/stop": false, "run/finish": false}
	for i, event := range trajectory {
		if event.Seq != uint64(i+1) {
			t.Fatalf("event %d has sequence %d", i, event.Seq)
		}
		if _, ok := want[event.Type]; ok {
			want[event.Type] = true
		}
	}
	for typ, seen := range want {
		if !seen {
			t.Fatalf("missing %s from trajectory", typ)
		}
	}
	deadline = time.Now().Add(5 * time.Second)
	var report client.EvidenceReport
	for {
		report, err = c.Evidence(context.Background(), created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if report.Verification != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("evidence report = %#v", report)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if report.Verification.Status != "ineligible" || report.Verification.Eligible {
		t.Fatalf("evidence report = %#v", report)
	}
	if report.Verification.EventCount != uint64(len(trajectory)) || report.Verification.TrackedEventChainHead == "" {
		t.Fatalf("evidence verification = %#v", report.Verification)
	}
	exportedBundle, err := c.ExportEvidence(context.Background(), created.ID)
	if err != nil || len(exportedBundle) == 0 {
		t.Fatalf("bundle export: %v", err)
	}
	response, err := http.Get(server.URL + "/web/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("web status = %d", response.StatusCode)
	}

	path := filepath.Join(root, "runs", created.ID, "tracked-events.jsonl")
	frames, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("durable trajectory: %v", err)
	}
	exported, err := c.ExportTrajectory(context.Background(), created.ID)
	if err != nil || string(exported) != string(frames) {
		t.Fatalf("export is not byte-exact: err=%v", err)
	}
	workloads, err := os.ReadDir(filepath.Join(root, "workloads"))
	if err != nil || len(workloads) != 1 {
		t.Fatalf("retained workloads=%v err=%v", workloads, err)
	}
	if _, err := os.Stat(filepath.Join(root, "workloads", workloads[0].Name(), "raw-records.bin")); err != nil {
		t.Fatalf("retained raw evidence: %v", err)
	}
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(root, "runs", created.ID, "evidence-manifest.json"))
	if err != nil {
		t.Fatalf("signed manifest: %v", err)
	}
	var manifest evidence.RunEvidenceManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	publicKey, err := os.ReadFile(filepath.Join(root, "dev-signing-key.ed25519.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := evidence.VerifyManifestSignature(manifest, ed25519.PublicKey(publicKey)); err != nil {
		t.Fatalf("manifest signature: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := appender.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if len(recovered.Snapshot()) != len(trajectory) {
		t.Fatalf("recovered %d events, want %d", len(recovered.Snapshot()), len(trajectory))
	}
	if _, err := recovered.Append(seed()); !errors.Is(err, appender.ErrSealed) {
		t.Fatalf("late append error=%v, want sealed", err)
	}
}
