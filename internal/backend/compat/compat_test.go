package compat

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
)

func testSpec(id string) backend.RunSpec {
	d := backend.SHA256Hex([]byte(id))
	return backend.RunSpec{SchemaVersion: "v1", RunID: id, HarnessDigest: d, BenchmarkDigest: d, PolicyDigest: d}
}

func testPlan(t *testing.T, command ...string) backend.ObservationPlan {
	t.Helper()
	raw, err := json.Marshal(workloadConfig{Type: "compat/local-process-v1", Command: command})
	if err != nil {
		t.Fatal(err)
	}
	return backend.ObservationPlan{SchemaVersion: "v1", OpaqueTrafficPolicy: backend.OpaqueTrafficAllow, SensorConfigs: []json.RawMessage{raw}}
}

func TestLifecycleCapturesImmutableRawEvidence(t *testing.T) {
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("lifecycle"), testPlan(t, "sh", "-c", "printf out; printf err >&2"))
	if err != nil {
		t.Fatal(err)
	}
	r := h.(*run)
	if filepath.Dir(r.dir) == "" {
		t.Fatal("prepare did not allocate a run directory")
	}
	started, err := b.Start(context.Background(), h)
	if err != nil || started.RunID != h.RunID() {
		t.Fatalf("Start() = %#v, %v", started, err)
	}
	exit, err := b.Wait(context.Background(), h)
	if err != nil || exit.Code != 0 {
		t.Fatalf("Wait() = %#v, %v", exit, err)
	}
	snapshot, err := b.Snapshot(context.Background(), h)
	if err != nil || snapshot.Digest == "" {
		t.Fatalf("Snapshot() = %#v, %v", snapshot, err)
	}
	evidenceOut, health, err := b.FinalizeEvidence(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if health.Sources[0].PlaintextFailures != 1 || health.Sources[0].ObservedEnd == 0 {
		t.Fatalf("health = %#v", health)
	}
	if len(evidenceOut.ArtifactIDs) < 3 || evidenceOut.RawChainHeads[sensorID] == "" {
		t.Fatalf("evidence = %#v", evidenceOut)
	}
	if got, err := os.ReadFile(r.stdoutPath); err != nil || string(got) != "out" {
		t.Fatalf("stdout = %q, %v", got, err)
	}
	if got, err := os.ReadFile(r.stderrPath); err != nil || string(got) != "err" {
		t.Fatalf("stderr = %q, %v", got, err)
	}
	head, err := evidence.ValidateChain(r.records, r.seed)
	if err != nil || head != evidenceOut.RawChainHeads[sensorID] {
		t.Fatalf("raw chain = %q, %v", head, err)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("run directory still exists: %v", err)
	}
}

func TestLifecycleRejectsInvalidStatesAndHandles(t *testing.T) {
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("states"), testPlan(t, "sh", "-c", "exit 7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err == nil {
		t.Fatal("Wait before Start succeeded")
	}
	if _, _, err := b.FinalizeEvidence(context.Background(), h); err == nil {
		t.Fatal("Finalize before Start succeeded")
	}
	if err := b.Stop(context.Background(), h, "not-started"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err == nil {
		t.Fatal("Start after Stop succeeded")
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Snapshot(context.Background(), h); err == nil {
		t.Fatal("destroyed handle accepted")
	}
	if _, err := b.Start(context.Background(), fakeHandle("bad")); err == nil {
		t.Fatal("foreign handle accepted")
	}
}

func TestPrepareValidationAndHonestCapabilities(t *testing.T) {
	b := New(Config{RootDir: t.TempDir()})
	base := testPlan(t, "sh", "-c", "true")
	cases := []struct {
		name string
		spec backend.RunSpec
		plan backend.ObservationPlan
	}{
		{"missing-config", testSpec("missing"), backend.ObservationPlan{SchemaVersion: "v1", OpaqueTrafficPolicy: backend.OpaqueTrafficAllow}},
		{"unknown-field", testSpec("unknown"), backend.ObservationPlan{SchemaVersion: "v1", OpaqueTrafficPolicy: backend.OpaqueTrafficAllow, SensorConfigs: []json.RawMessage{json.RawMessage(`{"type":"compat/local-process-v1","command":["true"],"extra":1}`)}}},
		{"verified", func() backend.RunSpec { s := testSpec("verified"); s.Verified = true; return s }(), base},
		{"unsupported-requirement", testSpec("network"), func() backend.ObservationPlan {
			p := base
			p.Requirements = []backend.ObservationRequirement{{EventFamily: "network/plaintext", MinimumObservation: backend.ObservationBestEffort, MinimumEnforcement: backend.EnforcementAuditOnly, Retention: "raw"}}
			return p
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := b.Prepare(context.Background(), tc.spec, tc.plan); err == nil {
				t.Fatal("Prepare succeeded")
			}
		})
	}
	m, err := b.Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range m.Capabilities {
		if c.EventFamily == "network/plaintext" && c.Observation != backend.ObservationUnsupported {
			t.Fatalf("plaintext capability dishonest: %#v", c)
		}
	}
}

func TestWaitCancellationAndStop(t *testing.T) {
	b := New(Config{RootDir: t.TempDir()})
	h, err := b.Prepare(context.Background(), testSpec("cancel"), testPlan(t, "sh", "-c", "sleep 5"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Start(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := b.Wait(ctx, h); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait cancellation = %v", err)
	}
	if err := b.Stop(context.Background(), h, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Wait(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if err := b.Destroy(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

type fakeHandle string

func (f fakeHandle) RunID() string { return string(f) }

func TestDecodeConfigRejectsTrailingAndEmptyArgs(t *testing.T) {
	cases := []string{
		`{"type":"compat/local-process-v1","command":["true"]} {}`,
		`{"type":"compat/local-process-v1","command":["true",""]}`,
	}
	for _, raw := range cases {
		t.Run(strings.ReplaceAll(raw, " ", "_"), func(t *testing.T) {
			if _, err := decodeConfig([]json.RawMessage{json.RawMessage(raw)}); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}

func TestCaptureFailureIsAccounted(t *testing.T) {
	r := &run{stdoutPath: t.TempDir(), rawPath: filepath.Join(t.TempDir(), "raw"), done: make(chan struct{})}
	if n, err := (runWriter{run: r, path: r.stdoutPath, kind: "workload/stdout"}).Write([]byte("output")); err != nil || n != len("output") {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	r.mu.Lock()
	drops := r.captureDrops
	r.mu.Unlock()
	if drops != 1 {
		t.Fatalf("capture drops = %d, want 1", drops)
	}
}
