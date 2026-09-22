package main

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
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/client"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

func TestRunHelpVersionAndSchemaOutput(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"--version"}, {"schema", "show"}} {
		var out, err bytes.Buffer
		if got := run(args, &out, &err); got != exitOK {
			t.Fatalf("%v got %d: %s", args, got, err.String())
		}
		if out.Len() == 0 || err.Len() != 0 {
			t.Fatalf("%v output routing out=%q err=%q", args, out.String(), err.String())
		}
	}
}

func TestTrajectoryAndEvidenceCommandsUseControlPlane(t *testing.T) {
	store := api.NewStore()
	h := api.NewHandler(store)
	s := httptest.NewServer(h)
	defer s.Close()
	previous, hadPrevious := os.LookupEnv("BENCHMARK_API_URL")
	if err := os.Setenv("BENCHMARK_API_URL", s.URL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadPrevious {
			_ = os.Setenv("BENCHMARK_API_URL", previous)
		} else {
			_ = os.Unsetenv("BENCHMARK_API_URL")
		}
	})

	var out, stderr bytes.Buffer
	if got := run([]string{"run", "create", "--harness", "h", "--suite", "s", "--backend", "b"}, &out, &stderr); got != exitOK {
		t.Fatalf("create exit=%d stderr=%s", got, stderr.String())
	}
	var created client.Run
	if err := json.Unmarshal(out.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendEvent(created.ID, events.TrackedEvent{Type: "run/start", Data: []byte(`{}`), Ignorable: true}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"trajectory", "get", created.ID}, {"trajectory", "stream", created.ID}, {"trajectory", "export", created.ID}, {"evidence", "inspect", created.ID}} {
		out.Reset()
		stderr.Reset()
		if got := run(args, &out, &stderr); got != exitOK || out.Len() == 0 || stderr.Len() != 0 {
			t.Fatalf("%v exit=%d stdout=%q stderr=%q", args, got, out.String(), stderr.String())
		}
	}
	out.Reset()
	stderr.Reset()
	if got := run([]string{"evidence", "export", created.ID}, &out, &stderr); got != exitExecution || out.Len() != 0 || !strings.Contains(stderr.String(), "persistent control-plane store") {
		t.Fatalf("unsupported export exit=%d stdout=%q stderr=%q", got, out.String(), stderr.String())
	}
	out.Reset()
	stderr.Reset()
	if got := run([]string{"evidence", "verify", created.ID}, &out, &stderr); got != exitVerification || !strings.Contains(out.String(), `"not_collected"`) || !strings.Contains(stderr.String(), `"verification"`) {
		t.Fatalf("unverified exit=%d stdout=%q stderr=%q", got, out.String(), stderr.String())
	}
}

func TestResultMapsTypedErrorCodeToStableExitCode(t *testing.T) {
	for code, want := range map[string]int{"validation": exitValidation, "execution": exitExecution, "policy": exitPolicy, "telemetry": exitTelemetry, "verification": exitVerification, "infrastructure": exitInfrastructure} {
		var out, stderr bytes.Buffer
		got := result(&out, &stderr, nil, &client.APIError{StatusCode: 400, Code: code, Message: "no"})
		if got != want {
			t.Fatalf("%s got %d want %d", code, got, want)
		}
		if out.Len() != 0 || !strings.Contains(stderr.String(), `"error":"`+code+`"`) {
			t.Fatalf("bad output for %s", code)
		}
	}
	var out, stderr bytes.Buffer
	if got := result(&out, &stderr, nil, errors.New("offline")); got != exitInfrastructure {
		t.Fatal(got)
	}
}

func TestReadParametersFileStrictObject(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "parameters.json")
	if err := os.WriteFile(valid, []byte(`{"command":["sh","-c","true"],"nested":{"enabled":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, input string
		want        bool
	}{
		{"valid", valid, true},
		{"array", writeParameterFixture(t, dir, "array", `[]`), false},
		{"trailing", writeParameterFixture(t, dir, "trailing", `{} {}`), false},
		{"duplicate", writeParameterFixture(t, dir, "duplicate", `{"x":1,"x":2}`), false},
		{"nested-duplicate", writeParameterFixture(t, dir, "nested-duplicate", `{"x":{"a":1,"a":2}}`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readParametersFile(tc.input, strings.NewReader(""))
			if (err == nil) != tc.want {
				t.Fatalf("parameters=%v err=%v", got, err)
			}
			if tc.want && string(got["command"]) != `["sh","-c","true"]` {
				t.Fatalf("parameters=%s", got["command"])
			}
		})
	}
}

func TestRunCreatePassesParametersAndVerified(t *testing.T) {
	store := api.NewStore()
	server := httptest.NewServer(api.NewHandler(store))
	defer server.Close()
	previous, hadPrevious := os.LookupEnv("BENCHMARK_API_URL")
	if err := os.Setenv("BENCHMARK_API_URL", server.URL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadPrevious {
			_ = os.Setenv("BENCHMARK_API_URL", previous)
		} else {
			_ = os.Unsetenv("BENCHMARK_API_URL")
		}
	})
	path := writeParameterFixture(t, t.TempDir(), "parameters", `{"command":["sh","-c","true"]}`)
	var out, stderr bytes.Buffer
	if got := run([]string{"run", "create", "--harness", "h", "--suite", "s", "--backend", "compat", "--parameters-file", path, "--verified"}, &out, &stderr); got != exitOK {
		t.Fatalf("exit=%d stderr=%s", got, stderr.String())
	}
	var created client.Run
	if err := json.Unmarshal(out.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !created.Spec.Verified || string(created.Spec.Parameters["command"]) != `["sh","-c","true"]` {
		t.Fatalf("created spec = %#v", created.Spec)
	}
}

func TestRunCreateDoesNotExposeInvalidParameterContents(t *testing.T) {
	secret := "do-not-print-this-secret"
	path := writeParameterFixture(t, t.TempDir(), "parameters", `{"token":"`+secret+`","token":"duplicate"}`)
	var out, stderr bytes.Buffer
	got := run([]string{"run", "create", "--harness", "h", "--suite", "s", "--backend", "compat", "--parameters-file", path}, &out, &stderr)
	if got != exitValidation || out.Len() != 0 || strings.Contains(stderr.String(), secret) {
		t.Fatalf("exit=%d stdout=%q stderr=%q", got, out.String(), stderr.String())
	}
}

func TestRunFollowStreamsUntilCompletionAndResumes(t *testing.T) {
	store := api.NewStore()
	server := httptest.NewServer(api.NewHandler(store))
	defer server.Close()
	t.Setenv("BENCHMARK_API_URL", server.URL)
	c := client.New(server.URL)
	runCreated, err := c.CreateRun(context.Background(), client.CreateRunRequest{Spec: client.RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lifecycle(context.Background(), runCreated.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = store.Complete(runCreated.ID, "completed", "exited")
	}()
	var out, diagnostics bytes.Buffer
	if code := run([]string{"run", "follow", runCreated.ID, "--timeout", "2s"}, &out, &diagnostics); code != exitOK {
		t.Fatalf("follow exit=%d stderr=%q", code, diagnostics.String())
	}
	if strings.Count(out.String(), `"seq":`) != 2 || !strings.Contains(out.String(), `"run/finish"`) {
		t.Fatalf("follow output=%q", out.String())
	}
	out.Reset()
	diagnostics.Reset()
	if code := run([]string{"run", "follow", runCreated.ID, "--from-seq", "1", "--timeout", "2s"}, &out, &diagnostics); code != exitOK || strings.Count(out.String(), `"seq":`) != 1 {
		t.Fatalf("resumed exit=%d stdout=%q stderr=%q", code, out.String(), diagnostics.String())
	}
}

func TestEvidenceValidateVerifiesBundleOffline(t *testing.T) {
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
	config, _ := json.Marshal(map[string]any{"type": "compat/local-process-v1", "command": []string{"/bin/sh", "-c", "printf cli"}})
	created, err := c.CreateRun(context.Background(), client.CreateRunRequest{Spec: client.RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "compat-local-process", Parameters: map[string]json.RawMessage{"backendConfig": config}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lifecycle(context.Background(), created.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		report, err := c.Evidence(context.Background(), created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if report.Verification != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("evidence was not published")
		}
		time.Sleep(10 * time.Millisecond)
	}
	exported, err := c.ExportEvidence(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, exported, 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(keyPath, publicKey, 0o600); err != nil {
		t.Fatal(err)
	}
	extractDir := filepath.Join(dir, "extract")
	var out, stderr bytes.Buffer
	if got := run([]string{"evidence", "validate", "--bundle", bundlePath, "--public-key", keyPath, "--extract", extractDir}, &out, &stderr); got != exitOK {
		t.Fatalf("validate exit=%d stdout=%q stderr=%q", got, out.String(), stderr.String())
	}
	var validation struct {
		IntegrityValid bool `json:"integrityValid"`
		Eligible       bool `json:"eligible"`
	}
	if err := json.Unmarshal(out.Bytes(), &validation); err != nil || !validation.IntegrityValid || validation.Eligible {
		t.Fatalf("validation result=%q err=%v", out.String(), err)
	}
	if _, err := os.Stat(filepath.Join(extractDir, "tracked-events.jsonl")); err != nil {
		t.Fatalf("extracted evidence missing: %v", err)
	}

	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(dir, "wrong.pub")
	if err := os.WriteFile(wrongPath, wrongPublic, 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	stderr.Reset()
	if got := run([]string{"evidence", "validate", "--bundle", bundlePath, "--public-key", wrongPath}, &out, &stderr); got != exitVerification {
		t.Fatalf("wrong key exit=%d stderr=%q", got, stderr.String())
	}
	out.Reset()
	stderr.Reset()
	if got := run([]string{"evidence", "validate", "--bundle", bundlePath}, &out, &stderr); got != exitValidation {
		t.Fatalf("missing args exit=%d", got)
	}
	out.Reset()
	stderr.Reset()
	if got := run([]string{"evidence", "validate", "--bundle", filepath.Join(dir, "missing.json"), "--public-key", keyPath}, &out, &stderr); got != exitInfrastructure {
		t.Fatalf("missing bundle exit=%d", got)
	}
}

func writeParameterFixture(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name+".json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
