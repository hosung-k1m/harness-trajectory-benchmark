package controlplane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/appender"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/backend/compat"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/bundle"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/llmnormalizer"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/plaintext"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/projection"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/replay"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/client"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

func TestMockHelperServer(t *testing.T) {
	if os.Getenv("HTB_MOCK_HELPER") != "1" {
		return
	}
	root := os.Getenv("HTB_MOCK_DATA_DIR")
	readyFile := os.Getenv("HTB_MOCK_READY_FILE")
	if root == "" || readyFile == "" {
		t.Fatal("HTB_MOCK_DATA_DIR and HTB_MOCK_READY_FILE are required")
	}
	keyBytes, err := os.ReadFile(filepath.Join(root, "dev-signing-key.ed25519"))
	if err != nil || len(keyBytes) != ed25519.PrivateKeySize {
		t.Fatalf("mock signing key: %v", err)
	}
	key := ed25519.PrivateKey(keyBytes)
	driver := newMockDriver(root, key)
	factory := func(run api.Run) (api.EventLog, error) {
		return appender.Open(filepath.Join(root, "runs", run.ID, "tracked-events.jsonl"))
	}
	store, err := api.OpenStore(root, factory, driver)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := driver.BindStore(store); err != nil {
		t.Fatalf("bind mock driver: %v", err)
	}
	validator := NewCompatDriver(compat.New(compat.Config{RootDir: filepath.Join(root, "workloads")}))
	if err := validator.ConfigureManifest(root, key); err != nil {
		t.Fatalf("configure validator: %v", err)
	}
	if err := validator.BindStore(store); err != nil {
		t.Fatalf("bind validator: %v", err)
	}
	if err := validator.ValidatePersistedBundles(); err != nil {
		t.Fatalf("persisted bundle validation: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: api.NewHandler(store), ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	if err := os.WriteFile(readyFile, []byte("http://"+listener.Addr().String()), 0o600); err != nil {
		t.Fatalf("write readiness: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("serve: %v", err)
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	_ = driver.Shutdown(shutdownCtx)
	_ = store.Close()
}

type cpServer struct {
	cmd      *exec.Cmd
	cancel   context.CancelFunc
	stderr   *bytes.Buffer
	waitCh   chan error
	stopOnce sync.Once
}

func (s *cpServer) stop(t *testing.T) {
	t.Helper()
	s.stopOnce.Do(func() {
		defer s.cancel()
		if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			s.cancel()
		}
		select {
		case err := <-s.waitCh:
			if err != nil {
				t.Fatalf("controlplane exited unexpectedly: %v stderr=%s", err, s.stderr.String())
			}
		case <-time.After(15 * time.Second):
			_ = s.cmd.Process.Kill()
			<-s.waitCh
			t.Fatalf("controlplane did not stop within deadline; stderr=%s", s.stderr.String())
		}
	})
}

type mockChild struct {
	cmd      *exec.Cmd
	cancel   context.CancelFunc
	url      string
	stderr   *bytes.Buffer
	waitCh   chan error
	stopOnce sync.Once
}

func startMockChild(t *testing.T, dataDir string) *mockChild {
	t.Helper()
	ready := filepath.Join(dataDir, "ready.url")
	if err := os.Remove(ready); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stderr := &bytes.Buffer{}
	self, err := os.Executable()
	if err != nil {
		cancel()
		t.Fatalf("resolve test binary: %v", err)
	}
	cmd := exec.CommandContext(ctx, self, "-test.run=^TestMockHelperServer$")
	cmd.Env = append(os.Environ(), "HTB_MOCK_HELPER=1", "HTB_MOCK_DATA_DIR="+dataDir, "HTB_MOCK_READY_FILE="+ready)
	cmd.Stdout = stderr
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start helper: %v", err)
	}
	child := &mockChild{cmd: cmd, cancel: cancel, stderr: stderr, waitCh: make(chan error, 1)}
	go func() { child.waitCh <- cmd.Wait() }()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(ready); err == nil && len(raw) > 0 {
			child.url = strings.TrimSpace(string(raw))
			return child
		}
		time.Sleep(25 * time.Millisecond)
	}
	child.stop(t)
	t.Fatalf("mock helper did not report readiness; stderr: %s", stderr.String())
	return nil
}

func (c *mockChild) stop(t *testing.T) {
	t.Helper()
	c.stopOnce.Do(func() {
		c.cancel()
		select {
		case <-c.waitCh:
		case <-time.After(10 * time.Second):
			_ = c.cmd.Process.Kill()
			<-c.waitCh
		}
	})
}

func e2eRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func e2eScratch(t *testing.T) string {
	t.Helper()
	scratch := filepath.Join(e2eRoot(t), "dist", "e2e")
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	return scratch
}

func e2eCLI(t *testing.T, benchmark, url string, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, benchmark, args...)
	cmd.Env = append(os.Environ(), "BENCHMARK_API_URL="+url)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return code, out.String(), errBuf.String()
}

func writeParamsFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func cliRunID(t *testing.T, out string) string {
	t.Helper()
	var run client.Run
	if err := json.Unmarshal([]byte(out), &run); err != nil || run.ID == "" {
		t.Fatalf("create output %q: %v", out, err)
	}
	return run.ID
}

func waitCLITerminal(t *testing.T, benchmark, url, id string) string {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		code, out, _ := e2eCLI(t, benchmark, url, "run", "status", id)
		if code == 0 {
			var run client.Run
			if json.Unmarshal([]byte(out), &run) == nil {
				switch run.Status {
				case "completed", "failed", "stopped":
					return run.Status
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("run %s did not reach a terminal status", id)
	return ""
}

func waitCLIEvidence(t *testing.T, benchmark, url, id string) client.EvidenceReport {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		code, out, _ := e2eCLI(t, benchmark, url, "evidence", "inspect", id)
		if code == 0 {
			var report client.EvidenceReport
			if json.Unmarshal([]byte(out), &report) == nil && report.Verification != nil {
				return report
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("run %s did not publish a verification result", id)
	return client.EvidenceReport{}
}

func decodeJSONL(t *testing.T, raw []byte) []events.TrackedEvent {
	t.Helper()
	var log []events.TrackedEvent
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event events.TrackedEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("decode trajectory line: %v", err)
		}
		log = append(log, event)
	}
	return log
}

func assertGapFreeSingleFinish(t *testing.T, log []events.TrackedEvent) {
	t.Helper()
	if len(log) == 0 {
		t.Fatal("empty trajectory")
	}
	finish := 0
	for i, event := range log {
		if event.Seq != uint64(i+1) {
			t.Fatalf("trajectory gap at index %d: seq=%d", i, event.Seq)
		}
		if event.Type == "run/finish" {
			finish++
			if i != len(log)-1 {
				t.Fatal("run/finish is not the final event")
			}
		}
	}
	if finish != 1 {
		t.Fatalf("run/finish count=%d", finish)
	}
}

func coverageFromEvents(t *testing.T, log []events.TrackedEvent) []evidence.NormalizedCoverage {
	t.Helper()
	var coverage []evidence.NormalizedCoverage
	for _, event := range log {
		var data struct {
			Source   events.Source   `json:"source"`
			Evidence events.Evidence `json:"evidence"`
		}
		if err := json.Unmarshal(event.Data, &data); err != nil {
			t.Fatalf("event %d observation data: %v", event.Seq, err)
		}
		if data.Evidence.RawRecordSHA256 == "" && data.Evidence.RawStreamID == "" {
			continue
		}
		coverage = append(coverage, evidence.NormalizedCoverage{
			Raw:     evidence.RawRange{SensorID: data.Source.SensorID, BootID: data.Source.BootID, Start: data.Evidence.RawSourceSeqStart, End: data.Evidence.RawSourceSeqEnd},
			EventID: strconv.FormatUint(event.Seq, 10),
		})
	}
	return coverage
}

func assertSourceSeqs(t *testing.T, event events.TrackedEvent, plaintextSeqs map[string]map[uint64]bool, direction string) {
	t.Helper()
	if len(event.SourceEventSeqs) == 0 {
		t.Fatalf("event %d (%s) has no sourceEventSeqs", event.Seq, event.Type)
	}
	for _, seq := range event.SourceEventSeqs {
		if seq >= event.Seq {
			t.Fatalf("event %d references future seq %d", event.Seq, seq)
		}
		if !plaintextSeqs[direction][seq] {
			t.Fatalf("event %d (%s) references seq %d which is not an %s plaintext event", event.Seq, event.Type, seq, direction)
		}
	}
}

func assertMockTrajectory(t *testing.T, log []events.TrackedEvent) {
	t.Helper()
	assembler := plaintext.NewAssembler()
	plaintextSeqs := map[string]map[uint64]bool{"egress": {}, "ingress": {}}
	expectedBodies := map[string]json.RawMessage{
		"model/request":      json.RawMessage(mockRequestLiteral),
		"model/stream-chunk": json.RawMessage(mockChunkLiteral),
		"model/response":     json.RawMessage(mockResponseLiteral),
	}
	usageEvents := 0
	modelEvents := 0
	for _, event := range log {
		if !events.IsObservationType(event.Type) {
			continue
		}
		var data struct {
			Source events.Source `json:"source"`
		}
		if err := json.Unmarshal(event.Data, &data); err != nil {
			t.Fatalf("event %d observation data: %v", event.Seq, err)
		}
		if data.Source.TrustDomain != "mock" || data.Source.Backend != "mock-data" {
			t.Fatalf("event %d source = %#v", event.Seq, data.Source)
		}
		switch event.Type {
		case "network/plaintext":
			var d struct {
				Details events.NetworkPlaintext `json:"details"`
			}
			if err := json.Unmarshal(event.Data, &d); err != nil {
				t.Fatal(err)
			}
			if d.Details.Capture.Verified {
				t.Fatalf("event %d claims verified capture", event.Seq)
			}
			if err := assembler.Add(d.Details); err != nil {
				t.Fatalf("event %d plaintext: %v", event.Seq, err)
			}
			plaintextSeqs[d.Details.Direction][event.Seq] = true
		case "model/request", "model/stream-chunk", "model/response":
			modelEvents++
			var d struct {
				Details events.OpenAICompatibleExchange `json:"details"`
			}
			if err := json.Unmarshal(event.Data, &d); err != nil {
				t.Fatal(err)
			}
			x := d.Details
			if x.Endpoint != mockEndpoint || x.Provider != llmnormalizer.ProviderOpenAICompatible || x.ProviderModel != "mock-model" || x.ModelExchangeID != "mock-exchange" {
				t.Fatalf("event %d exchange = %#v", event.Seq, x)
			}
			var gotBody, wantBody any
			if err := json.Unmarshal(x.Body, &gotBody); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(expectedBodies[event.Type], &wantBody); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotBody, wantBody) {
				t.Fatalf("event %d body = %s want %s", event.Seq, x.Body, expectedBodies[event.Type])
			}
			direction := "ingress"
			if event.Type == "model/request" {
				direction = "egress"
			}
			assertSourceSeqs(t, event, plaintextSeqs, direction)
		case "model/usage":
			usageEvents++
			var d struct {
				Details events.ModelUsage `json:"details"`
			}
			if err := json.Unmarshal(event.Data, &d); err != nil {
				t.Fatal(err)
			}
			u := d.Details
			if u.InputTokens == nil || *u.InputTokens != 7 || u.OutputTokens == nil || *u.OutputTokens != 3 || u.TotalTokens == nil || *u.TotalTokens != 10 {
				t.Fatalf("usage details = %#v", u)
			}
			if u.Quality.InputTokens != "provider_reported" || u.Quality.OutputTokens != "provider_reported" || u.Quality.TotalTokens != "provider_reported" {
				t.Fatalf("usage quality = %#v", u.Quality)
			}
			if u.CacheReadTokens != nil || u.CacheWriteTokens != nil || u.ReasoningTokens != nil {
				t.Fatalf("usage synthesized unavailable counters: %#v", u)
			}
			assertSourceSeqs(t, event, plaintextSeqs, "ingress")
		}
	}
	if usageEvents != 1 {
		t.Fatalf("model/usage count=%d", usageEvents)
	}
	if modelEvents != 3 {
		t.Fatalf("model event count=%d", modelEvents)
	}
	wantEgress, err := mockRequestWire(mockRequestLiteral)
	if err != nil {
		t.Fatal(err)
	}
	wantIngress, err := mockResponseWire(mockChunkLiteral + "\n" + mockResponseLiteral + "\n")
	if err != nil {
		t.Fatal(err)
	}
	for direction, want := range map[string][]byte{"egress": wantEgress, "ingress": wantIngress} {
		got, err := assembler.Bytes("mock-conn", "mock-stream", direction)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s stream bytes mismatch: %v", direction, err)
		}
		if !assembler.Closed("mock-conn", "mock-stream", direction) {
			t.Fatalf("%s stream not closed", direction)
		}
	}
}

func assertObservationRefs(t *testing.T, log []events.TrackedEvent, records []evidence.RawRecord) {
	t.Helper()
	byHash := map[string]evidence.RawRecord{}
	for _, record := range records {
		byHash[record.RecordSHA256] = record
	}
	for _, event := range log {
		if !events.IsObservationType(event.Type) {
			continue
		}
		var data struct {
			Evidence events.Evidence `json:"evidence"`
		}
		if err := json.Unmarshal(event.Data, &data); err != nil {
			t.Fatalf("event %d observation data: %v", event.Seq, err)
		}
		record, ok := byHash[data.Evidence.RawRecordSHA256]
		if !ok {
			t.Fatalf("event %d references unknown raw record %q", event.Seq, data.Evidence.RawRecordSHA256)
		}
		if data.Evidence.RawStreamID != record.SensorID+"/"+record.BootID || data.Evidence.RawSourceSeqStart != record.SourceSeq || data.Evidence.RawSourceSeqEnd != record.SourceSeq {
			t.Fatalf("event %d raw lineage = %#v", event.Seq, data.Evidence)
		}
	}
}

func TestPhase1MockEndToEnd(t *testing.T) {
	if os.Getenv("HTB_E2E") != "1" {
		t.Skip("subprocess E2E requires HTB_E2E=1 (see make test-e2e)")
	}
	root := e2eRoot(t)
	benchmark := filepath.Join(root, "dist", "e2e", "benchmark")
	if _, err := os.Stat(benchmark); err != nil {
		t.Fatalf("benchmark CLI binary missing; run make test-e2e: %v", err)
	}
	dataDir, err := os.MkdirTemp(e2eScratch(t), "mock-data-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("mock E2E data directory retained at %s", dataDir)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "dev-signing-key.ed25519"), privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	publicKeyPath := filepath.Join(dataDir, "dev-signing-key.ed25519.pub")
	if err := os.WriteFile(publicKeyPath, publicKey, 0o644); err != nil {
		t.Fatal(err)
	}

	child := startMockChild(t, dataDir)
	t.Cleanup(func() { child.stop(t) })
	url := child.url
	sdk := client.New(url)

	create := func(scenario, key string) (int, string, string) {
		params := writeParamsFile(t, dataDir, "params-"+scenario+".json", `{"scenario":"`+scenario+`"}`)
		return e2eCLI(t, benchmark, url, "run", "create", "--harness", "h", "--suite", "s", "--backend", "mock-data", "--idempotency-key", key, "--parameters-file", params)
	}

	code, _, stderr := e2eCLI(t, benchmark, url, "run", "create", "--harness", "h", "--suite", "s", "--backend", "mock-data", "--verified")
	if code == 0 || stderr == "" {
		t.Fatalf("verified mock create: code=%d stderr=%q", code, stderr)
	}

	code, createOut, createErr := create("clean", "mock-clean-create")
	if code != 0 {
		t.Fatalf("create clean: %d %s", code, createErr)
	}
	cleanID := cliRunID(t, createOut)
	code, replayOut, _ := create("clean", "mock-clean-create")
	if code != 0 || replayOut != createOut {
		t.Fatalf("create replay mismatch: code=%d out=%q want %q", code, replayOut, createOut)
	}
	code, startOut, startErr := e2eCLI(t, benchmark, url, "run", "start", cleanID, "--idempotency-key", "mock-clean-start")
	if code != 0 {
		t.Fatalf("start clean: %d %s", code, startErr)
	}
	code, startReplay, _ := e2eCLI(t, benchmark, url, "run", "start", cleanID, "--idempotency-key", "mock-clean-start")
	if code != 0 || startReplay != startOut {
		t.Fatalf("start replay mismatch: code=%d out=%q want %q", code, startReplay, startOut)
	}

	followCtx, followCancel := context.WithTimeout(context.Background(), 60*time.Second)
	followCmd := exec.CommandContext(followCtx, benchmark, "run", "follow", cleanID)
	followCmd.Env = append(os.Environ(), "BENCHMARK_API_URL="+url)
	followPipe, err := followCmd.StdoutPipe()
	if err != nil {
		followCancel()
		t.Fatal(err)
	}
	var followErrBuf bytes.Buffer
	followCmd.Stderr = &followErrBuf
	if err := followCmd.Start(); err != nil {
		followCancel()
		t.Fatalf("start follow: %v", err)
	}
	var followWaitOnce sync.Once
	var followWaitErr error
	waitFollow := func() error { followWaitOnce.Do(func() { followWaitErr = followCmd.Wait() }); return followWaitErr }
	t.Cleanup(func() { followCancel(); _ = waitFollow() })
	followReader := bufio.NewReader(followPipe)
	firstLine, err := followReader.ReadBytes('\n')
	if err != nil {
		followCancel()
		_ = waitFollow()
		t.Fatalf("follow first event: %v stderr=%s", err, followErrBuf.String())
	}
	var firstEvent events.TrackedEvent
	if err := json.Unmarshal(bytes.TrimSpace(firstLine), &firstEvent); err != nil || firstEvent.Type != "run/start" {
		t.Fatalf("follow first event = %q err=%v", firstLine, err)
	}
	running, err := sdk.GetRun(context.Background(), cleanID)
	if err != nil || running.Status != "running" {
		t.Fatalf("run not held at release gate: %#v %v", running, err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "release-clean"), []byte("release\n"), 0o600); err != nil {
		followCancel()
		t.Fatal(err)
	}
	rest, err := io.ReadAll(followReader)
	if err != nil {
		followCancel()
		_ = waitFollow()
		t.Fatalf("follow stream: %v stderr=%s", err, followErrBuf.String())
	}
	if err := waitFollow(); err != nil {
		t.Fatalf("follow exit: %v stderr=%s", err, followErrBuf.String())
	}
	followCancel()
	streamed := decodeJSONL(t, append(firstLine, rest...))
	if status := waitCLITerminal(t, benchmark, url, cleanID); status != "completed" {
		t.Fatalf("clean status=%q", status)
	}
	report := waitCLIEvidence(t, benchmark, url, cleanID)
	if report.Status != "verification_recorded" || report.Verification.Status != "ineligible" || report.Verification.Eligible {
		t.Fatalf("clean evidence report = %#v", report)
	}
	if !strings.Contains(report.Verification.Summary, "mock") {
		t.Fatalf("clean verification summary = %q", report.Verification.Summary)
	}

	code, trajectoryRaw, trajErr := e2eCLI(t, benchmark, url, "trajectory", "export", cleanID)
	if code != 0 {
		t.Fatalf("trajectory export: %d %s", code, trajErr)
	}
	sdkTrajectory, err := sdk.ExportTrajectory(context.Background(), cleanID)
	if err != nil || !bytes.Equal(sdkTrajectory, []byte(trajectoryRaw)) {
		t.Fatalf("SDK trajectory mismatch: %v", err)
	}
	sdkRun, err := sdk.GetRun(context.Background(), cleanID)
	if err != nil || sdkRun.ID != cleanID || sdkRun.Status != "completed" {
		t.Fatalf("SDK run = %#v %v", sdkRun, err)
	}
	sdkReport, err := sdk.Evidence(context.Background(), cleanID)
	if err != nil || !reflect.DeepEqual(sdkReport, report) {
		t.Fatalf("SDK evidence = %#v %v", sdkReport, err)
	}
	log := decodeJSONL(t, []byte(trajectoryRaw))
	assertGapFreeSingleFinish(t, log)
	if !reflect.DeepEqual(streamed, log) {
		t.Fatalf("followed events do not match exported trajectory: %d vs %d", len(streamed), len(log))
	}
	assertMockTrajectory(t, log)
	if _, err := replay.Replay(log); err != nil {
		t.Fatalf("production replay failed: %v", err)
	}
	if _, err := projection.Build(log); err != nil {
		t.Fatalf("production projection failed: %v", err)
	}

	code, exported, exportErr := e2eCLI(t, benchmark, url, "evidence", "export", cleanID)
	if code != 0 || len(exported) == 0 {
		t.Fatalf("evidence export: %d %s", code, exportErr)
	}
	sdkBundle, err := sdk.ExportEvidence(context.Background(), cleanID)
	if err != nil || !bytes.Equal(sdkBundle, []byte(exported)) {
		t.Fatalf("SDK evidence export mismatch: %v", err)
	}
	bundlePath := filepath.Join(dataDir, "clean-bundle.json")
	if err := os.WriteFile(bundlePath, []byte(exported), 0o600); err != nil {
		t.Fatal(err)
	}
	decoded, err := bundle.Decode(strings.NewReader(exported))
	if err != nil {
		t.Fatalf("decode exported bundle: %v", err)
	}
	var rawRecords []evidence.RawRecord
	if err := json.Unmarshal(decoded.Files["raw-records.json"], &rawRecords); err != nil {
		t.Fatal(err)
	}
	assertObservationRefs(t, log, rawRecords)

	code, validateOut, validateErr := e2eCLI(t, benchmark, url, "evidence", "validate", "--bundle", bundlePath, "--public-key", publicKeyPath)
	if code != 0 {
		t.Fatalf("bundle validate: %d %s", code, validateErr)
	}
	var result bundle.Result
	if err := json.Unmarshal([]byte(validateOut), &result); err != nil {
		t.Fatal(err)
	}
	if !result.IntegrityValid || result.Eligible || result.Report.PlaintextStreams != 2 || result.Report.ModelEvents != 3 {
		t.Fatalf("bundle result = %#v", result)
	}
	extractDir := filepath.Join(dataDir, "clean-extract")
	if code, _, extractErr := e2eCLI(t, benchmark, url, "evidence", "validate", "--bundle", bundlePath, "--public-key", publicKeyPath, "--extract", extractDir); code != 0 {
		t.Fatalf("bundle extract: %d %s", code, extractErr)
	}
	for path, want := range decoded.Files {
		got, err := os.ReadFile(filepath.Join(extractDir, filepath.FromSlash(path)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("extracted %s mismatch: %v", path, err)
		}
	}
	if err := evidence.VerifyManifestSignature(decoded.Manifest, publicKey); err != nil {
		t.Fatalf("manifest signature: %v", err)
	}

	tampered, err := bundle.Decode(strings.NewReader(exported))
	if err != nil {
		t.Fatal(err)
	}
	tampered.Files["workload/raw-records.bin"][0] ^= 0xff
	tamperedJSON, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(dataDir, "tampered-bundle.json")
	if err := os.WriteFile(tamperedPath, tamperedJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, tamperErr := e2eCLI(t, benchmark, url, "evidence", "validate", "--bundle", tamperedPath, "--public-key", publicKeyPath); code != 6 || !strings.Contains(tamperErr, "artifact") {
		t.Fatalf("tampered bundle: code=%d stderr=%q", code, tamperErr)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyPath := filepath.Join(dataDir, "other.pub")
	if err := os.WriteFile(otherKeyPath, otherPublic, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, keyErr := e2eCLI(t, benchmark, url, "evidence", "validate", "--bundle", bundlePath, "--public-key", otherKeyPath); code != 6 {
		t.Fatalf("wrong-key bundle: code=%d stderr=%q", code, keyErr)
	}

	missingID := startScenario(t, benchmark, url, dataDir, create, "missing-usage", "mock-missing-create", "mock-missing-start")
	missingReport := waitCLIEvidence(t, benchmark, url, missingID)
	if missingReport.Verification.Status != "ineligible" {
		t.Fatalf("missing-usage verification = %#v", missingReport.Verification)
	}
	code, missingTrajectory, missingTrajErr := e2eCLI(t, benchmark, url, "trajectory", "export", missingID)
	if code != 0 {
		t.Fatalf("missing-usage trajectory export: %d %s", code, missingTrajErr)
	}
	missingLog := decodeJSONL(t, []byte(missingTrajectory))
	assertGapFreeSingleFinish(t, missingLog)
	if countType(missingLog, "model/usage") != 0 {
		t.Fatal("missing-usage run synthesized a model/usage event")
	}
	var missingResponse events.TrackedEvent
	for _, event := range missingLog {
		if event.Type == "model/response" {
			missingResponse = event
		}
	}
	var responseData struct {
		Details struct {
			Body json.RawMessage `json:"body"`
		} `json:"details"`
	}
	if err := json.Unmarshal(missingResponse.Data, &responseData); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(responseData.Details.Body, []byte(`"usage"`)) {
		t.Fatal("missing-usage response body contains synthesized usage")
	}
	code, missingBundle, missingExportErr := e2eCLI(t, benchmark, url, "evidence", "export", missingID)
	if code != 0 {
		t.Fatalf("missing-usage evidence export: %d %s", code, missingExportErr)
	}
	missingPath := filepath.Join(dataDir, "missing-usage-bundle.json")
	if err := os.WriteFile(missingPath, []byte(missingBundle), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, e := e2eCLI(t, benchmark, url, "evidence", "validate", "--bundle", missingPath, "--public-key", publicKeyPath); code != 0 {
		t.Fatalf("missing-usage bundle validate: %d %s out=%s", code, e, out)
	}

	for _, scenario := range []string{"dropped", "opaque"} {
		id := startScenario(t, benchmark, url, dataDir, create, scenario, "mock-"+scenario+"-create", "mock-"+scenario+"-start")
		faultReport := waitCLIEvidence(t, benchmark, url, id)
		if faultReport.Verification.Status != "verification_error" || faultReport.Verification.Eligible {
			t.Fatalf("%s verification = %#v", scenario, faultReport.Verification)
		}
		if !strings.Contains(faultReport.Verification.Summary, "lacks complete plaintext") {
			t.Fatalf("%s summary = %q", scenario, faultReport.Verification.Summary)
		}
		if status := waitCLITerminal(t, benchmark, url, id); status != "completed" {
			t.Fatalf("%s status=%q", scenario, status)
		}
		code, faultTrajectory, trajErr := e2eCLI(t, benchmark, url, "trajectory", "export", id)
		if code != 0 {
			t.Fatalf("%s trajectory export: %d %s", scenario, code, trajErr)
		}
		faultLog := decodeJSONL(t, []byte(faultTrajectory))
		assertGapFreeSingleFinish(t, faultLog)
		code, faultBundle, e := e2eCLI(t, benchmark, url, "evidence", "export", id)
		if code != 0 {
			t.Fatalf("%s evidence export: %d %s", scenario, code, e)
		}
		faultPath := filepath.Join(dataDir, scenario+"-bundle.json")
		if err := os.WriteFile(faultPath, []byte(faultBundle), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, _, e := e2eCLI(t, benchmark, url, "evidence", "validate", "--bundle", faultPath, "--public-key", publicKeyPath); code != 6 || !strings.Contains(e, "lacks complete plaintext") {
			t.Fatalf("%s bundle validate: code=%d stderr=%q", scenario, code, e)
		}
		faultDecoded, err := bundle.Decode(strings.NewReader(faultBundle))
		if err != nil {
			t.Fatal(err)
		}
		var faultRecords []evidence.RawRecord
		if err := json.Unmarshal(faultDecoded.Files["raw-records.json"], &faultRecords); err != nil {
			t.Fatal(err)
		}
		assertObservationRefs(t, faultLog, faultRecords)
		if err := evidence.ValidateRawCoverage(faultRecords, coverageFromEvents(t, faultLog)); err != nil {
			t.Fatalf("%s raw coverage: %v", scenario, err)
		}
		var health backend.SensorHealth
		if err := json.Unmarshal(faultDecoded.Files["sensor-health.json"], &health); err != nil {
			t.Fatal(err)
		}
		recordsPerSensor := map[string]uint64{}
		for _, record := range faultRecords {
			recordsPerSensor[record.SensorID]++
		}
		for _, source := range health.Sources {
			if !source.Started || !source.Drained || !source.Stopped {
				t.Fatalf("%s sensor %s health flags = %#v", scenario, source.SensorID, source)
			}
			if source.ObservedEnd == 0 || source.ObservedEnd != recordsPerSensor[source.SensorID] {
				t.Fatalf("%s sensor %s observedEnd=%d want %d raw records", scenario, source.SensorID, source.ObservedEnd, recordsPerSensor[source.SensorID])
			}
		}
		switch scenario {
		case "dropped":
			found := false
			for _, source := range health.Sources {
				if source.SensorID == "mock-plaintext" && source.Drops == 1 {
					found = true
				}
			}
			if !found {
				t.Fatalf("dropped fixture health = %#v", health)
			}
		case "opaque":
			if health.OpaqueConnections != 1 {
				t.Fatalf("opaque fixture health = %#v", health)
			}
		}
	}

	child.stop(t)
	restarted := startMockChild(t, dataDir)
	defer restarted.stop(t)
	url = restarted.url
	sdk = client.New(url)

	code, replayAfter, replayErr := create("clean", "mock-clean-create")
	_ = replayErr
	if code != 0 || replayAfter != createOut {
		t.Fatalf("post-restart create replay mismatch: code=%d out=%q", code, replayAfter)
	}
	code, startAfter, startAfterErr := e2eCLI(t, benchmark, url, "run", "start", cleanID, "--idempotency-key", "mock-clean-start")
	_ = startAfterErr
	if code != 0 || startAfter != startOut {
		t.Fatalf("post-restart start replay mismatch: code=%d out=%q", code, startAfter)
	}
	code, trajectoryAfter, trajectoryAfterErr := e2eCLI(t, benchmark, url, "trajectory", "export", cleanID)
	if code != 0 {
		t.Fatalf("post-restart trajectory export: %d %s", code, trajectoryAfterErr)
	}
	if trajectoryAfter != trajectoryRaw {
		t.Fatal("trajectory changed across restart")
	}
	code, exportedAfter, exportedAfterErr := e2eCLI(t, benchmark, url, "evidence", "export", cleanID)
	if code != 0 {
		t.Fatalf("post-restart evidence export: %d %s", code, exportedAfterErr)
	}
	if exportedAfter != exported {
		t.Fatal("evidence bundle changed across restart")
	}
	reportAfter := waitCLIEvidence(t, benchmark, url, cleanID)
	if !reflect.DeepEqual(reportAfter, report) {
		t.Fatalf("verification changed across restart: %#v", reportAfter.Verification)
	}
}

func startScenario(t *testing.T, benchmark, url, dataDir string, create func(string, string) (int, string, string), scenario, createKey, startKey string) string {
	t.Helper()
	code, out, stderr := create(scenario, createKey)
	if code != 0 {
		t.Fatalf("create %s: %d %s", scenario, code, stderr)
	}
	id := cliRunID(t, out)
	if code, _, stderr := e2eCLI(t, benchmark, url, "run", "start", id, "--idempotency-key", startKey); code != 0 {
		t.Fatalf("start %s: %d %s", scenario, code, stderr)
	}
	if status := waitCLITerminal(t, benchmark, url, id); status != "completed" {
		t.Fatalf("%s status=%q", scenario, status)
	}
	return id
}

func countType(log []events.TrackedEvent, typ string) int {
	n := 0
	for _, event := range log {
		if event.Type == typ {
			n++
		}
	}
	return n
}

func TestPhase1ControlPlaneProcess(t *testing.T) {
	if os.Getenv("HTB_E2E") != "1" {
		t.Skip("subprocess E2E requires HTB_E2E=1 (see make test-e2e)")
	}
	root := e2eRoot(t)
	benchmark := filepath.Join(root, "dist", "e2e", "benchmark")
	controlplaneBin := filepath.Join(root, "dist", "e2e", "controlplane")
	for _, bin := range []string{benchmark, controlplaneBin} {
		if _, err := os.Stat(bin); err != nil {
			t.Fatalf("binary missing; run make test-e2e: %v", err)
		}
	}
	dataDir, err := os.MkdirTemp(e2eScratch(t), "controlplane-data-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("control-plane E2E data directory retained at %s", dataDir)

	startServer := func(t *testing.T) (string, *cpServer) {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, controlplaneBin, "-listen", fmt.Sprintf("127.0.0.1:%d", port), "-data-dir", dataDir)
		stderr := &bytes.Buffer{}
		cmd.Stderr = stderr
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatalf("start controlplane: %v", err)
		}
		server := &cpServer{cmd: cmd, cancel: cancel, stderr: stderr, waitCh: make(chan error, 1)}
		go func() { server.waitCh <- cmd.Wait() }()
		t.Cleanup(func() { server.stop(t) })
		url := fmt.Sprintf("http://127.0.0.1:%d", port)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			resp, err := http.Get(url + "/v1/compatibility")
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return url, server
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		server.stop(t)
		t.Fatalf("controlplane did not become ready; stderr: %s", stderr.String())
		return "", nil
	}
	stopServer := func(t *testing.T, server *cpServer) {
		t.Helper()
		server.stop(t)
	}

	url, server := startServer(t)
	params := writeParamsFile(t, dataDir, "compat-params.json", `{"backendConfig":{"type":"compat/local-process-v1","command":["/bin/sh","-c","printf e2e-out; printf e2e-err >&2"]}}`)
	code, createOut, createErr := e2eCLI(t, benchmark, url, "run", "create", "--harness", "h", "--suite", "s", "--backend", "compat-local-process", "--idempotency-key", "cp-create", "--parameters-file", params)
	if code != 0 {
		t.Fatalf("create: %d %s", code, createErr)
	}
	runID := cliRunID(t, createOut)
	code, startOut, startErr := e2eCLI(t, benchmark, url, "run", "start", runID, "--idempotency-key", "cp-start")
	if code != 0 {
		t.Fatalf("start: %d %s", code, startErr)
	}
	if status := waitCLITerminal(t, benchmark, url, runID); status != "completed" {
		t.Fatalf("status=%q", status)
	}
	report := waitCLIEvidence(t, benchmark, url, runID)
	code, trajectoryRaw, trajErr := e2eCLI(t, benchmark, url, "trajectory", "export", runID)
	if code != 0 {
		t.Fatalf("trajectory export: %d %s", code, trajErr)
	}
	assertGapFreeSingleFinish(t, decodeJSONL(t, []byte(trajectoryRaw)))
	code, exported, exportErr := e2eCLI(t, benchmark, url, "evidence", "export", runID)
	if code != 0 {
		t.Fatalf("evidence export: %d %s", code, exportErr)
	}
	bundlePath := filepath.Join(dataDir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(exported), 0o600); err != nil {
		t.Fatal(err)
	}
	publicKeyPath := filepath.Join(dataDir, "dev-signing-key.ed25519.pub")
	if code, _, e := e2eCLI(t, benchmark, url, "evidence", "validate", "--bundle", bundlePath, "--public-key", publicKeyPath); code != 0 {
		t.Fatalf("bundle validate: %d %s", code, e)
	}

	code, abandonedOut, abandonedErr := e2eCLI(t, benchmark, url, "run", "create", "--harness", "h", "--suite", "s", "--backend", "compat-local-process", "--parameters-file", params)
	if code != 0 {
		t.Fatalf("create abandoned: %d %s", code, abandonedErr)
	}
	abandonedID := cliRunID(t, abandonedOut)
	stopServer(t, server)

	url, server = startServer(t)
	if status := waitCLITerminal(t, benchmark, url, abandonedID); status != "failed" {
		t.Fatalf("abandoned run status=%q", status)
	}
	abandonedReport := waitCLIEvidence(t, benchmark, url, abandonedID)
	if abandonedReport.Verification.Status != "interrupted" {
		t.Fatalf("abandoned verification = %#v", abandonedReport.Verification)
	}
	code, abandonedTrajectory, abandonedTrajErr := e2eCLI(t, benchmark, url, "trajectory", "export", abandonedID)
	if code != 0 {
		t.Fatalf("abandoned trajectory export: %d %s", code, abandonedTrajErr)
	}
	abandonedLog := decodeJSONL(t, []byte(abandonedTrajectory))
	assertGapFreeSingleFinish(t, abandonedLog)

	code, createReplay, createReplayErr := e2eCLI(t, benchmark, url, "run", "create", "--harness", "h", "--suite", "s", "--backend", "compat-local-process", "--idempotency-key", "cp-create", "--parameters-file", params)
	if code != 0 || createReplay != createOut {
		t.Fatalf("post-restart create replay mismatch: code=%d %s", code, createReplayErr)
	}
	code, startReplay, startReplayErr := e2eCLI(t, benchmark, url, "run", "start", runID, "--idempotency-key", "cp-start")
	if code != 0 || startReplay != startOut {
		t.Fatalf("post-restart start replay mismatch: code=%d %s", code, startReplayErr)
	}
	code, exportedAfter, exportAfterErr := e2eCLI(t, benchmark, url, "evidence", "export", runID)
	if code != 0 {
		t.Fatalf("post-restart evidence export: %d %s", code, exportAfterErr)
	}
	if exportedAfter != exported {
		t.Fatal("evidence bundle changed across restart")
	}
	reportAfter := waitCLIEvidence(t, benchmark, url, runID)
	if !reflect.DeepEqual(reportAfter, report) {
		t.Fatal("verification report changed across restart")
	}
	stopServer(t, server)

	url, server = startServer(t)
	code, trajectorySecond, trajectorySecondErr := e2eCLI(t, benchmark, url, "trajectory", "export", abandonedID)
	if code != 0 {
		t.Fatalf("second-restart abandoned trajectory export: %d %s", code, trajectorySecondErr)
	}
	secondLog := decodeJSONL(t, []byte(trajectorySecond))
	assertGapFreeSingleFinish(t, secondLog)
	if trajectorySecond != abandonedTrajectory {
		t.Fatal("abandoned trajectory changed across second restart")
	}
	code, trajectoryAfter2, trajectoryAfter2Err := e2eCLI(t, benchmark, url, "trajectory", "export", runID)
	if code != 0 {
		t.Fatalf("second-restart trajectory export: %d %s", code, trajectoryAfter2Err)
	}
	if trajectoryAfter2 != trajectoryRaw {
		t.Fatal("completed trajectory changed across second restart")
	}
	stopServer(t, server)
}
