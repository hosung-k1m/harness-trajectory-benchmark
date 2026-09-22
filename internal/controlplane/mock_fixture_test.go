package controlplane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/bundle"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/llmnormalizer"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/normalizer"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/plaintext"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/verification"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

const (
	mockBackendName = "mock-data"
	mockBootID      = "mock-boot-1"
	mockEndpoint    = "https://provider.example.test/v1/chat/completions"
)

var errMockVerifiedRun = errors.New("mock-data driver does not admit verified runs")

type mockDriver struct {
	mu     sync.Mutex
	store  *api.Store
	root   string
	key    ed25519.PrivateKey
	runs   map[string]*mockRun
	closed bool
	wg     sync.WaitGroup
}

type mockRun struct {
	spec     backend.RunSpec
	plan     backend.ObservationPlan
	apiSpec  api.RunSpec
	scenario string
	cancel   chan struct{}
	started  bool
}

var _ api.RunDriver = (*mockDriver)(nil)

func newMockDriver(root string, key ed25519.PrivateKey) *mockDriver {
	return &mockDriver{root: root, key: append(ed25519.PrivateKey(nil), key...), runs: map[string]*mockRun{}}
}

func (d *mockDriver) BindStore(store *api.Store) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.store != nil && d.store != store {
		return errors.New("mock driver is already bound")
	}
	d.store = store
	return nil
}

func (d *mockDriver) Prepare(_ context.Context, run api.Run) error {
	if run.Spec.Backend != mockBackendName {
		return fmt.Errorf("mock driver requires spec.backend %q", mockBackendName)
	}
	if run.Spec.Verified {
		return errMockVerifiedRun
	}
	raw, ok := run.Spec.Parameters["scenario"]
	if !ok {
		return errors.New("spec.parameters.scenario is required")
	}
	var scenario string
	if err := json.Unmarshal(raw, &scenario); err != nil {
		return errors.New("spec.parameters.scenario must be a JSON string")
	}
	switch scenario {
	case "clean", "missing-usage", "dropped", "opaque":
	default:
		return fmt.Errorf("unknown mock scenario %q", scenario)
	}
	spec := backend.RunSpec{
		SchemaVersion: "v1", RunID: run.ID,
		HarnessDigest:   digestText("harness\x00" + run.Spec.Harness),
		BenchmarkDigest: digestText("suite\x00" + run.Spec.Suite),
		PolicyDigest:    digestText("mock-config\x00" + scenario),
		Profile:         "development", Verified: false,
		Labels: map[string]string{"harness": run.Spec.Harness, "suite": run.Spec.Suite, "backend": run.Spec.Backend},
	}
	plan := backend.ObservationPlan{SchemaVersion: "v1", SensorConfigs: []json.RawMessage{json.RawMessage(`"mock-` + scenario + `"`)}, OpaqueTrafficPolicy: backend.OpaqueTrafficAllow}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("mock driver is closed")
	}
	if _, exists := d.runs[run.ID]; exists {
		return fmt.Errorf("run %q is already prepared", run.ID)
	}
	d.runs[run.ID] = &mockRun{spec: spec, plan: plan, apiSpec: run.Spec, scenario: scenario, cancel: make(chan struct{})}
	return nil
}

func (d *mockDriver) Start(_ context.Context, runID string) error {
	d.mu.Lock()
	run, ok := d.runs[runID]
	if !ok {
		d.mu.Unlock()
		return fmt.Errorf("run %q is not prepared", runID)
	}
	if run.started {
		d.mu.Unlock()
		return fmt.Errorf("run %q is already started", runID)
	}
	run.started = true
	d.wg.Add(1)
	store := d.store
	d.mu.Unlock()
	go d.finish(runID, run, store)
	return nil
}

func (d *mockDriver) Stop(_ context.Context, runID, _ string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	run, ok := d.runs[runID]
	if !ok {
		return fmt.Errorf("run %q is not prepared", runID)
	}
	select {
	case <-run.cancel:
	default:
		close(run.cancel)
	}
	return nil
}

func (d *mockDriver) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	d.closed = true
	for _, run := range d.runs {
		select {
		case <-run.cancel:
		default:
			close(run.cancel)
		}
	}
	d.mu.Unlock()
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *mockDriver) Close() error { return d.Shutdown(context.Background()) }

func (d *mockDriver) finish(runID string, run *mockRun, store *api.Store) {
	defer d.wg.Done()
	select {
	case <-run.cancel:
		d.fail(store, runID, "failed", "mock run stopped before fixture replay", "mock run stopped before fixture replay")
		return
	default:
	}
	if run.scenario == "clean" {
		gate := filepath.Join(d.root, "release-clean")
		deadline := time.Now().Add(30 * time.Second)
		for {
			if _, err := os.Stat(gate); err == nil {
				break
			}
			select {
			case <-run.cancel:
				d.fail(store, runID, "failed", "mock run stopped before fixture replay", "mock run stopped before fixture replay")
				return
			case <-time.After(10 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				d.fail(store, runID, "failed", "mock release gate timed out", "mock release-clean gate timed out")
				return
			}
		}
	}
	records, health, err := buildMockFixture(runID, run.scenario)
	if err != nil {
		d.fail(store, runID, "failed", "mock fixture construction failed", err.Error())
		return
	}
	normalized, err := normalizer.NormalizeMock(records)
	if err != nil {
		d.fail(store, runID, "failed", "mock normalization failed", "mock normalization failed: "+err.Error())
		return
	}
	var egressSeqs, ingressSeqs []uint64
	seqs := make([]uint64, 0, len(normalized.Events))
	for i, candidate := range normalized.Events {
		switch records[i].RecordType {
		case "model/request":
			candidate.SourceEventSeqs = append([]uint64(nil), egressSeqs...)
		case "model/stream-chunk", "model/response", "model/usage":
			candidate.SourceEventSeqs = append([]uint64(nil), ingressSeqs...)
		}
		appended, err := store.AppendEvent(runID, candidate)
		if err != nil {
			d.fail(store, runID, "failed", "event append failed", "append normalized event failed: "+err.Error())
			return
		}
		seqs = append(seqs, appended.Seq)
		if records[i].RecordType == "network/plaintext" {
			var detail struct {
				Details events.NetworkPlaintext `json:"details"`
			}
			if err := json.Unmarshal(appended.Data, &detail); err == nil {
				switch detail.Details.Direction {
				case "egress":
					egressSeqs = append(egressSeqs, appended.Seq)
				case "ingress":
					ingressSeqs = append(ingressSeqs, appended.Seq)
				}
			}
		}
	}
	if _, err := store.Complete(runID, "completed", "mock fixture replay finished"); err != nil {
		d.fail(store, runID, "failed", "record run completion failed", "record run completion failed: "+err.Error())
		return
	}
	if err := store.SealRun(runID); err != nil {
		d.fail(store, runID, "failed", "seal trajectory failed", "seal trajectory failed: "+err.Error())
		return
	}
	coverage, err := normalizer.BindCoverageEventIDs(normalized.Coverage, seqs)
	if err != nil {
		d.fail(store, runID, "failed", "coverage binding failed", "bind coverage event IDs failed: "+err.Error())
		return
	}
	d.publish(store, runID, run, records, coverage, health)
}

func (d *mockDriver) publish(store *api.Store, runID string, run *mockRun, records []evidence.RawRecord, coverage []evidence.NormalizedCoverage, health backend.SensorHealth) {
	specDigest, planDigest := digestJSON(run.spec), digestJSON(run.plan)
	flows, err := mockFlows(records)
	if err != nil {
		d.failEvidence(store, runID, "raw boundary flow decode failed: "+err.Error())
		return
	}
	allEvents, ok := store.Events(runID)
	if !ok {
		d.failEvidence(store, runID, "run events are unavailable")
		return
	}
	head, err := store.RunHashHead(runID)
	if err != nil {
		d.failEvidence(store, runID, "read tracked event chain head: "+err.Error())
		return
	}
	caps := mockCapabilities()
	expected := map[evidence.RawSource]string{}
	rawHeads := map[string]string{}
	bySource := map[evidence.RawSource][]evidence.RawRecord{}
	for _, record := range records {
		source := evidence.RawSource{SensorID: record.SensorID, BootID: record.BootID}
		bySource[source] = append(bySource[source], record)
	}
	for source, chain := range bySource {
		seed, err := evidence.ChainSeed(specDigest, planDigest, source.SensorID, source.BootID)
		if err != nil {
			d.failEvidence(store, runID, "raw chain seed: "+err.Error())
			return
		}
		head, err := evidence.ValidateChain(chain, seed)
		if err != nil {
			d.failEvidence(store, runID, "raw chain head: "+err.Error())
			return
		}
		expected[source] = head
		rawHeads[source.SensorID] = head
	}
	var result api.VerificationResult
	report, verifyErr := verification.Verify(verification.Input{
		Events:                   allEvents,
		Flows:                    flows,
		RawRecords:               records,
		RawCoverage:              coverage,
		RawRunSpecDigest:         specDigest,
		RawObservationPlanDigest: planDigest,
		ExpectedRawChainHeads:    expected,
		Eligibility:              &verification.EligibilityInput{RunSpec: run.spec, ObservationPlan: run.plan, CapabilityManifest: caps, SensorHealth: health},
	})
	valid := true
	if verifyErr != nil {
		valid = false
		result = api.VerificationResult{Status: "verification_error", Eligible: false, Summary: verifyErr.Error(), CheckedAt: time.Now().UTC(), TrackedEventChainHead: head, EventCount: uint64(len(allEvents))}
	} else {
		result = api.VerificationResult{Status: "ineligible", Eligible: false, Summary: "mock-data fixture replay only; no isolated execution backend observed this run", CheckedAt: time.Now().UTC(), TrackedEventChainHead: head, EventCount: report.EventCount}
	}
	files, err := d.bundleFiles(store, runID, run, caps, health, records, result, head)
	if err != nil {
		d.failEvidence(store, runID, "bundle assembly failed: "+err.Error())
		return
	}
	manifest := evidence.RunEvidenceManifest{
		SchemaVersion: "v1", RunID: runID,
		RunSpecDigest: specDigest, ObservationPlanDigest: planDigest,
		CapabilityManifestDigest: caps.Digest, SensorHealthDigest: digestJSON(health),
		TrackedEventChainHead: head, RawChainHeads: rawHeads, SealedAt: time.Now().UTC(),
	}
	b, err := buildEvidenceBundle(d.key, manifest, files)
	if err != nil {
		d.failEvidence(store, runID, "bundle signing failed: "+err.Error())
		return
	}
	if valid {
		publicKey, ok := d.key.Public().(ed25519.PublicKey)
		if !ok {
			d.failEvidence(store, runID, "invalid manifest signing key")
			return
		}
		if _, err := bundle.Validate(b, publicKey); err != nil {
			d.failEvidence(store, runID, "bundle self-validation failed: "+err.Error())
			return
		}
	}
	manifestJSON, err := json.MarshalIndent(b.Manifest, "", "  ")
	if err != nil {
		d.failEvidence(store, runID, "encode evidence manifest: "+err.Error())
		return
	}
	bundleJSON, err := json.Marshal(b)
	if err != nil {
		d.failEvidence(store, runID, "encode evidence bundle: "+err.Error())
		return
	}
	dir := filepath.Join(d.root, "runs", runID)
	if err := writeFileAtomic(filepath.Join(dir, "evidence-manifest.json"), append(manifestJSON, '\n')); err != nil {
		d.failEvidence(store, runID, "publish evidence manifest: "+err.Error())
		return
	}
	if err := writeFileAtomic(filepath.Join(dir, "evidence-bundle.json"), append(bundleJSON, '\n')); err != nil {
		d.failEvidence(store, runID, "publish evidence bundle: "+err.Error())
		return
	}
	if err := store.SetEvidenceVerification(runID, result); err != nil {
		d.failEvidence(store, runID, "publish evidence verification failed: "+err.Error())
	}
}

func (d *mockDriver) bundleFiles(store *api.Store, runID string, run *mockRun, caps backend.CapabilityManifest, health backend.SensorHealth, records []evidence.RawRecord, result api.VerificationResult, head string) (map[string][]byte, error) {
	tracked, err := store.ExportEvents(runID)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	putJSON := func(name string, v any) error {
		encoded, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("encode %s: %w", name, err)
		}
		files[name] = append(encoded, '\n')
		return nil
	}
	for name, v := range map[string]any{
		"api-run-spec.json":        run.apiSpec,
		"run-spec.json":            run.spec,
		"observation-plan.json":    run.plan,
		"capability-manifest.json": caps,
		"sensor-health.json":       health,
		"raw-records.json":         records,
		"verification.json":        result,
	} {
		if err := putJSON(name, v); err != nil {
			return nil, err
		}
	}
	files["tracked-events.jsonl"] = tracked
	files["tracked-events.jsonl.sealed"] = []byte(head + "\n")
	var frames bytes.Buffer
	for _, record := range records {
		frame, err := record.Frame()
		if err != nil {
			return nil, err
		}
		frames.Write(frame)
	}
	files["workload/raw-records.bin"] = frames.Bytes()
	return files, nil
}

func (d *mockDriver) failEvidence(store *api.Store, runID, summary string) {
	_ = store.SetEvidenceVerification(runID, api.VerificationResult{Status: "verification_error", Eligible: false, Summary: summary, CheckedAt: time.Now().UTC()})
}

func (d *mockDriver) fail(store *api.Store, runID, status, reason, summary string) {
	if _, err := store.Complete(runID, status, reason); err != nil {
		d.failEvidence(store, runID, "record run completion failed: "+err.Error())
		return
	}
	if err := store.SealRun(runID); err != nil {
		d.failEvidence(store, runID, "seal trajectory failed: "+err.Error())
		return
	}
	d.failEvidence(store, runID, summary)
}

func mockCapabilities() backend.CapabilityManifest {
	m := backend.CapabilityManifest{
		SchemaVersion: "v1", Backend: "mock-data", Version: "phase1", TrustDomain: "mock",
		Capabilities: []backend.Capability{
			{EventFamily: "process", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "run"},
			{EventFamily: "filesystem", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "run"},
			{EventFamily: "network", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "run"},
			{EventFamily: "model", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "run"},
		},
	}
	without := m
	without.Digest = ""
	m.Digest = digestJSON(without)
	return m
}

func mockFlows(records []evidence.RawRecord) ([]plaintext.FlowAccounting, error) {
	var flows []plaintext.FlowAccounting
	for _, record := range records {
		if record.RecordType != "network/flow" {
			continue
		}
		var flow plaintext.FlowAccounting
		if err := json.Unmarshal(record.Payload, &flow); err != nil {
			return nil, fmt.Errorf("raw boundary flow %d: %w", record.SourceSeq, err)
		}
		flows = append(flows, flow)
	}
	return flows, nil
}

const (
	mockRequestLiteral  = `{"model":"mock-model","messages":[{"role":"user","content":"hello"}]}`
	mockResponseLiteral = `{"id":"mock-response","object":"chat.completion","model":"mock-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`
	mockChunkLiteral    = `{"id":"mock-response","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-1","type":"function","function":{"name":"shell","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`
)

func mockWireBytes(includeUsage bool) (requestWire, responseWire []byte, requestBody, chunkBody, responseBody json.RawMessage, err error) {
	responseObject := json.RawMessage(mockResponseLiteral)
	if !includeUsage {
		var m map[string]json.RawMessage
		if err = json.Unmarshal(responseObject, &m); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		delete(m, "usage")
		if responseObject, err = json.Marshal(m); err != nil {
			return nil, nil, nil, nil, nil, err
		}
	}
	requestWire, err = mockRequestWire(mockRequestLiteral)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	ndjson := mockChunkLiteral + "\n" + string(responseObject) + "\n"
	responseWire, err = mockResponseWire(ndjson)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	parsed, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(requestWire)))
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("parse mock request wire bytes: %w", err)
	}
	defer parsed.Body.Close()
	requestBody, err = io.ReadAll(parsed.Body)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	parsedResponse, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(responseWire)), nil)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("parse mock response wire bytes: %w", err)
	}
	defer parsedResponse.Body.Close()
	decoder := json.NewDecoder(parsedResponse.Body)
	if err = decoder.Decode(&chunkBody); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("decode mock stream chunk: %w", err)
	}
	if err = decoder.Decode(&responseBody); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("decode mock response: %w", err)
	}
	return requestWire, responseWire, requestBody, chunkBody, responseBody, nil
}

func mockRequestWire(body string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, mockEndpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func mockResponseWire(body string) ([]byte, error) {
	resp := &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": []string{"application/x-ndjson"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	if err := resp.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func mockLLMInput(kind llmnormalizer.Kind, body json.RawMessage) ([]byte, error) {
	return json.Marshal(llmnormalizer.Input{
		Kind: kind, Provider: llmnormalizer.ProviderOpenAICompatible, ProviderModel: "mock-model",
		Endpoint: mockEndpoint, ModelExchangeID: "mock-exchange", NativeBody: body,
	})
}

type mockChain struct {
	sensor  string
	records []evidence.RawRecord
}

func (c *mockChain) add(runID, typ string, payload []byte) error {
	record := evidence.RawRecord{
		RunID: runID, SensorID: c.sensor, BootID: mockBootID,
		SourceSeq:  uint64(len(c.records) + 1),
		RecordType: typ, Encoding: "json", Payload: payload,
	}
	if len(c.records) > 0 {
		record.PreviousRecordSHA256 = c.records[len(c.records)-1].RecordSHA256
	}
	hash, err := record.ComputedHash()
	if err != nil {
		return err
	}
	record.RecordSHA256 = hash
	c.records = append(c.records, record)
	return nil
}

func mockPlaintextPayload(direction string, seq uint64, offset uint64, data []byte, eos bool) ([]byte, error) {
	source := events.NetworkEndpoint{IP: "10.0.0.2", Port: 44444}
	destination := events.NetworkEndpoint{Hostname: "provider.example.test", Port: 443}
	if direction == "ingress" {
		source, destination = destination, source
	}
	return json.Marshal(events.NetworkPlaintext{
		Boundary: "sandbox", CapturePoint: "mock-boundary",
		ConnectionID: "mock-conn", StreamID: "mock-stream",
		Transport: "tcp", Direction: direction, Sequence: seq,
		Offset: &offset, EndOfStream: eos,
		Source: source, Destination: destination,
		Protocol: events.ProtocolIdentity{Name: "http", Version: "1.1"},
		Payload:  events.CapturedBytes{Encoding: "utf8", Inline: string(data), Length: uint64(len(data)), SHA256: backend.SHA256Hex(data)},
		Capture:  events.PlaintextCapture{Method: "mock", Backend: "mock-data", Verified: false},
	})
}

func mockFlowPayload(connection, stream, direction string, data []byte) ([]byte, error) {
	return json.Marshal(plaintext.FlowAccounting{
		ConnectionID: connection, StreamID: stream, Direction: direction,
		Bytes: uint64(len(data)), SHA256: backend.SHA256Hex(data),
	})
}

func mockHealth(chains map[string]*mockChain, drops map[string]uint64, opaque uint64) backend.SensorHealth {
	h := backend.SensorHealth{SchemaVersion: "v1", OpaqueConnections: opaque}
	for _, sensor := range []string{"mock-system", "mock-plaintext", "mock-boundary", "mock-provider"} {
		chain := chains[sensor]
		started := chain != nil && len(chain.records) > 0
		source := backend.SensorSourceHealth{
			SensorID: sensor, BootID: mockBootID,
			Drops: drops[sensor], Started: started, Drained: started, Stopped: started,
		}
		if started {
			end := uint64(len(chain.records))
			source.ExpectedStart, source.ExpectedEnd = 1, end
			source.ObservedStart, source.ObservedEnd = 1, end
		}
		h.Sources = append(h.Sources, source)
	}
	return h
}

func buildMockFixture(runID, scenario string) ([]evidence.RawRecord, backend.SensorHealth, error) {
	includeUsage := scenario != "missing-usage"
	requestWire, responseWire, requestBody, chunkBody, responseBody, err := mockWireBytes(includeUsage)
	if err != nil {
		return nil, backend.SensorHealth{}, err
	}
	chains := map[string]*mockChain{
		"mock-system":    {sensor: "mock-system"},
		"mock-plaintext": {sensor: "mock-plaintext"},
		"mock-boundary":  {sensor: "mock-boundary"},
		"mock-provider":  {sensor: "mock-provider"},
	}
	add := func(sensor, typ string, payload []byte) error {
		return chains[sensor].add(runID, typ, payload)
	}
	if err := add("mock-system", "process/exec", []byte(`{"processId":"proc-1","argv":["fixture"]}`)); err != nil {
		return nil, backend.SensorHealth{}, err
	}
	if err := add("mock-system", "file/write", []byte(`{"fileId":"file-1","path":"/workspace/result.txt","bytes":3}`)); err != nil {
		return nil, backend.SensorHealth{}, err
	}
	if err := add("mock-system", "dns/query", []byte(`{"queryName":"provider.example.test","queryType":"A"}`)); err != nil {
		return nil, backend.SensorHealth{}, err
	}

	addChunks := func(direction string, wire []byte, dropFinal bool) error {
		half := len(wire) / 2
		parts := []struct {
			seq    uint64
			offset uint64
			data   []byte
			eos    bool
		}{
			{1, 0, wire[:half], false},
			{2, uint64(half), wire[half:], true},
		}
		for _, part := range parts {
			if dropFinal && part.eos {
				return add("mock-plaintext", "sensor/drop", []byte(`{"dropped":1,"reason":"fixture dropped final ingress chunk"}`))
			}
			payload, err := mockPlaintextPayload(direction, part.seq, part.offset, part.data, part.eos)
			if err != nil {
				return err
			}
			if err := add("mock-plaintext", "network/plaintext", payload); err != nil {
				return err
			}
		}
		return nil
	}
	if err := addChunks("egress", requestWire, false); err != nil {
		return nil, backend.SensorHealth{}, err
	}
	if err := addChunks("ingress", responseWire, scenario == "dropped"); err != nil {
		return nil, backend.SensorHealth{}, err
	}

	egressFlow, err := mockFlowPayload("mock-conn", "mock-stream", "egress", requestWire)
	if err != nil {
		return nil, backend.SensorHealth{}, err
	}
	if err := add("mock-boundary", "network/flow", egressFlow); err != nil {
		return nil, backend.SensorHealth{}, err
	}
	ingressFlow, err := mockFlowPayload("mock-conn", "mock-stream", "ingress", responseWire)
	if err != nil {
		return nil, backend.SensorHealth{}, err
	}
	if err := add("mock-boundary", "network/flow", ingressFlow); err != nil {
		return nil, backend.SensorHealth{}, err
	}
	if scenario == "opaque" {
		opaqueFlow, err := mockFlowPayload("mock-opaque", "mock-opaque-stream", "egress", []byte("opaque-fixture-bytes"))
		if err != nil {
			return nil, backend.SensorHealth{}, err
		}
		if err := add("mock-boundary", "network/flow", opaqueFlow); err != nil {
			return nil, backend.SensorHealth{}, err
		}
		if err := add("mock-boundary", "sensor/bypass-attempt", []byte(`{"connectionId":"mock-opaque","reason":"fixture opaque tunnel"}`)); err != nil {
			return nil, backend.SensorHealth{}, err
		}
	}

	addProvider := func(typ string, kind llmnormalizer.Kind, body json.RawMessage) error {
		payload, err := mockLLMInput(kind, body)
		if err != nil {
			return err
		}
		return add("mock-provider", typ, payload)
	}
	if err := addProvider("model/request", llmnormalizer.KindRequest, requestBody); err != nil {
		return nil, backend.SensorHealth{}, err
	}
	if scenario != "dropped" {
		if err := addProvider("model/stream-chunk", llmnormalizer.KindChunk, chunkBody); err != nil {
			return nil, backend.SensorHealth{}, err
		}
		if err := addProvider("model/response", llmnormalizer.KindResponse, responseBody); err != nil {
			return nil, backend.SensorHealth{}, err
		}
		if includeUsage {
			if err := addProvider("model/usage", llmnormalizer.KindResponse, responseBody); err != nil {
				return nil, backend.SensorHealth{}, err
			}
		}
	}

	drops := map[string]uint64{}
	var opaqueCount uint64
	if scenario == "dropped" {
		drops["mock-plaintext"] = 1
	}
	if scenario == "opaque" {
		opaqueCount = 1
	}
	var records []evidence.RawRecord
	for _, sensor := range []string{"mock-system", "mock-plaintext", "mock-boundary", "mock-provider"} {
		records = append(records, chains[sensor].records...)
	}
	return records, mockHealth(chains, drops, opaqueCount), nil
}
