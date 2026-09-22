// Package controlplane wires the Phase 1 compatibility backend into the
// control-plane RunDriver boundary without making the API package depend on a
// concrete execution backend.
package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/appender"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/backend/compat"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/bundle"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/normalizer"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/verification"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
)

const compatBackendName = "compat-local-process"

// maxPersistedEvidenceBytes bounds each retained evidence file read at startup.
const maxPersistedEvidenceBytes = 64 << 20

// CompatDriver is the concrete Phase 1 adapter for the deliberately limited
// local-process compatibility backend. It owns all backend handles and the
// asynchronous evidence finalization lifecycle.
type CompatDriver struct {
	store   *api.Store
	backend *compat.Backend

	mu           sync.Mutex
	runs         map[string]*compatRun
	closed       bool
	wg           sync.WaitGroup
	manifestRoot string
	signingKey   ed25519.PrivateKey
}

type compatRun struct {
	handle    backend.RunHandle
	spec      backend.RunSpec
	plan      backend.ObservationPlan
	apiSpec   api.RunSpec
	started   bool
	completed bool
}

var _ api.RunDriver = (*CompatDriver)(nil)

// NewCompatDriver constructs a driver using backend. Passing nil creates the
// standard compatibility backend. BindStore must be called before preparing a
// run, which avoids a construction cycle with api.NewStoreWithRunDriver.
func NewCompatDriver(b *compat.Backend) *CompatDriver {
	if b == nil {
		b = compat.New(compat.Config{})
	}
	return &CompatDriver{backend: b, runs: make(map[string]*compatRun)}
}

// BindStore installs the Store through which this driver appends normalized
// events and publishes evidence. It may be called exactly before the first
// run is prepared.
func (d *CompatDriver) BindStore(store *api.Store) error {
	if store == nil {
		return errors.New("control-plane store is required")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.runs) != 0 {
		return errors.New("cannot bind store after runs are prepared")
	}
	if d.store != nil && d.store != store {
		return errors.New("control-plane store is already bound")
	}
	d.store = store
	return nil
}

// ConfigureManifest enables retained, signed development evidence manifests.
// It must be called before the first run is prepared.
func (d *CompatDriver) ConfigureManifest(root string, key ed25519.PrivateKey) error {
	if root == "" || len(key) != ed25519.PrivateKeySize {
		return errors.New("manifest root and Ed25519 development key are required")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.runs) != 0 || d.closed {
		return errors.New("cannot configure manifests after driver use")
	}
	d.manifestRoot = root
	d.signingKey = append(ed25519.PrivateKey(nil), key...)
	return nil
}

// Prepare maps the API declaration to the backend contracts and reserves a
// handle. The strict backendConfig is deliberately delegated to compat's own
// strict decoder rather than interpreted a second time here.
func (d *CompatDriver) Prepare(ctx context.Context, run api.Run) error {
	if run.Spec.Backend != compatBackendName {
		return fmt.Errorf("compat driver requires spec.backend %q", compatBackendName)
	}
	d.mu.Lock()
	bound := d.store != nil
	d.mu.Unlock()
	if !bound {
		return errors.New("compat driver is not bound to a control-plane store")
	}
	config, ok := run.Spec.Parameters["backendConfig"]
	if !ok || len(config) == 0 {
		return errors.New("spec.parameters.backendConfig is required")
	}
	if !json.Valid(config) {
		return errors.New("spec.parameters.backendConfig must be valid JSON")
	}
	spec, plan := mapRun(run, config)
	handle, err := d.backend.Prepare(ctx, spec, plan)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		_ = d.backend.Destroy(context.Background(), handle)
		return errors.New("compat driver is closed")
	}
	if _, exists := d.runs[run.ID]; exists {
		_ = d.backend.Destroy(context.Background(), handle)
		return fmt.Errorf("run %q is already prepared", run.ID)
	}
	d.runs[run.ID] = &compatRun{handle: handle, spec: spec, plan: plan, apiSpec: run.Spec}
	return nil
}

func (d *CompatDriver) Start(ctx context.Context, runID string) error {
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
	if _, err := d.backend.Start(ctx, run.handle); err != nil {
		d.mu.Unlock()
		return err
	}
	run.started = true
	d.wg.Add(1)
	d.mu.Unlock()
	go d.complete(runID, run)
	return nil
}

func (d *CompatDriver) Stop(ctx context.Context, runID, reason string) error {
	d.mu.Lock()
	run, ok := d.runs[runID]
	d.mu.Unlock()
	if !ok {
		return fmt.Errorf("run %q is not prepared", runID)
	}
	return d.backend.Stop(ctx, run.handle, backend.StopReason(reason))
}

// Abort discards a prepared run when control-plane creation fails before it
// publishes a run. No retained evidence has been promised at that point.
func (d *CompatDriver) Abort(ctx context.Context, runID string) error {
	d.mu.Lock()
	run, ok := d.runs[runID]
	if !ok {
		d.mu.Unlock()
		return nil
	}
	if run.started {
		d.mu.Unlock()
		return errors.New("cannot abort a started run")
	}
	delete(d.runs, runID)
	d.mu.Unlock()
	return d.backend.Destroy(ctx, run.handle)
}

func (d *CompatDriver) complete(runID string, run *compatRun) {
	defer d.wg.Done()
	ctx := context.Background()
	exit, err := d.backend.Wait(ctx, run.handle)
	if err != nil {
		d.record(runID, "verification_error", "compat workload wait failed: "+err.Error())
		d.completeRun(runID, "failed", "backend wait failed")
		d.retain(runID, run)
		return
	}
	evidenceOut, health, err := d.backend.FinalizeEvidence(ctx, run.handle)
	if err != nil {
		d.record(runID, "verification_error", "compat evidence finalization failed: "+err.Error())
		d.completeRun(runID, "failed", "evidence finalization failed")
		d.retain(runID, run)
		return
	}
	records, err := d.backend.RawRecords(ctx, run.handle)
	if err != nil {
		d.record(runID, "verification_error", "compat raw evidence read failed: "+err.Error())
		d.completeRun(runID, "failed", "raw evidence read failed")
		d.retain(runID, run)
		return
	}
	normalized, err := normalizer.NormalizeCompat(records)
	if err != nil {
		d.record(runID, "verification_error", "compat normalization failed: "+err.Error())
		d.completeRun(runID, "failed", "normalization failed")
		d.retain(runID, run)
		return
	}
	seqs := make([]uint64, 0, len(normalized.Events))
	for _, event := range normalized.Events {
		appended, err := d.store.AppendEvent(runID, event)
		if err != nil {
			d.record(runID, "verification_error", "append normalized event failed: "+err.Error())
			d.completeRun(runID, "failed", "event append failed")
			d.retain(runID, run)
			return
		}
		seqs = append(seqs, appended.Seq)
	}
	coverage, err := normalizer.BindCoverageEventIDs(normalized.Coverage, seqs)
	if err != nil {
		d.record(runID, "verification_error", "bind coverage event IDs failed: "+err.Error())
		d.completeRun(runID, "failed", "coverage binding failed")
		d.retain(runID, run)
		return
	}
	status := "completed"
	if exit.Code != 0 {
		status = "failed"
	}
	if err := d.completeRun(runID, status, exit.Reason); err == nil {
		result, err := d.computeVerification(runID, run, records, coverage, evidenceOut, health)
		if err != nil {
			d.record(runID, "verification_error", err.Error())
		} else if err := d.writeManifest(runID, run, evidenceOut, health, records, result); err != nil {
			d.record(runID, "verification_error", "write evidence manifest failed: "+err.Error())
		} else if err := d.store.SetEvidenceVerification(runID, result); err != nil {
			d.record(runID, "verification_error", "publish evidence verification failed: "+err.Error())
		}
	}
	d.retain(runID, run)
}

func (d *CompatDriver) completeRun(runID, status, reason string) error {
	if _, err := d.store.Complete(runID, status, reason); err != nil {
		d.record(runID, "verification_error", "record run completion failed: "+err.Error())
		return err
	}
	if err := d.store.SealRun(runID); err != nil {
		d.record(runID, "verification_error", "seal trajectory failed: "+err.Error())
		return err
	}
	return nil
}

func (d *CompatDriver) computeVerification(runID string, run *compatRun, records []evidence.RawRecord, coverage []evidence.NormalizedCoverage, evidenceOut backend.BackendEvidence, health backend.SensorHealth) (api.VerificationResult, error) {
	allEvents, ok := d.store.Events(runID)
	if !ok {
		return api.VerificationResult{}, errors.New("run events are unavailable")
	}
	manifest, err := d.backend.Describe(context.Background())
	if err != nil {
		return api.VerificationResult{}, fmt.Errorf("compat capability inspection failed: %w", err)
	}
	expected, err := expectedHeads(records, evidenceOut.RawChainHeads)
	if err != nil {
		return api.VerificationResult{}, fmt.Errorf("raw chain heads: %w", err)
	}
	report, err := verification.Verify(verification.Input{
		Events:                   allEvents,
		RawRecords:               records,
		RawCoverage:              coverage,
		RawRunSpecDigest:         digestJSON(run.spec),
		RawObservationPlanDigest: digestJSON(run.plan),
		ExpectedRawChainHeads:    expected,
		Eligibility:              &verification.EligibilityInput{RunSpec: run.spec, ObservationPlan: run.plan, CapabilityManifest: manifest, SensorHealth: health},
	})
	if err != nil {
		return api.VerificationResult{}, fmt.Errorf("integrity validation failed: %w", err)
	}
	if !report.IntegrityValid || !report.RawEvidenceIntegrityValid {
		return api.VerificationResult{}, errors.New("compat evidence integrity validation did not complete")
	}
	var chainHead string
	if d.manifestRoot != "" {
		if chainHead, err = d.store.RunHashHead(runID); err != nil {
			return api.VerificationResult{}, fmt.Errorf("read tracked event chain head: %w", err)
		}
	}
	return api.VerificationResult{
		Status:                "ineligible",
		Eligible:              false,
		Summary:               "compat-local-process is ineligible for verified status: plaintext network capture is unsupported",
		CheckedAt:             time.Now().UTC(),
		TrackedEventChainHead: chainHead,
		EventCount:            report.EventCount,
	}, nil
}

func (d *CompatDriver) ValidatePersistedBundles() error {
	d.mu.Lock()
	root, key, store := d.manifestRoot, d.signingKey, d.store
	d.mu.Unlock()
	if root == "" || store == nil || len(key) == 0 {
		return nil
	}
	publicKey, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("invalid manifest signing key")
	}
	for _, run := range store.Runs() {
		report, _ := store.Evidence(run.ID)
		if report.Verification == nil || report.Verification.Status == "interrupted" || report.Verification.Status == "verification_error" {
			continue
		}
		dir := filepath.Join(root, "runs", run.ID)
		bundlePath := filepath.Join(dir, "evidence-bundle.json")
		manifestPath := filepath.Join(dir, "evidence-manifest.json")
		for _, path := range []string{bundlePath, manifestPath} {
			info, err := os.Lstat(path)
			if err != nil {
				return fmt.Errorf("run %s evidence file %q: %w", run.ID, path, err)
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("run %s evidence file %q is not a regular file", run.ID, path)
			}
			if info.Size() > maxPersistedEvidenceBytes {
				return fmt.Errorf("run %s evidence file %q is %d bytes, exceeding the %d byte limit", run.ID, path, info.Size(), maxPersistedEvidenceBytes)
			}
		}
		data, err := os.ReadFile(bundlePath)
		if err != nil {
			return fmt.Errorf("run %s evidence bundle: %w", run.ID, err)
		}
		decoded, err := bundle.Decode(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("run %s evidence bundle: %w", run.ID, err)
		}
		result, err := bundle.Validate(decoded, publicKey)
		if err != nil {
			return fmt.Errorf("run %s evidence bundle: %w", run.ID, err)
		}
		if decoded.RunID != run.ID || result.TrackedEventChainHead != report.Verification.TrackedEventChainHead || result.Report.EventCount != report.Verification.EventCount {
			return fmt.Errorf("run %s evidence bundle does not match the published verification", run.ID)
		}
		events, err := store.ExportEvents(run.ID)
		if err != nil {
			return fmt.Errorf("run %s persisted trajectory: %w", run.ID, err)
		}
		if !bytes.Equal(events, decoded.Files["tracked-events.jsonl"]) {
			return fmt.Errorf("run %s bundle trajectory does not match the persisted log", run.ID)
		}
		var compactSpec bytes.Buffer
		if err := json.Compact(&compactSpec, decoded.Files["api-run-spec.json"]); err != nil {
			return fmt.Errorf("run %s api run spec: %w", run.ID, err)
		}
		catalogSpec, err := json.Marshal(run.Spec)
		if err != nil {
			return fmt.Errorf("run %s catalog spec: %w", run.ID, err)
		}
		if !bytes.Equal(compactSpec.Bytes(), catalogSpec) {
			return fmt.Errorf("run %s bundle api run spec does not match the catalog", run.ID)
		}
		var storedVerification api.VerificationResult
		if err := json.Unmarshal(decoded.Files["verification.json"], &storedVerification); err != nil {
			return fmt.Errorf("run %s stored verification: %w", run.ID, err)
		}
		if !reflect.DeepEqual(storedVerification, *report.Verification) {
			return fmt.Errorf("run %s stored verification does not match the catalog", run.ID)
		}
		manifestBytes, err := os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("run %s evidence manifest: %w", run.ID, err)
		}
		var diskManifest evidence.RunEvidenceManifest
		if err := json.Unmarshal(manifestBytes, &diskManifest); err != nil {
			return fmt.Errorf("run %s evidence manifest: %w", run.ID, err)
		}
		if !reflect.DeepEqual(diskManifest, decoded.Manifest) {
			return fmt.Errorf("run %s evidence manifest does not match the bundle", run.ID)
		}
		tracked, _, err := appender.ValidateFrames(decoded.Files["tracked-events.jsonl"])
		if err != nil || len(tracked) == 0 {
			return fmt.Errorf("run %s bundle trajectory is invalid", run.ID)
		}
		var finishData struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(tracked[len(tracked)-1].Data, &finishData); err != nil || finishData.Status != run.Status {
			return fmt.Errorf("run %s final event status does not match the catalog", run.ID)
		}
	}
	return nil
}

func expectedHeads(records []evidence.RawRecord, heads map[string]string) (map[evidence.RawSource]string, error) {
	expected := make(map[evidence.RawSource]string)
	boots := make(map[string]string)
	for _, record := range records {
		if previous, ok := boots[record.SensorID]; ok && previous != record.BootID {
			return nil, fmt.Errorf("ambiguous raw chain head for sensor %q", record.SensorID)
		}
		boots[record.SensorID] = record.BootID
		head, ok := heads[record.SensorID]
		if !ok || head == "" {
			return nil, fmt.Errorf("backend reported no raw chain head for sensor %q", record.SensorID)
		}
		expected[evidence.RawSource{SensorID: record.SensorID, BootID: record.BootID}] = head
	}
	return expected, nil
}

func (d *CompatDriver) record(runID, status, summary string) {
	_ = d.store.SetEvidenceVerification(runID, api.VerificationResult{Status: status, Eligible: false, Summary: summary})
}

// retain leaves the finalized raw evidence and workload artifacts on disk.
// Destroy would erase them, making the published trajectory unauditable.
func (d *CompatDriver) retain(runID string, run *compatRun) {
	d.mu.Lock()
	if d.runs[runID] == run {
		run.completed = true
	}
	d.mu.Unlock()
}

// Shutdown stops started workloads, destroys prepared workloads, and waits for
// owned completion goroutines. It is safe to call repeatedly.
func (d *CompatDriver) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	d.closed = true
	runs := make(map[string]*compatRun, len(d.runs))
	for id, run := range d.runs {
		runs[id] = run
	}
	d.mu.Unlock()
	var first error
	for id, run := range runs {
		d.mu.Lock()
		completed := run.completed
		d.mu.Unlock()
		if completed {
			continue
		}
		if err := d.backend.Stop(ctx, run.handle, backend.StopReason("shutdown")); err != nil && first == nil {
			first = fmt.Errorf("stop %s: %w", id, err)
		}
		if !run.started {
			if err := d.backend.Destroy(ctx, run.handle); err != nil && first == nil {
				first = fmt.Errorf("destroy %s: %w", id, err)
			}
			d.mu.Lock()
			delete(d.runs, id)
			d.mu.Unlock()
		}
	}
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		if first == nil {
			first = ctx.Err()
		}
	}
	return first
}

// Close is a convenience shutdown for callers without their own deadline.
func (d *CompatDriver) Close() error { return d.Shutdown(context.Background()) }

func mapRun(run api.Run, config json.RawMessage) (backend.RunSpec, backend.ObservationPlan) {
	return backend.RunSpec{
		SchemaVersion: "v1", RunID: run.ID,
		HarnessDigest: digestText("harness\x00" + run.Spec.Harness), BenchmarkDigest: digestText("suite\x00" + run.Spec.Suite),
		PolicyDigest: digestText("compat-config\x00" + string(config)), Profile: "development", Verified: run.Spec.Verified,
		Labels: map[string]string{"harness": run.Spec.Harness, "suite": run.Spec.Suite, "backend": run.Spec.Backend},
	}, backend.ObservationPlan{SchemaVersion: "v1", SensorConfigs: []json.RawMessage{append(json.RawMessage(nil), config...)}, OpaqueTrafficPolicy: backend.OpaqueTrafficAllow}
}

func digestText(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func digestJSON(value any) string {
	b, _ := json.Marshal(value)
	return digestText(string(b))
}
