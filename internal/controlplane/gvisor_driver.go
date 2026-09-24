package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/backend/gvisor"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
)

const gvisorBackendName = "gvisor-container"

type GvisorDriver struct {
	store   *api.Store
	backend *gvisor.Backend

	mu           sync.Mutex
	runs         map[string]*gvisorRun
	closed       bool
	wg           sync.WaitGroup
	manifestRoot string
	signingKey   ed25519.PrivateKey
}

type gvisorRun struct {
	handle    backend.RunHandle
	spec      backend.RunSpec
	plan      backend.ObservationPlan
	apiSpec   api.RunSpec
	started   bool
	completed bool
}

var _ api.RunDriver = (*GvisorDriver)(nil)

func NewGvisorDriver(b *gvisor.Backend) *GvisorDriver {
	if b == nil {
		b = gvisor.New(gvisor.Config{})
	}
	return &GvisorDriver{backend: b, runs: make(map[string]*gvisorRun)}
}

func (d *GvisorDriver) BindStore(store *api.Store) error {
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

func (d *GvisorDriver) ConfigureManifest(root string, key ed25519.PrivateKey) error {
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

func (d *GvisorDriver) Prepare(ctx context.Context, run api.Run) error {
	if run.Spec.Backend != gvisorBackendName {
		return fmt.Errorf("gvisor driver requires spec.backend %q", gvisorBackendName)
	}
	d.mu.Lock()
	bound := d.store != nil
	d.mu.Unlock()
	if !bound {
		return errors.New("gvisor driver is not bound to a control-plane store")
	}
	config, ok := run.Spec.Parameters["backendConfig"]
	if !ok || len(config) == 0 {
		return errors.New("spec.parameters.backendConfig is required")
	}
	if !json.Valid(config) {
		return errors.New("spec.parameters.backendConfig must be valid JSON")
	}
	spec, plan := mapGvisorRun(run, config)
	handle, err := d.backend.Prepare(ctx, spec, plan)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		_ = d.backend.Destroy(context.Background(), handle)
		return errors.New("gvisor driver is closed")
	}
	if _, exists := d.runs[run.ID]; exists {
		_ = d.backend.Destroy(context.Background(), handle)
		return fmt.Errorf("run %q is already prepared", run.ID)
	}
	d.runs[run.ID] = &gvisorRun{handle: handle, spec: spec, plan: plan, apiSpec: run.Spec}
	return nil
}

func (d *GvisorDriver) Start(ctx context.Context, runID string) error {
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
		_ = d.backend.Destroy(context.Background(), run.handle)
		d.mu.Unlock()
		return err
	}
	run.started = true
	d.wg.Add(1)
	d.mu.Unlock()
	go d.complete(runID, run)
	return nil
}

func (d *GvisorDriver) Stop(ctx context.Context, runID, reason string) error {
	d.mu.Lock()
	run, ok := d.runs[runID]
	d.mu.Unlock()
	if !ok {
		return fmt.Errorf("run %q is not prepared", runID)
	}
	return d.backend.Stop(ctx, run.handle, backend.StopReason(reason))
}

func (d *GvisorDriver) Abort(ctx context.Context, runID string) error {
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

func (d *GvisorDriver) complete(runID string, run *gvisorRun) {
	defer d.wg.Done()
	defer d.finish(runID, run)
	ctx := context.Background()
	exit, err := d.backend.Wait(ctx, run.handle)
	if err != nil {
		d.record(runID, "verification_error", "gvisor workload wait failed: "+err.Error())
		d.completeRun(runID, "failed", "backend wait failed")
		return
	}
	status := "completed"
	if exit.Code != 0 {
		status = "failed"
	}
	if err := d.completeRun(runID, status, exit.Reason); err != nil {
		return
	}
	evidenceOut, health, err := d.backend.FinalizeEvidence(ctx, run.handle)
	if err != nil {
		d.record(runID, "verification_error", "gvisor evidence finalization failed: "+err.Error())
		return
	}
	records, err := d.backend.RawRecords(ctx, run.handle)
	if err != nil {
		d.record(runID, "verification_error", "gvisor raw evidence read failed: "+err.Error())
		return
	}
	result, err := d.ineligibleReport(runID)
	if err != nil {
		d.record(runID, "verification_error", err.Error())
	} else if err := d.writeManifest(runID, run, evidenceOut, health, records, result); err != nil {
		d.record(runID, "verification_error", "write evidence manifest failed: "+err.Error())
	} else if err := d.store.SetEvidenceVerification(runID, result); err != nil {
		d.record(runID, "verification_error", "publish evidence verification failed: "+err.Error())
	}
}

func (d *GvisorDriver) ineligibleReport(runID string) (api.VerificationResult, error) {
	allEvents, ok := d.store.Events(runID)
	if !ok {
		return api.VerificationResult{}, errors.New("run events are unavailable")
	}
	chainHead, err := d.store.RunHashHead(runID)
	if err != nil {
		return api.VerificationResult{}, fmt.Errorf("read tracked event chain head: %w", err)
	}
	return api.VerificationResult{
		Status:                "ineligible",
		Eligible:              false,
		Summary:               "gvisor Phase 2 retains best-effort raw observations; verified execution is unsupported",
		CheckedAt:             time.Now().UTC(),
		TrackedEventChainHead: chainHead,
		EventCount:            uint64(len(allEvents)),
	}, nil
}

func (d *GvisorDriver) completeRun(runID, status, reason string) error {
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

func (d *GvisorDriver) writeManifest(runID string, run *gvisorRun, backendEvidence backend.BackendEvidence, health backend.SensorHealth, records []evidence.RawRecord, result api.VerificationResult) error {
	d.mu.Lock()
	root := d.manifestRoot
	key := append(ed25519.PrivateKey(nil), d.signingKey...)
	d.mu.Unlock()
	if root == "" {
		return nil
	}
	capabilities, err := d.backend.Describe(context.Background())
	if err != nil {
		return err
	}
	workloadDir, err := d.backend.RunDirectory(context.Background(), run.handle)
	if err != nil {
		return err
	}
	return publishEvidenceBundle(d.store, root, key, runID, run.apiSpec, run.spec, run.plan, capabilities, health, records, result, workloadDir, backendEvidence.ArtifactIDs, backendEvidence.RawChainHeads)
}

func (d *GvisorDriver) record(runID, status, summary string) {
	_ = d.store.SetEvidenceVerification(runID, api.VerificationResult{Status: status, Eligible: false, Summary: summary})
}

func (d *GvisorDriver) finish(runID string, run *gvisorRun) {
	if err := d.backend.Destroy(context.Background(), run.handle); err != nil {
		d.record(runID, "verification_error", "gvisor backend destroy failed: "+err.Error())
		return
	}
	d.mu.Lock()
	if d.runs[runID] == run {
		run.completed = true
	}
	d.mu.Unlock()
}

func (d *GvisorDriver) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	d.closed = true
	runs := make(map[string]*gvisorRun, len(d.runs))
	for id, run := range d.runs {
		runs[id] = run
	}
	d.mu.Unlock()
	var first error
	for id, run := range runs {
		d.mu.Lock()
		active := run.started && !run.completed
		d.mu.Unlock()
		if !active {
			continue
		}
		if err := d.backend.Stop(ctx, run.handle, backend.StopReason("shutdown")); err != nil && first == nil {
			first = fmt.Errorf("stop %s: %w", id, err)
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
	for id, run := range runs {
		d.mu.Lock()
		unfinished := !run.completed
		d.mu.Unlock()
		if !unfinished {
			continue
		}
		if err := d.backend.Destroy(ctx, run.handle); err != nil {
			if first == nil {
				first = fmt.Errorf("destroy %s: %w", id, err)
			}
			continue
		}
		d.mu.Lock()
		delete(d.runs, id)
		d.mu.Unlock()
	}
	return first
}

func (d *GvisorDriver) Close() error { return d.Shutdown(context.Background()) }

func mapGvisorRun(run api.Run, config json.RawMessage) (backend.RunSpec, backend.ObservationPlan) {
	return backend.RunSpec{
		SchemaVersion: "v1", RunID: run.ID,
		HarnessDigest: digestText("harness\x00" + run.Spec.Harness), BenchmarkDigest: digestText("suite\x00" + run.Spec.Suite),
		PolicyDigest: digestText("gvisor-config\x00" + string(config)), Profile: "development", Verified: run.Spec.Verified,
		Labels: map[string]string{"harness": run.Spec.Harness, "suite": run.Spec.Suite, "backend": run.Spec.Backend},
	}, backend.ObservationPlan{SchemaVersion: "v1", SensorConfigs: []json.RawMessage{append(json.RawMessage(nil), config...)}, OpaqueTrafficPolicy: backend.OpaqueTrafficAllow}
}
