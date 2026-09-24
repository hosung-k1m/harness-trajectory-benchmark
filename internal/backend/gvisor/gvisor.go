package gvisor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
)

const (
	sensorID       = "gvisor-container-lifecycle"
	sourceStdout   = "workload/stdout"
	sourceStderr   = "workload/stderr"
	sourceBefore   = "workspace/before"
	sourceAfter    = "workspace/after"
	sourceRunsc    = "runsc/debug"
	sourceResource = "runtime/resource"
	sourceSeccheck = "seccheck/remote"

	sourcePacketsBridge = "network/packets/bridge"
	sourcePacketsVeth   = "network/packets/veth"
	sourceNetConfig     = "network/config"
	sourceGatewayFlows  = "gateway/flows"
	sourceGatewayView   = "gateway/view"
	sourceDNS           = "dns/logs"

	mitmImage      = "mitmproxy/mitmproxy:12.2.3@sha256:62d266a86ee95187217866c0e35487837498daa3aa1cdce37d256f07e198a47b"
	mitmConfdir    = "/home/mitmproxy/.mitmproxy"
	workloadCAPath = "/etc/benchmark/mitmproxy-ca-cert.pem"
	resolverPath   = "/etc/resolv.conf"

	runtimeName      = "runsc-benchmark"
	workloadUID      = "10001"
	workloadGID      = "10001"
	maxRunIDSize     = 64
	runscLogDir      = "/var/log/benchmark-gvisor"
	seccheckDir      = "/run/benchmark-gvisor/seccheck"
	seccheckMaxFrame = 300 * 1024
	seccheckWait     = 5 * time.Second
	seccheckPoll     = 25 * time.Millisecond
	sampleInterval   = time.Second
	sampleTimeout    = 10 * time.Second
	captureDrain     = 5 * time.Second
	captureReadyWait = 2 * time.Second
	gatewayReadyWait = 5 * time.Second
	gatewayPoll      = 25 * time.Millisecond

	collectionTimeout = 60 * time.Second
)

var sourceOrder = []string{sensorID, sourceStdout, sourceStderr, sourceBefore, sourceAfter, sourceRunsc, sourceResource, sourceSeccheck, sourcePacketsBridge, sourcePacketsVeth, sourceNetConfig, sourceGatewayFlows, sourceGatewayView, sourceDNS}

type Config struct {
	RootDir string
}

type Backend struct {
	root string
	mu   sync.Mutex
	runs map[string]*run
}

func New(config Config) *Backend {
	return &Backend{root: config.RootDir, runs: make(map[string]*run)}
}

var _ backend.ExecutionBackend = (*Backend)(nil)

func manifest() backend.CapabilityManifest {
	return backend.CapabilityManifest{
		SchemaVersion: "v1", Backend: "gvisor-container", Version: "phase2.1", TrustDomain: "lima-vm-docker-daemon",
		Capabilities: []backend.Capability{
			{EventFamily: "process", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "raw", Details: map[string]string{"scope": "container init lifecycle plus runsc debug/strace and SecCheck remote point frame retention"}},
			{EventFamily: "workload/stdout", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "raw", Details: map[string]string{"scope": "docker logs bytes, not fd-level capture"}},
			{EventFamily: "workload/stderr", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "raw", Details: map[string]string{"scope": "docker logs bytes, not fd-level capture"}},
			{EventFamily: "filesystem", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "raw", Details: map[string]string{"scope": "workspace tree snapshots before and after execution; no per-access observation"}},
			{EventFamily: "dns", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "raw", Details: map[string]string{"scope": "a run-scoped resolv.conf points workload DNS at the per-run mitmproxy listener; resolver overrides, direct IP traffic, and DNS bypasses are not observed"}},
			{EventFamily: "network/packets", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "raw", Details: map[string]string{"scope": "host tcpdump full-frame pcap on the per-run bridge plus the discovered host veth; veth capture begins after container start so the startup interval is uncovered"}},
			{EventFamily: "network/config", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "raw", Details: map[string]string{"scope": "host bridge, route, iptables, and container namespace snapshots at start and stop"}},
			{EventFamily: "network/flow", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "raw", Details: map[string]string{"scope": "mitmproxy flow archive for traffic sent through the per-run gateway; non-proxied flows are absent"}},
			{EventFamily: "network/plaintext", Observation: backend.ObservationBestEffort, Enforcement: backend.EnforcementAuditOnly, Retention: "raw", Details: map[string]string{"scope": "mitmproxy flow archive is the authoritative proxy artifact; the derived mitmdump text is a human-readable view, not byte-exact wire plaintext; certificate pinning, QUIC/UDP, custom protocols, and proxy bypass remain unobserved"}},
		},
	}
}

func (b *Backend) Describe(context.Context) (backend.CapabilityManifest, error) {
	m := manifest()
	d, err := digestJSON(m)
	if err != nil {
		return backend.CapabilityManifest{}, err
	}
	m.Digest = d
	return m, nil
}

func (b *Backend) RawRecords(ctx context.Context, h backend.RunHandle) ([]evidence.RawRecord, error) {
	r, err := b.valid(h)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]evidence.RawRecord, len(r.all))
	for i, record := range r.all {
		out[i] = record
		out[i].Payload = append([]byte(nil), record.Payload...)
		if record.ObservedWallTime != nil {
			t := *record.ObservedWallTime
			out[i].ObservedWallTime = &t
		}
		if record.ObservedMonotonicNS != nil {
			v := *record.ObservedMonotonicNS
			out[i].ObservedMonotonicNS = &v
		}
	}
	return out, nil
}

func (b *Backend) RunDirectory(ctx context.Context, h backend.RunHandle) (string, error) {
	r, err := b.valid(h)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return r.evidenceDir, nil
}

type containerConfig struct {
	Type    string   `json:"type"`
	Image   string   `json:"image"`
	Command []string `json:"command"`
}

func decodeConfig(configs []json.RawMessage) (containerConfig, error) {
	if len(configs) != 1 {
		return containerConfig{}, fmt.Errorf("gvisor backend requires exactly one sensor config, got %d", len(configs))
	}
	dec := json.NewDecoder(bytes.NewReader(configs[0]))
	dec.DisallowUnknownFields()
	var config containerConfig
	if err := dec.Decode(&config); err != nil {
		return containerConfig{}, fmt.Errorf("invalid gvisor sensor config: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return containerConfig{}, errors.New("invalid gvisor sensor config: trailing JSON")
	}
	if config.Type != "gvisor/container-v1" {
		return containerConfig{}, fmt.Errorf("unsupported gvisor sensor config type %q", config.Type)
	}
	if !validImageRef(config.Image) {
		return containerConfig{}, fmt.Errorf("invalid or unsafe image reference %q", config.Image)
	}
	if len(config.Command) == 0 || strings.TrimSpace(config.Command[0]) == "" {
		return containerConfig{}, errors.New("gvisor command must have a program")
	}
	for _, arg := range config.Command {
		if arg == "" {
			return containerConfig{}, errors.New("gvisor command cannot contain empty arguments")
		}
	}
	return config, nil
}

func validRunID(id string) error {
	if len(id) == 0 || len(id) > maxRunIDSize {
		return fmt.Errorf("run ID length %d is outside 1..%d", len(id), maxRunIDSize)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') || (i == 0 && !isAlnum(c)) {
			return fmt.Errorf("run ID %q cannot be used in Docker resource names", id)
		}
	}
	return nil
}

func validImageRef(s string) bool {
	if len(s) == 0 || len(s) > 256 || !isAlnum(s[0]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAlnum(c) || c == '.' || c == '_' || c == '/' || c == ':' || c == '@' || c == '+' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (b *Backend) Prepare(ctx context.Context, spec backend.RunSpec, plan backend.ObservationPlan) (backend.RunHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := validRunID(spec.RunID); err != nil {
		return nil, err
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if spec.Verified {
		return nil, errors.New("gvisor-container cannot execute verified runs: plaintext boundary capture and structured sensors are unsupported")
	}
	m, err := b.Describe(ctx)
	if err != nil {
		return nil, err
	}
	if err := backend.ValidatePlanAgainstManifest(plan, m, false); err != nil {
		return nil, err
	}
	config, err := decodeConfig(plan.SensorConfigs)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.runs[spec.RunID]; exists {
		return nil, fmt.Errorf("run %q is already prepared", spec.RunID)
	}
	specDigest, err := digestJSON(spec)
	if err != nil {
		return nil, err
	}
	planDigest, err := digestJSON(plan)
	if err != nil {
		return nil, err
	}
	sources := make(map[string]*sourceState, len(sourceOrder))
	for _, id := range sourceOrder {
		bootID, err := randomID()
		if err != nil {
			return nil, err
		}
		seed, err := evidence.ChainSeed(specDigest, planDigest, id, bootID)
		if err != nil {
			return nil, err
		}
		sources[id] = &sourceState{id: id, bootID: bootID, seed: seed}
	}
	suffix, err := randomID()
	if err != nil {
		return nil, err
	}
	base := b.root
	if base == "" {
		base = os.TempDir()
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(base, spec.RunID+"-")
	if err != nil {
		return nil, err
	}
	r := &run{backend: b, spec: spec, plan: plan, config: config, dir: dir, sources: sources, done: make(chan struct{}), exited: make(chan struct{}), samplerDone: make(chan struct{}), state: statePrepared}
	cleanup := func() { _, _ = sudoCombined(context.Background(), "rm", "-rf", "--", dir) }
	r.workspaceDir = filepath.Join(dir, "workspace")
	r.evidenceDir = filepath.Join(dir, "evidence")
	r.rawPath = filepath.Join(r.evidenceDir, "raw-records.bin")
	r.stdoutPath = filepath.Join(r.evidenceDir, "stdout.log")
	r.stderrPath = filepath.Join(r.evidenceDir, "stderr.log")
	if out, err := sudoCombined(ctx, "install", "-d", "-m", "0700", "-o", workloadUID, "-g", workloadGID, r.workspaceDir); err != nil {
		cleanup()
		return nil, fmt.Errorf("allocate run workspace: %w: %s", err, out)
	}
	r.workspaceExists = true
	if err := os.MkdirAll(r.evidenceDir, 0o700); err != nil {
		cleanup()
		return nil, err
	}
	r.proxyDir = filepath.Join(dir, "proxy")
	if err := os.MkdirAll(r.proxyDir, 0o700); err != nil {
		cleanup()
		return nil, err
	}
	r.proxyDirExists = true
	r.resolverFile = filepath.Join(r.proxyDir, "resolv.conf")
	if err := touchPrivate(r.rawPath); err != nil {
		cleanup()
		return nil, err
	}
	r.containerName = "htb-" + spec.RunID + "-" + suffix
	r.networkName = "htb-" + spec.RunID + "-" + suffix + "-net"
	r.bridgeName = "br-" + suffix[:12]
	r.proxyName = "htb-gateway-" + spec.RunID + "-" + suffix
	b.runs[spec.RunID] = r
	return r, nil
}

func (b *Backend) Start(ctx context.Context, h backend.RunHandle) (backend.StartedRun, error) {
	r, err := b.valid(h)
	if err != nil {
		return backend.StartedRun{}, err
	}
	if err := ctx.Err(); err != nil {
		return backend.StartedRun{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != statePrepared {
		return backend.StartedRun{}, fmt.Errorf("cannot start run in %s state", r.state)
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	if out, err := dockerCombined(ctx, "network", "create", "-o", "com.docker.network.bridge.name="+r.bridgeName, r.networkName); err != nil {
		r.cancel()
		return backend.StartedRun{}, fmt.Errorf("create run network %q: %w: %s", r.networkName, err, out)
	}
	r.networkCreated = true
	r.collectWorkspaceLocked(ctx, sourceBefore, "workspace-before.tar")
	r.collectNetConfigLocked(ctx, "start")
	r.startPacketCapturesLocked(r.bridgeName, sourcePacketsBridge, "bridge")
	r.awaitCaptureReadyLocked(sourcePacketsBridge)
	r.startGatewayLocked(ctx)
	args := []string{
		"run", "--detach",
		"--name=" + r.containerName,
		"--runtime=" + runtimeName,
		"--network=" + r.networkName,
		"--pull=never",
		"--user=" + workloadUID + ":" + workloadGID,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--workdir=/workspace",
		"--mount=type=bind,src=" + r.workspaceDir + ",dst=/workspace",
	}
	if r.gatewayIP != "" {
		proxyURL := "http://" + r.gatewayIP + ":8080"
		if err := r.writeResolverLocked(); err != nil {
			r.dnsDegradedLocked()
		} else {
			args = append(args, "--mount=type=bind,src="+r.resolverFile+",dst="+resolverPath+",readonly")
		}
		args = append(args,
			"--mount=type=bind,src="+filepath.Join(r.proxyDir, "mitmproxy-ca-cert.pem")+",dst="+workloadCAPath+",readonly",
			"--env=http_proxy="+proxyURL,
			"--env=https_proxy="+proxyURL,
			"--env=HTTP_PROXY="+proxyURL,
			"--env=HTTPS_PROXY="+proxyURL,
			"--env=NODE_EXTRA_CA_CERTS="+workloadCAPath,
			"--env=SSL_CERT_FILE="+workloadCAPath,
		)
	}
	args = append(args, r.config.Image)
	args = append(args, r.config.Command...)
	out, err := dockerCombined(ctx, args...)
	if err != nil {
		r.abortStartLocked()
		return backend.StartedRun{}, fmt.Errorf("start container %q: %w: %s", r.containerName, err, out)
	}
	if !isHex64(out) {
		r.abortStartLocked()
		return backend.StartedRun{}, fmt.Errorf("docker run returned unexpected output %q, cannot attribute runsc logs", out)
	}
	r.containerID = out
	r.containerCreated = true
	r.startedAt = time.Now().UTC()
	r.state = stateStarted
	payload := fmt.Sprintf("container=%s network=%s runtime=%s image=%s id=%s", r.containerName, r.networkName, runtimeName, r.config.Image, r.containerID)
	if err := r.appendLocked(r.sources[sensorID], "container/start", "binary", []byte(payload)); err != nil {
		r.sources[sensorID].parseFailures++
	}
	if pid, err := r.containerPIDLocked(ctx); err == nil {
		r.containerPID = pid
		if veth, err := r.discoverVethLocked(ctx); err != nil {
			r.sources[sourcePacketsVeth].drops++
			r.sources[sourcePacketsVeth].degraded = true
		} else {
			r.sources[sourcePacketsVeth].streamGaps = 1
			r.startPacketCapturesLocked(veth, sourcePacketsVeth, "veth")
		}
		r.collectContainerNetConfigLocked(ctx, "start")
	} else {
		r.sources[sourcePacketsVeth].drops++
		r.sources[sourcePacketsVeth].degraded = true
		r.sources[sourceNetConfig].drops += 2
		r.sources[sourceNetConfig].degraded = true
	}
	go r.reap()
	go r.sampleResources()
	return backend.StartedRun{RunID: r.spec.RunID, StartedAt: r.startedAt}, nil
}

func (r *run) abortStartLocked() {
	r.stopCapturesLocked()
	if r.proxyCreated {
		r.proxyCreated = dockerCleanup("rm", "--force", r.proxyName) != nil
	}
	r.containerCreated = dockerCleanup("rm", "--force", r.containerName) != nil
	r.networkCreated = dockerCleanup("network", "rm", r.networkName) != nil
	if r.containerCreated || r.networkCreated {
		r.exit = backend.ExitStatus{Code: -1, Reason: "failed", ExitedAt: time.Now().UTC()}
		close(r.done)
		r.state = stateDestroying
	} else {
		r.state = statePrepared
	}
	r.cancel()
}

func (b *Backend) Wait(ctx context.Context, h backend.RunHandle) (backend.ExitStatus, error) {
	r, err := b.valid(h)
	if err != nil {
		return backend.ExitStatus{}, err
	}
	r.mu.Lock()
	if r.state == statePrepared {
		r.mu.Unlock()
		return backend.ExitStatus{}, errors.New("run has not started")
	}
	done := r.done
	r.mu.Unlock()
	select {
	case <-ctx.Done():
		return backend.ExitStatus{}, ctx.Err()
	case <-done:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exit, nil
}

func (b *Backend) Stop(ctx context.Context, h backend.RunHandle, reason backend.StopReason) error {
	r, err := b.valid(h)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.state {
	case statePrepared:
		r.state = stateStopped
		r.exit = backend.ExitStatus{Code: -1, Reason: string(reason), ExitedAt: time.Now().UTC()}
		close(r.done)
		return nil
	case stateExited, stateStopped, stateStopping, stateDestroying:
		return nil
	}
	out, err := dockerCombined(ctx, "kill", r.containerName)
	if err != nil {
		if dockerResourceGone(out) {
			return nil
		}
		select {
		case <-r.done:
			return nil
		default:
		}
		return fmt.Errorf("stop container %q: %w: %s", r.containerName, err, out)
	}
	r.state = stateStopping
	return nil
}

func (b *Backend) Snapshot(ctx context.Context, h backend.RunHandle) (backend.RunSnapshot, error) {
	r, err := b.valid(h)
	if err != nil {
		return backend.RunSnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return backend.RunSnapshot{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == stateDestroyed {
		return backend.RunSnapshot{}, errors.New("run is destroyed")
	}
	payload, err := json.Marshal(struct {
		RunID     string    `json:"runId"`
		State     string    `json:"state"`
		CreatedAt time.Time `json:"createdAt"`
	}{r.spec.RunID, string(r.state), time.Now().UTC()})
	if err != nil {
		return backend.RunSnapshot{}, err
	}
	d := backend.SHA256Hex(payload)
	path := filepath.Join(r.evidenceDir, "snapshot-"+d+".json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return backend.RunSnapshot{}, err
	}
	if err := r.appendLocked(r.sources[sensorID], "runtime/snapshot", "binary", payload); err != nil {
		return backend.RunSnapshot{}, err
	}
	return backend.RunSnapshot{ID: d, Digest: d, CreatedAt: time.Now().UTC()}, nil
}

func (b *Backend) FinalizeEvidence(ctx context.Context, h backend.RunHandle) (backend.BackendEvidence, backend.SensorHealth, error) {
	r, err := b.valid(h)
	if err != nil {
		return backend.BackendEvidence{}, backend.SensorHealth{}, err
	}
	if err := ctx.Err(); err != nil {
		return backend.BackendEvidence{}, backend.SensorHealth{}, err
	}
	r.mu.Lock()
	if r.state == stateStarted || r.state == stateStopping {
		r.mu.Unlock()
		return backend.BackendEvidence{}, backend.SensorHealth{}, errors.New("cannot finalize evidence before container exits")
	}
	if r.state == statePrepared {
		r.mu.Unlock()
		return backend.BackendEvidence{}, backend.SensorHealth{}, errors.New("cannot finalize evidence before container starts")
	}
	done := r.done
	r.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return backend.BackendEvidence{}, backend.SensorHealth{}, ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finalized {
		return r.evidenceOut, r.health, nil
	}
	if err := r.appendLocked(r.sources[sensorID], "sensor/health", "binary", []byte("network/plaintext, packet, and per-access filesystem capture unsupported; run is not verification eligible")); err != nil {
		return backend.BackendEvidence{}, backend.SensorHealth{}, err
	}
	heads := make(map[string]string, len(sourceOrder))
	for _, id := range sourceOrder {
		head, err := evidence.ValidateChain(r.sources[id].records, r.sources[id].seed)
		if err != nil {
			return backend.BackendEvidence{}, backend.SensorHealth{}, fmt.Errorf("validate %s raw chain: %w", id, err)
		}
		heads[id] = head
	}
	artifacts, err := fileDigests(r.evidenceDir)
	if err != nil {
		return backend.BackendEvidence{}, backend.SensorHealth{}, err
	}
	ids := make([]string, len(artifacts))
	for i, a := range artifacts {
		ids[i] = a.Path
	}
	d, err := digestJSON(struct {
		Artifacts []evidence.ArtifactDigest `json:"artifacts"`
		Heads     map[string]string         `json:"heads"`
	}{artifacts, heads})
	if err != nil {
		return backend.BackendEvidence{}, backend.SensorHealth{}, err
	}
	r.evidenceOut = backend.BackendEvidence{ArtifactIDs: ids, RawChainHeads: heads, Digest: d}
	sources := make([]backend.SensorSourceHealth, 0, len(sourceOrder))
	var appenderDrops uint64
	for _, id := range sourceOrder {
		src := r.sources[id]
		end := uint64(len(src.records))
		var start uint64
		if end > 0 {
			start = 1
		}
		source := backend.SensorSourceHealth{
			SensorID: id, BootID: src.bootID,
			ExpectedStart: start, ExpectedEnd: end,
			ObservedStart: start, ObservedEnd: end,
			Drops: src.drops, ParseFailures: src.parseFailures, StreamGaps: src.streamGaps,
			Started: end > 0, Drained: end > 0 && !src.degraded, Stopped: end > 0 && !src.degraded,
		}
		if id == sensorID {
			source.PlaintextFailures = 1
		}
		appenderDrops += src.parseFailures
		sources = append(sources, source)
	}
	r.health = backend.SensorHealth{SchemaVersion: "v1", Sources: sources, AppenderDrops: appenderDrops}
	r.finalized = true
	return r.evidenceOut, r.health, nil
}

func (b *Backend) Destroy(ctx context.Context, h backend.RunHandle) error {
	r, ok := h.(*run)
	if !ok || r == nil || r.backend != b {
		return errors.New("invalid gvisor backend run handle")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	destroyed := r.state == stateDestroyed
	r.mu.Unlock()
	b.mu.Lock()
	known := b.runs[r.spec.RunID] == r
	b.mu.Unlock()
	if !known {
		if destroyed {
			return nil
		}
		return errors.New("unknown or destroyed gvisor backend run handle")
	}
	r.mu.Lock()
	state := r.state
	r.mu.Unlock()
	if state == stateStarted || state == stateStopping {
		if err := b.Stop(ctx, h, "destroy"); err != nil {
			return err
		}
		select {
		case <-r.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == stateDestroyed {
		return nil
	}
	if r.state == statePrepared {
		r.exit = backend.ExitStatus{Code: -1, Reason: "destroy", ExitedAt: time.Now().UTC()}
		close(r.done)
	}
	r.state = stateDestroying
	var first error
	if r.proxyCreated {
		if out, err := dockerCombined(ctx, "rm", "--force", r.proxyName); err != nil && !dockerResourceGone(out) {
			if first == nil {
				first = fmt.Errorf("remove gateway %q: %w: %s", r.proxyName, err, out)
			}
		} else {
			r.proxyCreated = false
		}
	}
	if r.containerCreated {
		if out, err := dockerCombined(ctx, "rm", "--force", r.containerName); err != nil && !dockerResourceGone(out) {
			if first == nil {
				first = fmt.Errorf("remove container %q: %w: %s", r.containerName, err, out)
			}
		} else {
			r.containerCreated = false
		}
	}
	if r.networkCreated {
		if out, err := dockerCombined(ctx, "network", "rm", r.networkName); err != nil && !dockerResourceGone(out) {
			if first == nil {
				first = fmt.Errorf("remove network %q: %w: %s", r.networkName, err, out)
			}
		} else {
			r.networkCreated = false
		}
	}
	if r.workspaceExists {
		if out, err := sudoCombined(ctx, "rm", "-rf", "--", r.workspaceDir); err != nil {
			if first == nil {
				first = fmt.Errorf("remove workspace: %w: %s", err, out)
			}
		} else {
			r.workspaceExists = false
		}
	}
	if r.proxyDirExists {
		if err := os.RemoveAll(r.proxyDir); err != nil {
			if first == nil {
				first = fmt.Errorf("remove gateway proxy dir: %w", err)
			}
		} else {
			r.proxyDirExists = false
		}
	}
	if first != nil {
		return first
	}
	r.state = stateDestroyed
	if r.cancel != nil {
		r.cancel()
	}
	b.mu.Lock()
	delete(b.runs, r.spec.RunID)
	b.mu.Unlock()
	return nil
}

func (b *Backend) valid(h backend.RunHandle) (*run, error) {
	r, ok := h.(*run)
	if !ok || r == nil || r.backend != b {
		return nil, errors.New("invalid gvisor backend run handle")
	}
	b.mu.Lock()
	current := b.runs[r.spec.RunID]
	b.mu.Unlock()
	if current != r {
		return nil, errors.New("unknown or destroyed gvisor backend run handle")
	}
	return r, nil
}

type runState string

const (
	statePrepared   runState = "prepared"
	stateStarted    runState = "started"
	stateStopping   runState = "stopping"
	stateStopped    runState = "stopped"
	stateExited     runState = "exited"
	stateDestroying runState = "destroying"
	stateDestroyed  runState = "destroyed"
)

type sourceState struct {
	id            string
	bootID        string
	seed          string
	records       []evidence.RawRecord
	drops         uint64
	parseFailures uint64
	streamGaps    uint64
	degraded      bool
}

type capture struct {
	source     string
	iface      string
	direction  string
	pcapPath   string
	statsPath  string
	cmd        *exec.Cmd
	wait       chan error
	statsFile  *os.File
	ready      chan struct{}
	streamDone chan struct{}
	stopped    bool
	exited     bool
	waitErr    error
}

type run struct {
	backend          *Backend
	spec             backend.RunSpec
	plan             backend.ObservationPlan
	config           containerConfig
	dir              string
	workspaceDir     string
	evidenceDir      string
	rawPath          string
	stdoutPath       string
	stderrPath       string
	containerName    string
	networkName      string
	bridgeName       string
	containerID      string
	containerPID     int
	proxyName        string
	proxyDir         string
	resolverFile     string
	gatewayIP        string
	proxyCreated     bool
	proxyDirExists   bool
	captures         []*capture
	mu               sync.Mutex
	state            runState
	ctx              context.Context
	cancel           context.CancelFunc
	startedAt        time.Time
	exit             backend.ExitStatus
	done             chan struct{}
	exited           chan struct{}
	samplerDone      chan struct{}
	networkCreated   bool
	containerCreated bool
	workspaceExists  bool
	sources          map[string]*sourceState
	all              []evidence.RawRecord
	finalized        bool
	evidenceOut      backend.BackendEvidence
	health           backend.SensorHealth
}

func (r *run) RunID() string { return r.spec.RunID }

func (r *run) reap() {
	defer r.cancel()
	out, err := dockerCmd(r.ctx, "wait", r.containerName).Output()
	code, reason := -1, "failed"
	waitDrop, waitParse := false, false
	if err != nil {
		waitDrop = true
	} else if n, perr := strconv.Atoi(strings.TrimSpace(string(out))); perr == nil {
		code, reason = n, "exited"
	} else {
		waitParse = true
	}
	collectCtx, collectCancel := context.WithTimeout(r.ctx, collectionTimeout)
	defer collectCancel()
	r.mu.Lock()
	if waitDrop {
		r.sources[sensorID].drops++
	}
	if waitParse {
		r.sources[sensorID].parseFailures++
	}
	if r.state == stateStopping {
		reason = "stopped"
	}
	r.exit = backend.ExitStatus{Code: code, Reason: reason, ExitedAt: time.Now().UTC()}
	r.state = stateExited
	if appendErr := r.appendLocked(r.sources[sensorID], "container/exit", "binary", []byte(fmt.Sprintf("code=%d reason=%s", code, reason))); appendErr != nil {
		r.sources[sensorID].parseFailures++
	}
	close(r.exited)
	r.collectLogsLocked(collectCtx)
	r.collectWorkspaceLocked(collectCtx, sourceAfter, "workspace-after.tar")
	r.collectRunscLocked(collectCtx)
	r.collectSeccheckLocked(collectCtx)
	r.collectGatewayLocked(collectCtx)
	r.stopCapturesLocked()
	r.collectNetConfigLocked(collectCtx, "stop")
	if _, err := r.containerPIDLocked(collectCtx); err == nil {
		r.collectContainerNetConfigLocked(collectCtx, "stop")
	} else {
		r.sources[sourceNetConfig].drops += 2
		r.sources[sourceNetConfig].degraded = true
	}
	r.mu.Unlock()
	<-r.samplerDone
	r.mu.Lock()
	close(r.done)
	r.mu.Unlock()
}

func (r *run) collectLogsLocked(ctx context.Context) {
	streams := map[string]*artifactWriter{}
	for _, s := range []struct {
		source string
		path   string
	}{{sourceStdout, r.stdoutPath}, {sourceStderr, r.stderrPath}} {
		w, err := openArtifact(s.path)
		if err != nil {
			r.sources[s.source].drops++
			continue
		}
		streams[s.source] = w
	}
	cmd := dockerCmd(ctx, "logs", r.containerName)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if w, ok := streams[sourceStdout]; ok {
		cmd.Stdout = w
	}
	if w, ok := streams[sourceStderr]; ok {
		cmd.Stderr = w
	}
	runErr := cmd.Run()
	for source, w := range streams {
		closeErr := w.close()
		if runErr != nil || closeErr != nil {
			_ = os.Remove(w.path)
			r.sources[source].drops++
			continue
		}
		if err := r.appendArtifactLocked(r.sources[source], source, filepath.Base(w.path), w.digest(), w.size); err != nil {
			r.sources[source].parseFailures++
		}
	}
}

func (r *run) collectWorkspaceLocked(ctx context.Context, sourceID, artifact string) {
	src := r.sources[sourceID]
	path := filepath.Join(r.evidenceDir, artifact)
	if err := touchPrivate(path); err != nil {
		src.drops++
		return
	}
	if _, err := sudoCombined(ctx, "tar", "-cf", path, "-C", r.workspaceDir, "."); err != nil {
		_ = os.Remove(path)
		src.drops++
		return
	}
	digest, size, err := digestFile(path)
	if err != nil {
		_ = os.Remove(path)
		src.drops++
		return
	}
	if err := r.appendArtifactLocked(src, "workspace/snapshot", artifact, digest, size); err != nil {
		src.parseFailures++
	}
}

func (r *run) collectRunscLocked(ctx context.Context) {
	src := r.sources[sourceRunsc]
	out, err := sudoOut(ctx, "ls", "-1", runscLogDir)
	if err != nil {
		src.drops++
		return
	}
	prefix := "runsc." + r.containerID + "."
	var names []string
	for _, name := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".log") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		src.drops++
		return
	}
	for _, name := range names {
		dst := filepath.Join(r.evidenceDir, name)
		if err := touchPrivate(dst); err != nil {
			src.drops++
			continue
		}
		if _, err := sudoCombined(ctx, "cp", filepath.Join(runscLogDir, name), dst); err != nil {
			_ = os.Remove(dst)
			src.drops++
			continue
		}
		digest, size, err := digestFile(dst)
		if err != nil {
			_ = os.Remove(dst)
			src.drops++
			continue
		}
		if err := r.appendArtifactLocked(src, "runsc/log", name, digest, size); err != nil {
			src.parseFailures++
		}
	}
}

type seccheckStatus struct {
	Frames        uint64 `json:"frames"`
	Oversize      uint64 `json:"oversize"`
	ReportedDrops uint64 `json:"reportedDrops"`
}

func (r *run) collectSeccheckLocked(ctx context.Context) {
	src := r.sources[sourceSeccheck]
	src.degraded = true
	statusName := r.containerID + ".done"
	framesName := r.containerID + ".frames"
	deadline := time.Now().Add(seccheckWait)
	for {
		out, err := sudoOut(ctx, "ls", "-1", seccheckDir)
		if err != nil {
			src.drops++
			return
		}
		found := false
		for _, name := range strings.Split(string(out), "\n") {
			if name == statusName {
				found = true
				break
			}
		}
		if found {
			break
		}
		if !time.Now().Before(deadline) {
			r.copyTrustedLocked(ctx, filepath.Join(seccheckDir, framesName), filepath.Join(r.evidenceDir, "seccheck.partial"))
			src.drops++
			return
		}
		timer := time.NewTimer(seccheckPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			src.drops++
			return
		case <-timer.C:
		}
	}
	statusDst := filepath.Join(r.evidenceDir, "seccheck.done")
	framesDst := filepath.Join(r.evidenceDir, "seccheck.frames")
	statusCopied, framesCopied := false, false
	retain := func() {
		if framesCopied {
			_ = os.Rename(framesDst, filepath.Join(r.evidenceDir, "seccheck.partial"))
		}
		if statusCopied {
			_ = os.Rename(statusDst, filepath.Join(r.evidenceDir, "seccheck.partial-status"))
		}
	}
	if err := r.copyTrustedLocked(ctx, filepath.Join(seccheckDir, statusName), statusDst); err != nil {
		src.drops++
		return
	}
	statusCopied = true
	if err := r.copyTrustedLocked(ctx, filepath.Join(seccheckDir, framesName), framesDst); err != nil {
		src.drops++
		retain()
		return
	}
	framesCopied = true
	status, err := parseSeccheckStatus(statusDst)
	if err != nil {
		src.parseFailures++
		retain()
		return
	}
	parsed, err := r.appendSeccheckFramesLocked(src, framesDst)
	if err != nil || parsed != status.Frames || status.Oversize > math.MaxUint64-status.ReportedDrops {
		src.parseFailures++
		retain()
		return
	}
	src.drops += status.Oversize + status.ReportedDrops
	src.degraded = false
}

func (r *run) copyTrustedLocked(ctx context.Context, name, dst string) error {
	if err := touchPrivate(dst); err != nil {
		return err
	}
	if _, err := sudoCombined(ctx, "cp", name, dst); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}

func parseSeccheckStatus(path string) (seccheckStatus, error) {
	f, err := os.Open(path)
	if err != nil {
		return seccheckStatus{}, err
	}
	defer f.Close()
	var status seccheckStatus
	dec := json.NewDecoder(io.LimitReader(f, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&status); err != nil {
		return seccheckStatus{}, err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return seccheckStatus{}, errors.New("trailing data in seccheck status")
	}
	return status, nil
}

func (r *run) appendSeccheckFramesLocked(src *sourceState, path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var parsed uint64
	var lenBuf [4]byte
	for {
		if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return parsed, nil
			}
			return parsed, err
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n == 0 || n > seccheckMaxFrame {
			return parsed, fmt.Errorf("invalid seccheck frame length %d", n)
		}
		frame := make([]byte, n)
		if _, err := io.ReadFull(f, frame); err != nil {
			return parsed, err
		}
		if err := r.appendLocked(src, "seccheck/frame", "protobuf", frame); err != nil {
			src.parseFailures++
			continue
		}
		parsed++
	}
}

func (r *run) containerPIDLocked(ctx context.Context) (int, error) {
	out, err := dockerCombined(ctx, "inspect", "--format", "{{.State.Pid}}", r.containerName)
	if err != nil {
		return 0, fmt.Errorf("inspect container %q pid: %w: %s", r.containerName, err, out)
	}
	pid, err := strconv.Atoi(out)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("container %q reported invalid pid %q", r.containerName, out)
	}
	return pid, nil
}

func (r *run) discoverVethLocked(ctx context.Context) (string, error) {
	peerOut, err := sudoCombined(ctx, "nsenter", "-t", strconv.Itoa(r.containerPID), "-n", "ip", "-j", "link", "show", "dev", "eth0")
	if err != nil {
		return "", fmt.Errorf("nsenter eth0 link: %w: %s", err, peerOut)
	}
	var peers []struct {
		LinkIndex int `json:"link_index"`
	}
	if err := json.Unmarshal([]byte(peerOut), &peers); err != nil || len(peers) != 1 || peers[0].LinkIndex <= 0 {
		return "", fmt.Errorf("unexpected eth0 link data %q", peerOut)
	}
	linksOut, err := sudoCombined(ctx, "ip", "-j", "link", "show")
	if err != nil {
		return "", fmt.Errorf("host link list: %w: %s", err, linksOut)
	}
	var links []struct {
		Ifindex int    `json:"ifindex"`
		Ifname  string `json:"ifname"`
		Master  string `json:"master"`
	}
	if err := json.Unmarshal([]byte(linksOut), &links); err != nil {
		return "", fmt.Errorf("parse host link list: %w", err)
	}
	var matches []string
	for _, link := range links {
		if link.Ifindex == peers[0].LinkIndex && link.Master == r.bridgeName && strings.HasPrefix(link.Ifname, "veth") {
			matches = append(matches, link.Ifname)
		}
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("expected exactly one veth peer on %s for ifindex %d, got %v", r.bridgeName, peers[0].LinkIndex, matches)
	}
	return matches[0], nil
}

func (r *run) startPacketCapturesLocked(iface, source, prefix string) {
	src := r.sources[source]
	for _, dir := range []struct {
		name string
		q    string
	}{{"ingress", "in"}, {"egress", "out"}} {
		artifact := prefix + "-" + dir.name + ".pcap"
		pcapPath := filepath.Join(r.evidenceDir, artifact)
		statsPath := pcapPath + ".stats"
		metaPath := pcapPath + ".meta"
		if err := touchPrivate(pcapPath); err != nil {
			src.drops++
			src.degraded = true
			continue
		}
		stats, err := os.OpenFile(statsPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = os.Remove(pcapPath)
			src.drops++
			src.degraded = true
			continue
		}
		meta, err := json.Marshal(struct {
			Interface string    `json:"interface"`
			Direction string    `json:"direction"`
			StartedAt time.Time `json:"startedAt"`
		}{iface, dir.name, time.Now().UTC()})
		if err != nil {
			meta = nil
		}
		if err := writePrivate(metaPath, append(meta, '\n')); err != nil {
			_ = stats.Close()
			_ = os.Remove(pcapPath)
			_ = os.Remove(statsPath)
			src.drops++
			src.degraded = true
			continue
		}
		cmd := exec.Command("sudo", "-n", "tcpdump", "-n", "-U", "-s", "0", "-Q", dir.q, "-i", iface, "-w", pcapPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Stdout = io.Discard
		stderr, err := cmd.StderrPipe()
		if err != nil {
			_ = stats.Close()
			_ = os.Remove(pcapPath)
			_ = os.Remove(statsPath)
			_ = os.Remove(metaPath)
			src.drops++
			src.degraded = true
			continue
		}
		if err := cmd.Start(); err != nil {
			_ = stats.Close()
			_ = os.Remove(pcapPath)
			_ = os.Remove(statsPath)
			_ = os.Remove(metaPath)
			src.drops++
			src.degraded = true
			continue
		}
		c := &capture{source: source, iface: iface, direction: dir.name, pcapPath: pcapPath, statsPath: statsPath, cmd: cmd, wait: make(chan error, 1), statsFile: stats, ready: make(chan struct{}), streamDone: make(chan struct{})}
		go func() { c.wait <- cmd.Wait() }()
		go c.streamStats(stderr)
		r.captures = append(r.captures, c)
	}
}

func (c *capture) streamStats(stderr io.Reader) {
	defer close(c.streamDone)
	br := bufio.NewReader(stderr)
	ready := false
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			_, _ = c.statsFile.WriteString(line)
			if !ready && strings.Contains(line, "listening on") {
				ready = true
				close(c.ready)
			}
		}
		if err != nil {
			return
		}
	}
}

func (r *run) awaitCaptureReadyLocked(source string) {
	src := r.sources[source]
	timer := time.NewTimer(captureReadyWait)
	defer timer.Stop()
	for _, c := range r.captures {
		if c.source != source || c.ready == nil {
			continue
		}
		select {
		case <-c.ready:
		case <-timer.C:
			src.streamGaps++
			src.degraded = true
			return
		}
	}
}

func (r *run) stopCapturesLocked() {
	for _, c := range r.captures {
		if c.stopped {
			continue
		}
		select {
		case c.waitErr = <-c.wait:
			c.exited = true
		default:
			_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGINT)
		}
	}
	deadline := time.Now().Add(captureDrain)
	for _, c := range r.captures {
		if c.stopped {
			continue
		}
		c.stopped = true
		src := r.sources[c.source]
		waitErr := c.waitErr
		if !c.exited {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				select {
				case waitErr = <-c.wait:
				default:
					_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
					waitErr = <-c.wait
					src.drops++
					src.degraded = true
				}
			} else {
				timer := time.NewTimer(remaining)
				select {
				case waitErr = <-c.wait:
					timer.Stop()
				case <-timer.C:
					select {
					case waitErr = <-c.wait:
					default:
						_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
						waitErr = <-c.wait
						src.drops++
						src.degraded = true
					}
				}
			}
		}
		if waitErr != nil {
			src.drops++
			src.degraded = true
		}
		<-c.streamDone
		_ = c.statsFile.Close()
		owner := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
		chownCtx, chownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, chownErr := sudoCombined(chownCtx, "chown", owner, c.pcapPath)
		chownCancel()
		if chownErr != nil {
			src.drops++
			src.degraded = true
			continue
		}
		stats, err := os.ReadFile(c.statsPath)
		if err != nil {
			src.parseFailures++
			src.degraded = true
		} else if dropped, ok := parseKernelDrops(string(stats)); !ok {
			src.parseFailures++
			src.degraded = true
		} else {
			src.drops += dropped
		}
		digest, size, err := digestFile(c.pcapPath)
		if err != nil {
			src.drops++
			src.degraded = true
			continue
		}
		if err := r.appendNetArtifactLocked(src, "network/packet", filepath.Base(c.pcapPath), digest, size, c.iface, c.direction, ""); err != nil {
			src.parseFailures++
			src.degraded = true
		}
	}
}

func parseKernelDrops(stats string) (uint64, bool) {
	for _, line := range strings.Split(stats, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 5 || fields[1] != "packets" || fields[2] != "dropped" || fields[3] != "by" || fields[4] != "kernel" {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		return n, true
	}
	return 0, false
}

func (r *run) startGatewayLocked(ctx context.Context) {
	out, err := dockerCombined(ctx, "run", "--detach",
		"--name="+r.proxyName,
		"--network="+r.networkName,
		"--network-alias=htb-gateway",
		"--pull=never",
		"--mount=type=bind,src="+r.proxyDir+",dst="+mitmConfdir,
		mitmImage,
		"mitmdump", "--mode", "regular@8080", "--mode", "dns@53",
		"--listen-host", "0.0.0.0", "--set", "confdir="+mitmConfdir,
		"-w", mitmConfdir+"/flows.mitm")
	if err != nil {
		r.gatewayDegradedLocked()
		return
	}
	_ = out
	r.proxyCreated = true
	if !r.awaitGatewayLocked(ctx) {
		return
	}
}

func (r *run) gatewayDegradedLocked() {
	for _, id := range []string{sourceGatewayFlows, sourceGatewayView, sourceDNS} {
		r.sources[id].drops++
		r.sources[id].degraded = true
	}
}

func (r *run) dnsDegradedLocked() {
	r.sources[sourceDNS].drops++
	r.sources[sourceDNS].degraded = true
}

func (r *run) writeResolverLocked() error {
	ip := net.ParseIP(r.gatewayIP)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid gateway IPv4 %q", r.gatewayIP)
	}
	return writeExclusive(r.resolverFile, []byte("nameserver "+ip.To4().String()+"\n"), 0o644)
}

func regularFile(path string) bool {
	st, err := os.Lstat(path)
	return err == nil && st.Mode().IsRegular()
}

func (r *run) awaitGatewayLocked(ctx context.Context) bool {
	certPath := filepath.Join(r.proxyDir, "mitmproxy-ca-cert.pem")
	flowsPath := filepath.Join(r.proxyDir, "flows.mitm")
	deadline := time.Now().Add(gatewayReadyWait)
	for {
		running := false
		if out, err := dockerCombined(ctx, "inspect", "--format", "{{.State.Running}}", r.proxyName); err == nil {
			running = strings.TrimSpace(out) == "true"
		}
		if running && regularFile(certPath) && regularFile(flowsPath) {
			ip, err := r.gatewayIPLocked(ctx)
			if err == nil {
				if err := probeGatewayListeners(ctx, r.proxyName); err == nil {
					r.gatewayIP = ip
					return true
				}
			} else {
				r.gatewayDegradedLocked()
				return false
			}
		}
		if time.Now().After(deadline) {
			r.gatewayDegradedLocked()
			return false
		}
		select {
		case <-ctx.Done():
			r.gatewayDegradedLocked()
			return false
		case <-time.After(gatewayPoll):
		}
	}
}

const gatewayProbeScript = `import socket, struct
with socket.create_connection(("127.0.0.1", 8080), timeout=0.5) as proxy:
    proxy.settimeout(0.5)
    proxy.sendall(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
    if not proxy.recv(64).startswith(b"HTTP/1."):
        raise RuntimeError("HTTP CONNECT listener did not respond")
query = struct.pack("!HHHHHH", 0x4854, 0x0100, 1, 0, 0, 0) + b"\x09localhost\x00\x00\x01\x00\x01"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
    dns.settimeout(0.5)
    dns.sendto(query, ("127.0.0.1", 53))
    response, _ = dns.recvfrom(512)
    if len(response) < 12 or response[:2] != query[:2] or not response[2] & 0x80:
        raise RuntimeError("DNS listener did not respond")`

func probeGatewayListeners(ctx context.Context, name string) error {
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	out, err := dockerCombined(probeCtx, "exec", name, "python", "-c", gatewayProbeScript)
	if err != nil {
		return fmt.Errorf("probe gateway listeners: %w: %s", err, out)
	}
	return nil
}

func (r *run) gatewayIPLocked(ctx context.Context) (string, error) {
	out, err := dockerCombined(ctx, "inspect", "--format", "{{json .NetworkSettings.Networks}}", r.proxyName)
	if err != nil {
		return "", fmt.Errorf("inspect gateway %q networks: %w: %s", r.proxyName, err, out)
	}
	var nets map[string]struct {
		IPAddress string `json:"IPAddress"`
	}
	if err := json.Unmarshal([]byte(out), &nets); err != nil {
		return "", fmt.Errorf("parse gateway %q networks: %w", r.proxyName, err)
	}
	entry, ok := nets[r.networkName]
	if !ok {
		return "", fmt.Errorf("gateway %q is not attached to run network %q", r.proxyName, r.networkName)
	}
	ip := net.ParseIP(entry.IPAddress)
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("gateway %q reported invalid IPv4 %q", r.proxyName, entry.IPAddress)
	}
	return ip.To4().String(), nil
}

func (r *run) collectGatewayLocked(ctx context.Context) {
	if !r.proxyCreated {
		return
	}
	if out, err := dockerCombined(ctx, "stop", "--time=3", r.proxyName); err != nil {
		_ = out
		r.gatewayDegradedLocked()
	}
	certPath := filepath.Join(r.proxyDir, "mitmproxy-ca-cert.pem")
	if regularFile(certPath) {
		if err := copyPrivate(certPath, filepath.Join(r.evidenceDir, "gateway-ca-cert.pem")); err != nil {
			r.sources[sourceGatewayFlows].drops++
			r.sources[sourceGatewayFlows].degraded = true
		}
	}
	src := r.sources[sourceGatewayFlows]
	flowsPath := filepath.Join(r.proxyDir, "flows.mitm")
	if !regularFile(flowsPath) {
		src.drops++
		src.degraded = true
	} else {
		dst := filepath.Join(r.evidenceDir, "gateway-flows.mitm")
		if err := copyPrivate(flowsPath, dst); err != nil {
			src.drops++
			src.degraded = true
		} else if digest, size, err := digestFile(dst); err != nil {
			src.drops++
			src.degraded = true
		} else if err := r.appendArtifactLocked(src, "gateway/flow", "gateway-flows.mitm", digest, size); err != nil {
			src.parseFailures++
			src.degraded = true
		}
	}
	r.collectGatewayLogLocked(ctx)
	r.renderFlowsLocked(ctx, sourceGatewayView, "gateway/view", "gateway-plaintext.txt", []string{"--flow-detail", "4"})
	if r.renderFlowsLocked(ctx, sourceDNS, "dns/log", "dns.log", []string{"--set", "dumper_filter=~dns", "--flow-detail", "3"}) {
		r.recordDNSCountLocked()
	}
}

func (r *run) recordDNSCountLocked() {
	src := r.sources[sourceDNS]
	data, err := os.ReadFile(filepath.Join(r.evidenceDir, "dns.log"))
	if err != nil {
		src.drops++
		src.degraded = true
		return
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "DNS QUERY (") {
			count++
		}
	}
	metadata, err := json.Marshal(struct {
		RenderedQueryLines     int  `json:"renderedQueryLines"`
		IncludesReadinessProbe bool `json:"includesReadinessProbe"`
	}{count, true})
	if err != nil {
		src.parseFailures++
		src.degraded = true
		return
	}
	name := "dns-observation.json"
	path := filepath.Join(r.evidenceDir, name)
	if err := os.WriteFile(path, append(metadata, '\n'), 0o600); err != nil {
		src.drops++
		src.degraded = true
		return
	}
	digest, size, err := digestFile(path)
	if err != nil {
		src.drops++
		src.degraded = true
		return
	}
	if err := r.appendArtifactLocked(src, "dns/observation", name, digest, size); err != nil {
		src.parseFailures++
		src.degraded = true
	}
}

func (r *run) collectGatewayLogLocked(ctx context.Context) {
	path := filepath.Join(r.evidenceDir, "gateway.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		r.sources[sourceGatewayFlows].drops++
		r.sources[sourceGatewayFlows].degraded = true
		return
	}
	cmd := dockerCmd(ctx, "logs", r.proxyName)
	cmd.Stdout = f
	cmd.Stderr = f
	runErr := cmd.Run()
	closeErr := f.Close()
	if runErr != nil || closeErr != nil {
		r.sources[sourceGatewayFlows].drops++
		r.sources[sourceGatewayFlows].degraded = true
	}
}

func (r *run) renderFlowsLocked(ctx context.Context, sourceID, recordType, artifact string, extra []string) bool {
	src := r.sources[sourceID]
	path := filepath.Join(r.evidenceDir, artifact)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		src.drops++
		src.degraded = true
		return false
	}
	args := []string{"run", "--rm", "--pull=never", "--network", "none",
		"--mount=type=bind,src=" + r.proxyDir + ",dst=" + mitmConfdir + ",readonly",
		mitmImage, "mitmdump", "-nr", mitmConfdir + "/flows.mitm"}
	args = append(args, extra...)
	cmd := dockerCmd(ctx, args...)
	cmd.Stdout = f
	cmd.Stderr = io.Discard
	runErr := cmd.Run()
	closeErr := f.Close()
	if runErr != nil || closeErr != nil {
		_ = os.Remove(path)
		src.parseFailures++
		src.degraded = true
		return false
	}
	digest, size, err := digestFile(path)
	if err != nil {
		src.drops++
		src.degraded = true
		return false
	}
	if err := r.appendArtifactLocked(src, recordType, artifact, digest, size); err != nil {
		src.parseFailures++
		src.degraded = true
		return false
	}
	return true
}

func copyPrivate(srcPath, dstPath string) error {
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dstPath)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dstPath)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dstPath)
		return err
	}
	return nil
}

func (r *run) collectNetConfigLocked(ctx context.Context, phase string) {
	src := r.sources[sourceNetConfig]
	failed := false
	for _, snap := range []struct {
		artifact string
		iface    string
		args     []string
	}{
		{"net-inspect-" + phase + ".json", r.bridgeName, []string{"docker", "network", "inspect", r.networkName}},
		{"bridge-addr-" + phase + ".json", r.bridgeName, []string{"ip", "-j", "addr", "show", "dev", r.bridgeName}},
		{"route-" + phase + ".json", "host", []string{"ip", "-j", "route"}},
		{"bridge-link-" + phase + ".txt", r.bridgeName, []string{"ip", "-s", "link", "show", "dev", r.bridgeName}},
		{"iptables-" + phase + ".txt", "host", []string{"iptables-save"}},
		{"nft-" + phase + ".txt", "host", []string{"nft", "list", "ruleset"}},
	} {
		if !r.collectSnapshotLocked(ctx, src, snap.artifact, snap.iface, phase, snap.args) {
			failed = true
		}
	}
	src.degraded = src.degraded || failed
}

func (r *run) collectContainerNetConfigLocked(ctx context.Context, phase string) {
	if r.containerPID <= 0 {
		return
	}
	src := r.sources[sourceNetConfig]
	pid := strconv.Itoa(r.containerPID)
	failed := false
	for _, snap := range []struct {
		artifact string
		args     []string
	}{
		{"eth0-addr-" + phase + ".json", []string{"nsenter", "-t", pid, "-n", "ip", "-j", "addr"}},
		{"eth0-route-" + phase + ".json", []string{"nsenter", "-t", pid, "-n", "ip", "-j", "route"}},
	} {
		if !r.collectSnapshotLocked(ctx, src, snap.artifact, "eth0", phase, snap.args) {
			failed = true
		}
	}
	src.degraded = src.degraded || failed
}

func (r *run) collectSnapshotLocked(ctx context.Context, src *sourceState, artifact, iface, phase string, args []string) bool {
	out, err := sudoOut(ctx, args...)
	if err != nil {
		src.drops++
		return false
	}
	path := filepath.Join(r.evidenceDir, artifact)
	if err := writePrivate(path, out); err != nil {
		src.drops++
		return false
	}
	digest, size, err := digestFile(path)
	if err != nil {
		_ = os.Remove(path)
		src.drops++
		return false
	}
	if err := r.appendNetArtifactLocked(src, "network/config", artifact, digest, size, iface, "", phase); err != nil {
		src.parseFailures++
		return false
	}
	return true
}

func (r *run) appendNetArtifactLocked(src *sourceState, recordType, name, digest string, size uint64, iface, direction, phase string) error {
	meta, err := json.Marshal(struct {
		Artifact  string `json:"artifact"`
		SHA256    string `json:"sha256"`
		Size      uint64 `json:"size"`
		Interface string `json:"interface,omitempty"`
		Direction string `json:"direction,omitempty"`
		Phase     string `json:"phase,omitempty"`
	}{name, digest, size, iface, direction, phase})
	if err != nil {
		return err
	}
	return r.appendLocked(src, recordType, "json", meta)
}

func writePrivate(path string, data []byte) error {
	return writeExclusive(path, data, 0o600)
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

func (r *run) sampleResources() {
	defer close(r.samplerDone)
	r.sampleOnce()
	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.exited:
			r.sampleOnce()
			return
		case <-ticker.C:
			r.sampleOnce()
		}
	}
}

func (r *run) sampleOnce() {
	ctx, cancel := context.WithTimeout(r.ctx, sampleTimeout)
	out, err := dockerCmd(ctx, "stats", "--no-stream", r.containerName).Output()
	cancel()
	src := r.sources[sourceResource]
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		src.drops++
		return
	}
	if err := r.appendLocked(src, "resource/sample", "binary", out); err != nil {
		src.parseFailures++
	}
}

func (r *run) appendArtifactLocked(src *sourceState, recordType, name, digest string, size uint64) error {
	meta, err := json.Marshal(struct {
		Artifact string `json:"artifact"`
		SHA256   string `json:"sha256"`
		Size     uint64 `json:"size"`
	}{name, digest, size})
	if err != nil {
		return err
	}
	return r.appendLocked(src, recordType, "json", meta)
}

func (r *run) appendLocked(src *sourceState, recordType, encoding string, payload []byte) error {
	now := time.Now().UTC()
	seq := uint64(len(src.records) + 1)
	prev := ""
	if seq > 1 {
		prev = src.records[len(src.records)-1].RecordSHA256
	}
	record := evidence.RawRecord{RunID: r.spec.RunID, SensorID: src.id, BootID: src.bootID, SourceSeq: seq, ObservedWallTime: &now, RecordType: recordType, Encoding: encoding, Payload: append([]byte(nil), payload...), PreviousRecordSHA256: prev}
	hash, err := record.ComputedHash()
	if err != nil {
		return err
	}
	record.RecordSHA256 = hash
	frame, err := record.Frame()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(r.rawPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(frame)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	src.records = append(src.records, record)
	r.all = append(r.all, record)
	return nil
}

func sudoCmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "sudo", append([]string{"-n"}, args...)...)
}

func sudoCombined(ctx context.Context, args ...string) (string, error) {
	out, err := sudoCmd(ctx, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func sudoOut(ctx context.Context, args ...string) ([]byte, error) {
	return sudoCmd(ctx, args...).Output()
}

func dockerCmd(ctx context.Context, args ...string) *exec.Cmd {
	return sudoCmd(ctx, append([]string{"docker"}, args...)...)
}

func dockerCombined(ctx context.Context, args ...string) (string, error) {
	out, err := dockerCmd(ctx, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func dockerCleanup(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := dockerCombined(ctx, args...)
	return err
}

func dockerResourceGone(out string) bool {
	return strings.Contains(out, "No such container") || strings.Contains(out, "no such container") ||
		strings.Contains(out, "is not running") || strings.Contains(out, "not found")
}

func touchPrivate(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate random ID: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func digestJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func fileDigests(root string) ([]evidence.ArtifactDigest, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := make([]evidence.ArtifactDigest, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		digest, size, err := digestFile(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, evidence.ArtifactDigest{Path: e.Name(), SHA256: digest, Size: size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func digestFile(path string) (string, uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	size, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil {
		return "", 0, copyErr
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), uint64(size), nil
}

type artifactWriter struct {
	path   string
	file   *os.File
	hasher hash.Hash
	size   uint64
}

func openArtifact(path string) (*artifactWriter, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &artifactWriter{path: path, file: f, hasher: sha256.New()}, nil
}

func (w *artifactWriter) Write(p []byte) (int, error) {
	n, err := w.file.Write(p)
	_, _ = w.hasher.Write(p[:n])
	w.size += uint64(n)
	return n, err
}

func (w *artifactWriter) digest() string {
	return hex.EncodeToString(w.hasher.Sum(nil))
}

func (w *artifactWriter) close() error {
	if err := w.file.Sync(); err != nil {
		_ = w.file.Close()
		return err
	}
	return w.file.Close()
}
