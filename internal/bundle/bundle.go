package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/appender"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/normalizer"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/plaintext"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/verification"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

const Version = "htb.evidence-bundle.v1"

type Bundle struct {
	SchemaVersion string                       `json:"schemaVersion"`
	RunID         string                       `json:"runId"`
	Manifest      evidence.RunEvidenceManifest `json:"manifest"`
	Files         map[string][]byte            `json:"files"`
}

type Result struct {
	RunID                 string              `json:"runId"`
	TrackedEventChainHead string              `json:"trackedEventChainHead"`
	IntegrityValid        bool                `json:"integrityValid"`
	Eligible              bool                `json:"eligible"`
	Report                verification.Report `json:"report"`
}

var requiredFiles = []string{
	"api-run-spec.json",
	"run-spec.json",
	"observation-plan.json",
	"capability-manifest.json",
	"sensor-health.json",
	"tracked-events.jsonl",
	"tracked-events.jsonl.sealed",
	"raw-records.json",
	"verification.json",
	"workload/raw-records.bin",
}

type apiRunSpec struct {
	SchemaVersion string                     `json:"schemaVersion"`
	Harness       string                     `json:"harness"`
	Suite         string                     `json:"suite"`
	Backend       string                     `json:"backend"`
	Parameters    map[string]json.RawMessage `json:"parameters,omitempty"`
	Verified      bool                       `json:"verified,omitempty"`
}

type storedVerification struct {
	Status                string    `json:"status"`
	Eligible              bool      `json:"eligible"`
	Summary               string    `json:"summary,omitempty"`
	CheckedAt             time.Time `json:"checkedAt,omitempty"`
	TrackedEventChainHead string    `json:"trackedEventChainHead,omitempty"`
	EventCount            uint64    `json:"eventCount,omitempty"`
}

func Decode(r io.Reader) (Bundle, error) {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	var b Bundle
	if err := decoder.Decode(&b); err != nil {
		return Bundle{}, fmt.Errorf("decode evidence bundle: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Bundle{}, errors.New("evidence bundle contains trailing JSON")
		}
		return Bundle{}, fmt.Errorf("decode evidence bundle: %w", err)
	}
	return b, nil
}

func Validate(b Bundle, publicKey ed25519.PublicKey) (Result, error) {
	fail := func(format string, args ...any) (Result, error) {
		return Result{}, fmt.Errorf(format, args...)
	}
	if b.SchemaVersion != Version {
		return fail("unsupported bundle schemaVersion %q", b.SchemaVersion)
	}
	if b.RunID == "" || b.Manifest.RunID != b.RunID {
		return fail("bundle and manifest run IDs do not match")
	}
	required := map[string]bool{}
	for _, name := range requiredFiles {
		required[name] = true
	}
	for name := range b.Files {
		if err := validBundlePath(name); err != nil {
			return fail("invalid bundle file path %q: %v", name, err)
		}
		if !required[name] && !strings.HasPrefix(name, "workload/") {
			return fail("bundle file %q is not a recognized evidence file", name)
		}
	}
	if err := evidence.VerifyManifestSignature(b.Manifest, publicKey); err != nil {
		return fail("manifest signature: %v", err)
	}
	if len(b.Files) != len(b.Manifest.Artifacts) {
		return fail("bundle file set does not match manifest artifacts")
	}
	seenArtifacts := map[string]bool{}
	for _, artifact := range b.Manifest.Artifacts {
		if seenArtifacts[artifact.Path] {
			return fail("duplicate manifest artifact path %q", artifact.Path)
		}
		seenArtifacts[artifact.Path] = true
		if err := validBundlePath(artifact.Path); err != nil {
			return fail("invalid artifact path %q: %v", artifact.Path, err)
		}
		content, ok := b.Files[artifact.Path]
		if !ok {
			return fail("manifest artifact %q has no bundle file", artifact.Path)
		}
		if uint64(len(content)) != artifact.Size || sha256Hex(content) != artifact.SHA256 {
			return fail("artifact %q content does not match manifest digest", artifact.Path)
		}
	}
	leaves := []string{b.Manifest.RunSpecDigest, b.Manifest.ObservationPlanDigest, b.Manifest.CapabilityManifestDigest, b.Manifest.SensorHealthDigest, b.Manifest.TrackedEventChainHead}
	for _, head := range b.Manifest.RawChainHeads {
		leaves = append(leaves, head)
	}
	for _, artifact := range b.Manifest.Artifacts {
		leaves = append(leaves, artifact.SHA256)
	}
	root, err := evidence.ComputeMerkleRoot(leaves)
	if err != nil {
		return fail("manifest Merkle root: %v", err)
	}
	if root != b.Manifest.MerkleRoot {
		return fail("manifest Merkle root does not match its evidence")
	}
	for _, name := range requiredFiles {
		if _, ok := b.Files[name]; !ok {
			return fail("bundle is missing required file %q", name)
		}
	}

	var apiSpec apiRunSpec
	var spec backend.RunSpec
	var plan backend.ObservationPlan
	var capabilities backend.CapabilityManifest
	var health backend.SensorHealth
	var records []evidence.RawRecord
	var stored storedVerification
	for name, out := range map[string]any{
		"api-run-spec.json":        &apiSpec,
		"run-spec.json":            &spec,
		"observation-plan.json":    &plan,
		"capability-manifest.json": &capabilities,
		"sensor-health.json":       &health,
		"raw-records.json":         &records,
		"verification.json":        &stored,
	} {
		if err := decodeStrict(b.Files[name], out); err != nil {
			return fail("decode %s: %v", name, err)
		}
	}
	if apiSpec.SchemaVersion != "v1" || apiSpec.Harness == "" || apiSpec.Suite == "" || apiSpec.Backend == "" {
		return fail("api run spec is invalid")
	}
	if err := spec.Validate(); err != nil {
		return fail("run spec: %v", err)
	}
	if spec.RunID != b.RunID {
		return fail("run spec runId does not match bundle")
	}
	if err := plan.Validate(); err != nil {
		return fail("observation plan: %v", err)
	}
	if err := capabilities.Validate(); err != nil {
		return fail("capability manifest: %v", err)
	}
	if err := health.Validate(); err != nil {
		return fail("sensor health: %v", err)
	}
	specDigest, err := digestOf(spec)
	if err != nil {
		return fail("run spec digest: %v", err)
	}
	planDigest, err := digestOf(plan)
	if err != nil {
		return fail("observation plan digest: %v", err)
	}
	healthDigest, err := digestOf(health)
	if err != nil {
		return fail("sensor health digest: %v", err)
	}
	capabilityDigest := capabilities.Digest
	withoutDigest := capabilities
	withoutDigest.Digest = ""
	computedCapabilityDigest, err := digestOf(withoutDigest)
	if err != nil {
		return fail("capability manifest digest: %v", err)
	}
	if capabilityDigest != computedCapabilityDigest {
		return fail("capability manifest digest does not match its content")
	}
	if b.Manifest.RunSpecDigest != specDigest ||
		b.Manifest.ObservationPlanDigest != planDigest ||
		b.Manifest.CapabilityManifestDigest != capabilityDigest ||
		b.Manifest.SensorHealthDigest != healthDigest {
		return fail("manifest digests do not match bundle documents")
	}

	tracked, head, err := appender.ValidateFrames(b.Files["tracked-events.jsonl"])
	if err != nil {
		return fail("tracked event log: %v", err)
	}
	if head != b.Manifest.TrackedEventChainHead {
		return fail("tracked event chain head does not match manifest")
	}
	if string(b.Files["tracked-events.jsonl.sealed"]) != head+"\n" {
		return fail("seal marker does not match the computed chain head")
	}
	finish := 0
	startSeen := false
	for i, event := range tracked {
		switch event.Type {
		case "run/start":
			if startSeen {
				return fail("duplicate run/start event")
			}
			if finish != 0 {
				return fail("run/start appears after run/finish")
			}
			startSeen = true
		case "run/finish":
			finish++
			if i != len(tracked)-1 {
				return fail("run/finish is not the final trajectory event")
			}
		}
	}
	if finish != 1 {
		return fail("trajectory must end with exactly one run/finish event")
	}

	frames := make([]byte, 0)
	bySourceSeq := map[evidence.RawSource]map[uint64]evidence.RawRecord{}
	bootsPerSensor := map[string]map[string]bool{}
	for _, record := range records {
		if record.RunID != b.RunID {
			return fail("raw record runId does not match bundle")
		}
		frame, err := record.Frame()
		if err != nil {
			return fail("raw record frame: %v", err)
		}
		frames = append(frames, frame...)
		source := evidence.RawSource{SensorID: record.SensorID, BootID: record.BootID}
		if bySourceSeq[source] == nil {
			bySourceSeq[source] = map[uint64]evidence.RawRecord{}
		}
		if _, dup := bySourceSeq[source][record.SourceSeq]; dup {
			return fail("duplicate raw record source sequence")
		}
		bySourceSeq[source][record.SourceSeq] = record
		if bootsPerSensor[record.SensorID] == nil {
			bootsPerSensor[record.SensorID] = map[string]bool{}
		}
		bootsPerSensor[record.SensorID][record.BootID] = true
	}
	if !bytes.Equal(frames, b.Files["workload/raw-records.bin"]) {
		return fail("workload/raw-records.bin does not equal the exact record frames")
	}

	expectedHeads := map[evidence.RawSource]string{}
	for source := range bySourceSeq {
		if len(bootsPerSensor[source.SensorID]) != 1 {
			return fail("ambiguous raw chain head for sensor %q", source.SensorID)
		}
		head, ok := b.Manifest.RawChainHeads[source.SensorID]
		if !ok || head == "" {
			return fail("manifest lacks a raw chain head for sensor %q", source.SensorID)
		}
		expectedHeads[source] = head
	}
	if len(expectedHeads) != len(b.Manifest.RawChainHeads) && capabilities.Backend != "gvisor-container" {
		return fail("manifest raw chain head count does not match the raw sources")
	}
	if capabilities.Backend == "gvisor-container" {
		if capabilities.TrustDomain != "lima-vm-docker-daemon" || apiSpec.Backend != capabilities.Backend || spec.Verified || !startSeen || len(records) == 0 {
			return fail("invalid gvisor raw-only declaration")
		}
		if err := backend.ValidatePlanAgainstManifest(plan, capabilities, false); err != nil {
			return fail("gvisor observation plan: %v", err)
		}
		if stored.Status != "ineligible" || stored.Eligible || stored.TrackedEventChainHead != head || stored.EventCount != uint64(len(tracked)) {
			return fail("gvisor raw-only verification result does not match the trajectory")
		}
		for _, event := range tracked {
			if !strings.HasPrefix(event.Type, "run/") {
				return fail("gvisor raw-only bundle contains a normalized event")
			}
		}
		chains := make(map[evidence.RawSource][]evidence.RawRecord)
		for _, record := range records {
			source := evidence.RawSource{SensorID: record.SensorID, BootID: record.BootID}
			chains[source] = append(chains[source], record)
		}
		for source, chain := range chains {
			seed, err := evidence.ChainSeed(specDigest, planDigest, source.SensorID, source.BootID)
			if err != nil {
				return fail("gvisor raw chain seed: %v", err)
			}
			computed, err := evidence.ValidateChain(chain, seed)
			if err != nil || computed != expectedHeads[source] {
				return fail("gvisor raw chain %s/%s: %v", source.SensorID, source.BootID, err)
			}
		}
		healthBySource := make(map[evidence.RawSource]backend.SensorSourceHealth, len(health.Sources))
		if len(health.Sources) != len(b.Manifest.RawChainHeads) {
			return fail("gvisor health and raw chain heads disagree on source count")
		}
		seenSensors := make(map[string]bool, len(health.Sources))
		for _, status := range health.Sources {
			if seenSensors[status.SensorID] {
				return fail("gvisor health has ambiguous boots for sensor %s", status.SensorID)
			}
			seenSensors[status.SensorID] = true
			source := evidence.RawSource{SensorID: status.SensorID, BootID: status.BootID}
			healthBySource[source] = status
			claimed, ok := b.Manifest.RawChainHeads[status.SensorID]
			if !ok {
				return fail("gvisor raw source %s lacks a chain head", status.SensorID)
			}
			if len(chains[source]) == 0 {
				seed, err := evidence.ChainSeed(specDigest, planDigest, status.SensorID, status.BootID)
				if err != nil || claimed != seed || status.ObservedStart != 0 || status.ObservedEnd != 0 {
					return fail("gvisor empty source %s/%s has an invalid head or health", status.SensorID, status.BootID)
				}
			}
		}
		for source, chain := range chains {
			status, ok := healthBySource[source]
			if !ok || status.ObservedStart != 1 || status.ObservedEnd != uint64(len(chain)) {
				return fail("gvisor raw source %s/%s does not match capture health", source.SensorID, source.BootID)
			}
		}
		for _, record := range records {
			switch record.RecordType {
			case "workload/stdout", "workload/stderr", "workspace/snapshot", "runsc/log", "network/packet", "network/config", "gateway/flow", "gateway/view", "dns/log":
				if record.Encoding != "json" {
					return fail("gvisor source %s has invalid artifact encoding", record.SensorID)
				}
				var meta struct {
					Artifact  string `json:"artifact"`
					SHA256    string `json:"sha256"`
					Size      uint64 `json:"size"`
					Interface string `json:"interface,omitempty"`
					Direction string `json:"direction,omitempty"`
					Phase     string `json:"phase,omitempty"`
				}
				if err := decodeStrict(record.Payload, &meta); err != nil {
					return fail("gvisor artifact reference: %v", err)
				}
				if record.RecordType == "network/packet" && (meta.Interface == "" || meta.Phase != "" || (meta.Direction != "ingress" && meta.Direction != "egress") || (record.SensorID != "network/packets/bridge" && record.SensorID != "network/packets/veth")) {
					return fail("gvisor packet source lacks interface or direction")
				}
				if record.RecordType == "network/config" && (meta.Interface == "" || meta.Direction != "" || (meta.Phase != "start" && meta.Phase != "stop") || record.SensorID != "network/config") {
					return fail("gvisor network config source has invalid interface or phase")
				}
				if record.RecordType == "gateway/flow" && record.SensorID != "gateway/flows" || record.RecordType == "gateway/view" && record.SensorID != "gateway/view" || record.RecordType == "dns/log" && record.SensorID != "dns/logs" {
					return fail("gvisor gateway source identity is invalid")
				}
				if (record.RecordType == "gateway/flow" || record.RecordType == "gateway/view" || record.RecordType == "dns/log") && (meta.Interface != "" || meta.Direction != "" || meta.Phase != "") {
					return fail("gvisor gateway source uses unsupported network metadata")
				}
				path := "workload/" + meta.Artifact
				if meta.Artifact == "" || filepath.Base(meta.Artifact) != meta.Artifact || validBundlePath(path) != nil {
					return fail("gvisor artifact reference has invalid path %q", meta.Artifact)
				}
				content, ok := b.Files[path]
				if !ok || uint64(len(content)) != meta.Size || sha256Hex(content) != meta.SHA256 {
					return fail("gvisor artifact %q does not match its raw reference", path)
				}
			}
		}
		secFrames, hasFrames := b.Files["workload/seccheck.frames"]
		secDone, hasDone := b.Files["workload/seccheck.done"]
		partialFrames, hasPartial := b.Files["workload/seccheck.partial"]
		_, hasPartialStatus := b.Files["workload/seccheck.partial-status"]
		if (hasFrames && hasPartial) || (hasDone && hasPartialStatus) || (hasDone && !hasFrames) {
			return fail("gvisor SecCheck artifacts contain conflicting capture states")
		}
		if !hasFrames && hasPartial {
			secFrames = partialFrames
		}
		var secHealth backend.SensorSourceHealth
		secKnown := false
		for source, status := range healthBySource {
			if source.SensorID == "seccheck/remote" {
				secHealth, secKnown = status, true
			}
		}
		offset := 0
		var frameCount uint64
		for _, record := range records {
			if record.SensorID != "seccheck/remote" && record.RecordType != "seccheck/frame" {
				continue
			}
			if record.SensorID != "seccheck/remote" || record.RecordType != "seccheck/frame" || record.Encoding != "protobuf" || (!hasFrames && !hasPartial) || len(record.Payload) == 0 || len(record.Payload) > 300*1024 || len(secFrames)-offset < 4 {
				return fail("gvisor SecCheck frame source is invalid")
			}
			length := binary.BigEndian.Uint32(secFrames[offset : offset+4])
			offset += 4
			if length != uint32(len(record.Payload)) || len(secFrames)-offset < len(record.Payload) || !bytes.Equal(secFrames[offset:offset+len(record.Payload)], record.Payload) {
				return fail("gvisor SecCheck raw artifact disagrees with source record")
			}
			offset += len(record.Payload)
			frameCount++
		}
		if (frameCount == 0 && (hasFrames || hasDone)) || (hasFrames && offset != len(secFrames)) {
			return fail("gvisor SecCheck raw artifact has unreferenced bytes")
		}
		if frameCount > 0 && hasDone {
			var status struct {
				Frames        uint64 `json:"frames"`
				Oversize      uint64 `json:"oversize"`
				ReportedDrops uint64 `json:"reportedDrops"`
			}
			if err := decodeStrict(secDone, &status); err != nil || status.Frames != frameCount || status.Oversize > ^uint64(0)-status.ReportedDrops || secHealth.Drops < status.Oversize+status.ReportedDrops || !secHealth.Drained || !secHealth.Stopped {
				return fail("gvisor SecCheck drain status disagrees with captured frames or health")
			}
		} else if (frameCount > 0 || hasPartial || hasPartialStatus) && (!secKnown || secHealth.Drained || secHealth.Stopped || secHealth.Drops == 0 && secHealth.ParseFailures == 0) {
			return fail("gvisor SecCheck partial source was not recorded as loss")
		}
		report := verification.Report{IntegrityValid: true, LogIntegrityValid: true, RawEvidenceValidated: true, RawEvidenceIntegrityValid: true, EventCount: uint64(len(tracked)), Ineligibility: []string{"gvisor Phase 2 retains raw evidence only"}}
		return Result{RunID: b.RunID, TrackedEventChainHead: head, IntegrityValid: true, Eligible: false, Report: report}, nil
	}

	type observationEvidence struct {
		RunID    string          `json:"runId"`
		Source   events.Source   `json:"source"`
		Evidence events.Evidence `json:"evidence"`
	}
	var coverage []evidence.NormalizedCoverage
	for _, event := range tracked {
		var data observationEvidence
		if err := json.Unmarshal(event.Data, &data); err != nil {
			return fail("event %d observation data: %v", event.Seq, err)
		}
		if data.Evidence.RawRecordSHA256 == "" && data.Evidence.RawStreamID == "" {
			continue
		}
		if data.Evidence.RawRecordSHA256 == "" || data.Evidence.RawStreamID == "" {
			return fail("event %d has an incomplete raw evidence reference", event.Seq)
		}
		compatNormalizer := data.Evidence.NormalizerVersion == normalizer.CompatVersion && data.Evidence.NormalizerSHA256 == normalizer.CompatDigest
		mockNormalizer := data.Evidence.NormalizerVersion == normalizer.MockVersion && data.Evidence.NormalizerSHA256 == normalizer.MockDigest && capabilities.Backend == "mock-data" && capabilities.TrustDomain == "mock" && data.Source.Backend == "mock-data" && data.Source.TrustDomain == "mock"
		if !compatNormalizer && !mockNormalizer {
			return fail("event %d references an unknown normalizer", event.Seq)
		}
		if data.RunID != "" && data.RunID != b.RunID {
			return fail("event %d observation runId does not match bundle", event.Seq)
		}
		source := evidence.RawSource{SensorID: data.Source.SensorID, BootID: data.Source.BootID}
		seqs, ok := bySourceSeq[source]
		if !ok {
			return fail("event %d references an unknown raw source", event.Seq)
		}
		if data.Evidence.RawSourceSeqStart == 0 || data.Evidence.RawSourceSeqEnd < data.Evidence.RawSourceSeqStart {
			return fail("event %d has an invalid raw source range", event.Seq)
		}
		if data.Source.SourceSeq != data.Evidence.RawSourceSeqStart {
			return fail("event %d source sequence does not cover its raw range", event.Seq)
		}
		if data.Evidence.RawStreamID != source.SensorID+"/"+source.BootID {
			return fail("event %d raw stream ID does not match its source", event.Seq)
		}
		for seq := data.Evidence.RawSourceSeqStart; seq <= data.Evidence.RawSourceSeqEnd; seq++ {
			record, ok := seqs[seq]
			if !ok {
				return fail("event %d references missing raw record %d", event.Seq, seq)
			}
			if seq == data.Evidence.RawSourceSeqStart && record.RecordSHA256 != data.Evidence.RawRecordSHA256 {
				return fail("event %d raw record hash does not match the referenced record", event.Seq)
			}
		}
		coverage = append(coverage, evidence.NormalizedCoverage{
			Raw:     evidence.RawRange{SensorID: source.SensorID, BootID: source.BootID, Start: data.Evidence.RawSourceSeqStart, End: data.Evidence.RawSourceSeqEnd},
			EventID: strconv.FormatUint(event.Seq, 10),
		})
	}
	var flows []plaintext.FlowAccounting
	for _, record := range records {
		if record.RecordType == "network/flow" {
			var flow plaintext.FlowAccounting
			if err := decodeStrict(record.Payload, &flow); err != nil {
				return fail("raw boundary flow: %v", err)
			}
			flows = append(flows, flow)
		}
	}
	report, err := verification.Verify(verification.Input{
		Events:                   tracked,
		Flows:                    flows,
		RawRecords:               records,
		RawCoverage:              coverage,
		RawRunSpecDigest:         specDigest,
		RawObservationPlanDigest: planDigest,
		ExpectedRawChainHeads:    expectedHeads,
		Eligibility:              &verification.EligibilityInput{RunSpec: spec, ObservationPlan: plan, CapabilityManifest: capabilities, SensorHealth: health},
	})
	if err != nil {
		return fail("verification: %v", err)
	}
	if !report.IntegrityValid || !report.RawEvidenceIntegrityValid {
		return fail("bundle integrity validation did not complete")
	}
	if stored.Status != "ineligible" || stored.Eligible {
		return fail("stored verification result is not the expected ineligible outcome")
	}
	if stored.TrackedEventChainHead != head || stored.EventCount != uint64(len(tracked)) {
		return fail("stored verification result does not match the trajectory")
	}
	return Result{RunID: b.RunID, TrackedEventChainHead: head, IntegrityValid: true, Eligible: false, Report: report}, nil
}

func Extract(b Bundle, destination string, publicKey ed25519.PublicKey) error {
	if _, err := Validate(b, publicKey); err != nil {
		return err
	}
	info, err := os.Lstat(destination)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("extract destination %q is not a real directory", destination)
		}
		entries, err := os.ReadDir(destination)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("extract destination %q is not empty", destination)
		}
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(destination, 0o700); err != nil {
			return err
		}
	default:
		return err
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer root.Close()
	names := make([]string, 0, len(b.Files))
	for name := range b.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if dir := filepath.Dir(name); dir != "." {
			parts := strings.Split(filepath.ToSlash(dir), "/")
			for i := range parts {
				parent := strings.Join(parts[:i+1], "/")
				if err := root.Mkdir(parent, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
					return fmt.Errorf("create %s: %w", parent, err)
				}
			}
		}
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		if _, err := file.Write(b.Files[name]); err != nil {
			_ = file.Close()
			return fmt.Errorf("write %s: %w", name, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close %s: %w", name, err)
		}
	}
	return nil
}

func validBundlePath(name string) error {
	if name == "" || !fs.ValidPath(name) {
		return errors.New("not a portable relative path")
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return errors.New("path contains a parent traversal segment")
		}
	}
	if strings.ContainsAny(name, "\\:") || filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return errors.New("path contains forbidden separators or anchors")
	}
	return nil
}

func decodeStrict(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON")
		}
		return err
	}
	return nil
}

func digestOf(v any) (string, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return sha256Hex(encoded), nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
