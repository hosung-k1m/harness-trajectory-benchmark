package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/appender"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

func TestValidBundlePath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"simple file", "verification.json", false},
		{"nested file", "workload/raw-records.bin", false},
		{"empty", "", true},
		{"leading traversal", "../escape", true},
		{"nested traversal", "workload/../../../etc/passwd", true},
		{"interior traversal", "workload/../secret", true},
		{"absolute", "/etc/passwd", true},
		{"backslash", `workload\raw`, true},
		{"colon", "a:b", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validBundlePath(tc.path)
			if tc.wantErr && err == nil {
				t.Fatalf("path %q accepted", tc.path)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("path %q rejected: %v", tc.path, err)
			}
		})
	}
}

func rawOnlyFixture(t *testing.T) (Bundle, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "tracked-events.jsonl")
	log, err := appender.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"run/start", "run/finish"} {
		if _, err := log.Append(events.TrackedEvent{Type: typ, Data: json.RawMessage(`{"status":"completed"}`), Ignorable: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	tracked, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	id := "gvisor-raw-only"
	digest := backend.SHA256Hex([]byte(id))
	spec := backend.RunSpec{SchemaVersion: "v1", RunID: id, HarnessDigest: digest, BenchmarkDigest: digest, PolicyDigest: digest, Profile: "development"}
	plan := backend.ObservationPlan{SchemaVersion: "v1", OpaqueTrafficPolicy: backend.OpaqueTrafficAllow}
	capabilities := backend.CapabilityManifest{SchemaVersion: "v1", Backend: "gvisor-container", Version: "phase2.1", TrustDomain: "lima-vm-docker-daemon"}
	capabilities.Digest, err = digestOf(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	health := backend.SensorHealth{SchemaVersion: "v1", Sources: []backend.SensorSourceHealth{
		{SensorID: "gvisor-container-lifecycle", BootID: "boot", ExpectedStart: 1, ExpectedEnd: 1, ObservedStart: 1, ObservedEnd: 1, Started: true, Stopped: true, Drained: true, PlaintextFailures: 1},
		{SensorID: "runsc/debug", BootID: "missing", Drops: 1},
	}}
	specHash, err := digestOf(spec)
	if err != nil {
		t.Fatal(err)
	}
	planHash, err := digestOf(plan)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := evidence.ChainSeed(specHash, planHash, "gvisor-container-lifecycle", "boot")
	if err != nil {
		t.Fatal(err)
	}
	record := evidence.RawRecord{RunID: id, SensorID: "gvisor-container-lifecycle", BootID: "boot", SourceSeq: 1, RecordType: "container/start", Encoding: "binary", Payload: []byte("exact raw bytes")}
	record.RecordSHA256, err = record.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	frame, err := record.Frame()
	if err != nil {
		t.Fatal(err)
	}
	head, err := evidence.ChainedHash(seed, frame)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"tracked-events.jsonl": tracked, "tracked-events.jsonl.sealed": []byte(log.HashHead() + "\n"), "workload/raw-records.bin": frame}
	for path, value := range map[string]any{
		"api-run-spec.json": apiRunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "gvisor-container"},
		"run-spec.json":     spec, "observation-plan.json": plan, "capability-manifest.json": capabilities,
		"sensor-health.json": health, "raw-records.json": []evidence.RawRecord{record},
		"verification.json": storedVerification{Status: "ineligible", TrackedEventChainHead: log.HashHead(), EventCount: 2},
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		files[path] = append(data, '\n')
	}
	healthHash, err := digestOf(health)
	if err != nil {
		t.Fatal(err)
	}
	emptySeed, err := evidence.ChainSeed(specHash, planHash, "runsc/debug", "missing")
	if err != nil {
		t.Fatal(err)
	}
	manifest := evidence.RunEvidenceManifest{SchemaVersion: "v1", RunID: id, RunSpecDigest: specHash, ObservationPlanDigest: planHash, CapabilityManifestDigest: capabilities.Digest, SensorHealthDigest: healthHash, TrackedEventChainHead: log.HashHead(), RawChainHeads: map[string]string{record.SensorID: head, "runsc/debug": emptySeed}, SealedAt: time.Now().UTC()}
	leaves := []string{specHash, planHash, capabilities.Digest, healthHash, log.HashHead(), head, emptySeed}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		hash := backend.SHA256Hex(files[path])
		manifest.Artifacts = append(manifest.Artifacts, evidence.ArtifactDigest{Path: path, SHA256: hash, Size: uint64(len(files[path]))})
		leaves = append(leaves, hash)
	}
	manifest.MerkleRoot, err = evidence.ComputeMerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = evidence.SignManifest(manifest, private)
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{SchemaVersion: Version, RunID: id, Manifest: manifest, Files: files}, public, private
}

func TestRawOnlyBundleIntegrity(t *testing.T) {
	b, public, _ := rawOnlyFixture(t)
	result, err := Validate(b, public)
	if err != nil || !result.IntegrityValid || !result.Report.RawEvidenceIntegrityValid || result.Eligible {
		t.Fatalf("raw-only validation = %#v, %v", result, err)
	}
	b.Files["workload/raw-records.bin"][len(b.Files["workload/raw-records.bin"])-1] ^= 1
	if _, err := Validate(b, public); err == nil {
		t.Fatal("modified raw frame passed validation")
	}
}

func resignRawFixture(t *testing.T, b Bundle, private ed25519.PrivateKey) Bundle {
	t.Helper()
	var err error
	var health backend.SensorHealth
	if err := json.Unmarshal(b.Files["sensor-health.json"], &health); err != nil {
		t.Fatal(err)
	}
	b.Manifest.SensorHealthDigest, err = digestOf(health)
	if err != nil {
		t.Fatal(err)
	}
	leaves := []string{b.Manifest.RunSpecDigest, b.Manifest.ObservationPlanDigest, b.Manifest.CapabilityManifestDigest, b.Manifest.SensorHealthDigest, b.Manifest.TrackedEventChainHead}
	for _, head := range b.Manifest.RawChainHeads {
		leaves = append(leaves, head)
	}
	b.Manifest.Artifacts = nil
	paths := make([]string, 0, len(b.Files))
	for path := range b.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		hash := backend.SHA256Hex(b.Files[path])
		b.Manifest.Artifacts = append(b.Manifest.Artifacts, evidence.ArtifactDigest{Path: path, SHA256: hash, Size: uint64(len(b.Files[path]))})
		leaves = append(leaves, hash)
	}
	b.Manifest.MerkleRoot, err = evidence.ComputeMerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	b.Manifest.Signature = ""
	b.Manifest.SignatureFormat = ""
	b.Manifest, err = evidence.SignManifest(b.Manifest, private)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRawOnlyBundleChecksArtifactReferences(t *testing.T) {
	b, public, private := rawOnlyFixture(t)
	data := []byte("original stdout")
	b.Files["workload/stdout.log"] = data
	meta, err := json.Marshal(struct {
		Artifact string `json:"artifact"`
		SHA256   string `json:"sha256"`
		Size     uint64 `json:"size"`
	}{"stdout.log", backend.SHA256Hex(data), uint64(len(data))})
	if err != nil {
		t.Fatal(err)
	}
	record := evidence.RawRecord{RunID: b.RunID, SensorID: "workload/stdout", BootID: "stdout-boot", SourceSeq: 1, RecordType: "workload/stdout", Encoding: "json", Payload: meta}
	record.RecordSHA256, err = record.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	frame, err := record.Frame()
	if err != nil {
		t.Fatal(err)
	}
	var records []evidence.RawRecord
	if err := json.Unmarshal(b.Files["raw-records.json"], &records); err != nil {
		t.Fatal(err)
	}
	records = append(records, record)
	b.Files["raw-records.json"], _ = json.Marshal(records)
	b.Files["workload/raw-records.bin"] = append(b.Files["workload/raw-records.bin"], frame...)
	seed, err := evidence.ChainSeed(b.Manifest.RunSpecDigest, b.Manifest.ObservationPlanDigest, record.SensorID, record.BootID)
	if err != nil {
		t.Fatal(err)
	}
	b.Manifest.RawChainHeads[record.SensorID], err = evidence.ChainedHash(seed, frame)
	if err != nil {
		t.Fatal(err)
	}
	var health backend.SensorHealth
	if err := json.Unmarshal(b.Files["sensor-health.json"], &health); err != nil {
		t.Fatal(err)
	}
	health.Sources = append(health.Sources, backend.SensorSourceHealth{SensorID: record.SensorID, BootID: record.BootID, ExpectedStart: 1, ExpectedEnd: 1, ObservedStart: 1, ObservedEnd: 1, Started: true, Stopped: true, Drained: true})
	b.Files["sensor-health.json"], _ = json.Marshal(health)
	b = resignRawFixture(t, b, private)
	if _, err := Validate(b, public); err != nil {
		t.Fatalf("valid artifact reference rejected: %v", err)
	}
	b.Files["workload/stdout.log"] = []byte("forged stdout")
	b = resignRawFixture(t, b, private)
	if _, err := Validate(b, public); err == nil {
		t.Fatal("signed artifact disagrees with raw reference but passed validation")
	}
}

func TestRawOnlyBundleChecksCaptureArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name, source, recordType, artifact, iface, direction string
	}{
		{"network packet", "network/packets/veth", "network/packet", "veth-ingress.pcap", "veth0", "ingress"},
		{"gateway flows", "gateway/flows", "gateway/flow", "gateway-flows.mitm", "", ""},
		{"gateway view", "gateway/view", "gateway/view", "gateway-plaintext.txt", "", ""},
		{"dns logs", "dns/logs", "dns/log", "dns.log", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, public, private := rawOnlyFixture(t)
			data := []byte("captured " + tc.name)
			b.Files["workload/"+tc.artifact] = data
			meta, err := json.Marshal(struct {
				Artifact  string `json:"artifact"`
				SHA256    string `json:"sha256"`
				Size      uint64 `json:"size"`
				Interface string `json:"interface,omitempty"`
				Direction string `json:"direction,omitempty"`
			}{tc.artifact, backend.SHA256Hex(data), uint64(len(data)), tc.iface, tc.direction})
			if err != nil {
				t.Fatal(err)
			}
			record := evidence.RawRecord{RunID: b.RunID, SensorID: tc.source, BootID: "capture-boot", SourceSeq: 1, RecordType: tc.recordType, Encoding: "json", Payload: meta}
			record.RecordSHA256, err = record.ComputedHash()
			if err != nil {
				t.Fatal(err)
			}
			frame, err := record.Frame()
			if err != nil {
				t.Fatal(err)
			}
			var records []evidence.RawRecord
			if err := json.Unmarshal(b.Files["raw-records.json"], &records); err != nil {
				t.Fatal(err)
			}
			records = append(records, record)
			b.Files["raw-records.json"], _ = json.Marshal(records)
			b.Files["workload/raw-records.bin"] = append(b.Files["workload/raw-records.bin"], frame...)
			seed, err := evidence.ChainSeed(b.Manifest.RunSpecDigest, b.Manifest.ObservationPlanDigest, record.SensorID, record.BootID)
			if err != nil {
				t.Fatal(err)
			}
			b.Manifest.RawChainHeads[record.SensorID], err = evidence.ChainedHash(seed, frame)
			if err != nil {
				t.Fatal(err)
			}
			var health backend.SensorHealth
			if err := json.Unmarshal(b.Files["sensor-health.json"], &health); err != nil {
				t.Fatal(err)
			}
			health.Sources = append(health.Sources, backend.SensorSourceHealth{SensorID: record.SensorID, BootID: record.BootID, ExpectedStart: 1, ExpectedEnd: 1, ObservedStart: 1, ObservedEnd: 1, Started: true, Stopped: true, Drained: true})
			b.Files["sensor-health.json"], _ = json.Marshal(health)
			b = resignRawFixture(t, b, private)
			if _, err := Validate(b, public); err != nil {
				t.Fatalf("valid capture artifact rejected: %v", err)
			}
			b.Files["workload/"+tc.artifact] = []byte("different bytes")
			b = resignRawFixture(t, b, private)
			if _, err := Validate(b, public); err == nil {
				t.Fatal("signed artifact disagrees with raw reference but passed validation")
			}
		})
	}
}

func TestRawOnlyBundleChecksSecCheckFrames(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(*testing.T, *Bundle)
		wantErr bool
	}{
		{"frame bytes", func(_ *testing.T, b *Bundle) { b.Files["workload/seccheck.frames"][5] ^= 1 }, true},
		{"drain count", func(_ *testing.T, b *Bundle) {
			b.Files["workload/seccheck.done"] = []byte(`{"frames":3,"oversize":0,"reportedDrops":0}`)
		}, true},
		{"partial source", func(t *testing.T, b *Bundle) {
			b.Files["workload/seccheck.partial"] = b.Files["workload/seccheck.frames"]
			b.Files["workload/seccheck.partial-status"] = b.Files["workload/seccheck.done"]
			delete(b.Files, "workload/seccheck.frames")
			delete(b.Files, "workload/seccheck.done")
			var records []evidence.RawRecord
			if err := json.Unmarshal(b.Files["raw-records.json"], &records); err != nil {
				t.Fatal(err)
			}
			lastFrame, err := records[len(records)-1].Frame()
			if err != nil {
				t.Fatal(err)
			}
			records = records[:len(records)-1]
			b.Files["raw-records.json"], _ = json.Marshal(records)
			b.Files["workload/raw-records.bin"] = b.Files["workload/raw-records.bin"][:len(b.Files["workload/raw-records.bin"])-len(lastFrame)]
			seed, err := evidence.ChainSeed(b.Manifest.RunSpecDigest, b.Manifest.ObservationPlanDigest, "seccheck/remote", "sec-boot")
			if err != nil {
				t.Fatal(err)
			}
			firstFrame, err := records[len(records)-1].Frame()
			if err != nil {
				t.Fatal(err)
			}
			b.Manifest.RawChainHeads["seccheck/remote"], err = evidence.ChainedHash(seed, firstFrame)
			if err != nil {
				t.Fatal(err)
			}
			var health backend.SensorHealth
			if err := json.Unmarshal(b.Files["sensor-health.json"], &health); err != nil {
				t.Fatal(err)
			}
			last := len(health.Sources) - 1
			health.Sources[last].ObservedEnd = 1
			health.Sources[last].Drained = false
			health.Sources[last].Stopped = false
			health.Sources[last].ParseFailures = 1
			b.Files["sensor-health.json"], _ = json.Marshal(health)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, public, private := rawOnlyFixture(t)
			var records []evidence.RawRecord
			if err := json.Unmarshal(b.Files["raw-records.json"], &records); err != nil {
				t.Fatal(err)
			}
			seed, err := evidence.ChainSeed(b.Manifest.RunSpecDigest, b.Manifest.ObservationPlanDigest, "seccheck/remote", "sec-boot")
			if err != nil {
				t.Fatal(err)
			}
			head := seed
			var frames []byte
			for i, payload := range [][]byte{{8, 0, 1, 0, 0, 0, 0, 0, 10, 1}, {8, 0, 4, 0, 0, 0, 0, 0, 10, 2}} {
				record := evidence.RawRecord{RunID: b.RunID, SensorID: "seccheck/remote", BootID: "sec-boot", SourceSeq: uint64(i + 1), RecordType: "seccheck/frame", Encoding: "protobuf", Payload: payload}
				if i > 0 {
					record.PreviousRecordSHA256 = records[len(records)-1].RecordSHA256
				}
				record.RecordSHA256, err = record.ComputedHash()
				if err != nil {
					t.Fatal(err)
				}
				frame, err := record.Frame()
				if err != nil {
					t.Fatal(err)
				}
				head, err = evidence.ChainedHash(head, frame)
				if err != nil {
					t.Fatal(err)
				}
				records = append(records, record)
				b.Files["workload/raw-records.bin"] = append(b.Files["workload/raw-records.bin"], frame...)
				var prefix [4]byte
				binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
				frames = append(frames, prefix[:]...)
				frames = append(frames, payload...)
			}
			b.Files["raw-records.json"], _ = json.Marshal(records)
			b.Files["workload/seccheck.frames"] = frames
			b.Files["workload/seccheck.done"] = []byte("{\"frames\":2,\"oversize\":0,\"reportedDrops\":0}\n")
			b.Manifest.RawChainHeads["seccheck/remote"] = head
			var health backend.SensorHealth
			if err := json.Unmarshal(b.Files["sensor-health.json"], &health); err != nil {
				t.Fatal(err)
			}
			health.Sources = append(health.Sources, backend.SensorSourceHealth{SensorID: "seccheck/remote", BootID: "sec-boot", ExpectedStart: 1, ExpectedEnd: 2, ObservedStart: 1, ObservedEnd: 2, Started: true, Drained: true, Stopped: true})
			b.Files["sensor-health.json"], _ = json.Marshal(health)
			b = resignRawFixture(t, b, private)
			if _, err := Validate(b, public); err != nil {
				t.Fatalf("valid SecCheck frames rejected: %v", err)
			}
			tc.change(t, &b)
			b = resignRawFixture(t, b, private)
			_, err = Validate(b, public)
			if tc.wantErr && err == nil {
				t.Fatal("signed inconsistent SecCheck frames passed validation")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("degraded SecCheck source rejected: %v", err)
			}
		})
	}
}

func TestRawOnlyBundleRejectsSignedInconsistency(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *Bundle)
	}{
		{"chain head", func(t *testing.T, b *Bundle) {
			b.Manifest.RawChainHeads["gvisor-container-lifecycle"] = backend.SHA256Hex([]byte("different"))
		}},
		{"health sequence", func(t *testing.T, b *Bundle) {
			var health backend.SensorHealth
			if err := json.Unmarshal(b.Files["sensor-health.json"], &health); err != nil {
				t.Fatal(err)
			}
			health.Sources[0].ObservedEnd = 2
			b.Files["sensor-health.json"], _ = json.Marshal(health)
		}},
		{"record content", func(t *testing.T, b *Bundle) {
			var records []evidence.RawRecord
			if err := json.Unmarshal(b.Files["raw-records.json"], &records); err != nil {
				t.Fatal(err)
			}
			records[0].Payload = []byte("different")
			var err error
			records[0].RecordSHA256, err = records[0].ComputedHash()
			if err != nil {
				t.Fatal(err)
			}
			b.Files["workload/raw-records.bin"], err = records[0].Frame()
			if err != nil {
				t.Fatal(err)
			}
			b.Files["raw-records.json"], _ = json.Marshal(records)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, public, private := rawOnlyFixture(t)
			tc.change(t, &b)
			b = resignRawFixture(t, b, private)
			if _, err := Validate(b, public); err == nil {
				t.Fatal("signed inconsistent raw-only bundle passed validation")
			}
		})
	}
}
