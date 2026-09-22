package bundle_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/appender"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/backend/compat"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/bundle"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/controlplane"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/client"
)

func produceBundle(t *testing.T) (bundle.Bundle, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
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
	store := api.NewStoreWithDependencies(factory, driver)
	if err := driver.BindStore(store); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.NewHandler(store))
	c := client.New(server.URL)
	config := json.RawMessage(`{"type":"compat/local-process-v1","command":["/bin/sh","-c","printf bundle"]}`)
	run, err := c.CreateRun(context.Background(), client.CreateRunRequest{Spec: client.RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "compat-local-process", Parameters: map[string]json.RawMessage{"backendConfig": config}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lifecycle(context.Background(), run.ID, client.LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		report, err := c.Evidence(context.Background(), run.ID)
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
	raw, err := os.ReadFile(filepath.Join(dataDir, "runs", run.ID, "evidence-bundle.json"))
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
	decoded, err := bundle.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return decoded, publicKey, privateKey
}

// repack recomputes every derived digest and the signature over the current
// Files map, so a mutation fails only on content checks rather than encoding.
func repack(t *testing.T, b bundle.Bundle, privateKey ed25519.PrivateKey) bundle.Bundle {
	t.Helper()
	if data, ok := b.Files["tracked-events.jsonl"]; ok {
		_, head, err := appender.ValidateFrames(data)
		if err == nil {
			b.Manifest.TrackedEventChainHead = head
			b.Files["tracked-events.jsonl.sealed"] = []byte(head + "\n")
		}
	}
	paths := make([]string, 0, len(b.Files))
	for path := range b.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	artifacts := make([]evidence.ArtifactDigest, 0, len(paths))
	leaves := []string{b.Manifest.RunSpecDigest, b.Manifest.ObservationPlanDigest, b.Manifest.CapabilityManifestDigest, b.Manifest.SensorHealthDigest, b.Manifest.TrackedEventChainHead}
	for _, head := range b.Manifest.RawChainHeads {
		leaves = append(leaves, head)
	}
	for _, path := range paths {
		hash := backend.SHA256Hex(b.Files[path])
		artifacts = append(artifacts, evidence.ArtifactDigest{Path: path, SHA256: hash, Size: uint64(len(b.Files[path]))})
		leaves = append(leaves, hash)
	}
	merkle, err := evidence.ComputeMerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	b.Manifest.Artifacts = artifacts
	b.Manifest.MerkleRoot = merkle
	b.Manifest.Signature = ""
	b.Manifest.SignatureFormat = ""
	signed, err := evidence.SignManifest(b.Manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	b.Manifest = signed
	return b
}

func signOnly(t *testing.T, b bundle.Bundle, privateKey ed25519.PrivateKey) bundle.Bundle {
	t.Helper()
	b.Manifest.Signature = ""
	b.Manifest.SignatureFormat = ""
	signed, err := evidence.SignManifest(b.Manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	b.Manifest = signed
	return b
}

func TestBundleValidatesAndExtracts(t *testing.T) {
	b, publicKey, _ := produceBundle(t)
	result, err := bundle.Validate(b, publicKey)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !result.IntegrityValid || result.Eligible || result.TrackedEventChainHead != b.Manifest.TrackedEventChainHead {
		t.Fatalf("result = %#v", result)
	}
	destination := filepath.Join(t.TempDir(), "out")
	if err := bundle.Extract(b, destination, publicKey); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	for name, content := range b.Files {
		got, err := os.ReadFile(filepath.Join(destination, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("extracted %s mismatch: %v", name, err)
		}
	}
	if err := bundle.Extract(b, destination, publicKey); err == nil {
		t.Fatal("Extract accepted a non-empty destination")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(destination, link); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Extract(b, link, publicKey); err == nil {
		t.Fatal("Extract accepted a symlink destination")
	}
}

func TestBundleExtractsNestedWorkloadArtifacts(t *testing.T) {
	b, publicKey, privateKey := produceBundle(t)
	b.Files["workload/nested/deep/artifact.bin"] = []byte("nested-payload")
	b = repack(t, b, privateKey)
	if _, err := bundle.Validate(b, publicKey); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	destination := filepath.Join(t.TempDir(), "out")
	if err := bundle.Extract(b, destination, publicKey); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destination, "workload", "nested", "deep", "artifact.bin"))
	if err != nil || string(got) != "nested-payload" {
		t.Fatalf("nested artifact = %q err=%v", got, err)
	}
}

func TestBundleRejectsSignedDigestAndCoverageTampering(t *testing.T) {
	valid, publicKey, privateKey := produceBundle(t)
	t.Run("wrong merkle root signed", func(t *testing.T) {
		b := valid
		other := sha256.Sum256([]byte("wrong-root"))
		b.Manifest.MerkleRoot = hex.EncodeToString(other[:])
		b = signOnly(t, b, privateKey)
		if _, err := bundle.Validate(b, publicKey); err == nil || !strings.Contains(err.Error(), "Merkle") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("extra signed raw head", func(t *testing.T) {
		b := valid
		b.Manifest.RawChainHeads = map[string]string{}
		for k, v := range valid.Manifest.RawChainHeads {
			b.Manifest.RawChainHeads[k] = v
		}
		b.Manifest.RawChainHeads["phantom-sensor"] = strings.Repeat("0", 64)
		b = repack(t, b, privateKey)
		if _, err := bundle.Validate(b, publicKey); err == nil {
			t.Fatal("extra raw chain head accepted")
		}
	})
	t.Run("duplicate artifact path", func(t *testing.T) {
		b := valid
		artifacts := append([]evidence.ArtifactDigest(nil), valid.Manifest.Artifacts...)
		artifacts = append(artifacts, valid.Manifest.Artifacts[0])
		artifacts = append(artifacts[:1], artifacts[2:]...)
		b.Manifest.Artifacts = artifacts
		if _, err := bundle.Validate(b, publicKey); err == nil {
			t.Fatal("duplicate artifact path accepted")
		}
	})
	t.Run("source seq mismatching raw start", func(t *testing.T) {
		b := valid
		frames := bytes.Split(bytes.TrimRight(b.Files["tracked-events.jsonl"], "\n"), []byte("\n"))
		target := -1
		var event map[string]any
		for i, frame := range frames {
			if err := json.Unmarshal(frame, &event); err != nil {
				t.Fatal(err)
			}
			if event["type"] == "process/exec" {
				target = i
				break
			}
		}
		if target < 0 {
			t.Fatal("no observation event found")
		}
		data := event["data"].(map[string]any)
		source := data["source"].(map[string]any)
		source["sourceSeq"] = float64(99)
		data["source"] = source
		event["data"] = data
		frame, _ := json.Marshal(event)
		frames[target] = frame
		b.Files["tracked-events.jsonl"] = append(bytes.Join(frames, []byte("\n")), '\n')
		b = repack(t, b, privateKey)
		if _, err := bundle.Validate(b, publicKey); err == nil || !strings.Contains(err.Error(), "source sequence") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestBundleRejectsTraversalFileKeys(t *testing.T) {
	valid, publicKey, _ := produceBundle(t)
	for _, key := range []string{"../escape", "workload/../../../etc/passwd"} {
		t.Run(key, func(t *testing.T) {
			b := valid
			files := make(map[string][]byte, len(valid.Files)+1)
			for k, v := range valid.Files {
				files[k] = v
			}
			files[key] = []byte("x")
			b.Files = files
			if _, err := bundle.Validate(b, publicKey); err == nil || !strings.Contains(err.Error(), "invalid bundle file path") {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestBundleRejectsRawRangeTampering(t *testing.T) {
	valid, publicKey, privateKey := produceBundle(t)
	clone := func() bundle.Bundle {
		b := valid
		files := make(map[string][]byte, len(valid.Files))
		for k, v := range valid.Files {
			files[k] = append([]byte(nil), v...)
		}
		b.Files = files
		return b
	}
	t.Run("coverage range extends past last raw record", func(t *testing.T) {
		b := clone()
		frames := bytes.Split(bytes.TrimRight(b.Files["tracked-events.jsonl"], "\n"), []byte("\n"))
		var maxSeq float64
		target := -1
		for i, frame := range frames {
			var event map[string]any
			if err := json.Unmarshal(frame, &event); err != nil {
				t.Fatal(err)
			}
			data, _ := event["data"].(map[string]any)
			ev, _ := data["evidence"].(map[string]any)
			if end, ok := ev["rawSourceSeqEnd"].(float64); ok && end > maxSeq {
				maxSeq = end
				target = i
			}
		}
		if target < 0 {
			t.Fatal("no raw evidence reference found")
		}
		var event map[string]any
		if err := json.Unmarshal(frames[target], &event); err != nil {
			t.Fatal(err)
		}
		event["data"].(map[string]any)["evidence"].(map[string]any)["rawSourceSeqEnd"] = maxSeq + 1
		frame, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		frames[target] = frame
		b.Files["tracked-events.jsonl"] = append(bytes.Join(frames, []byte("\n")), '\n')
		b = repack(t, b, privateKey)
		if _, err := bundle.Validate(b, publicKey); err == nil || !strings.Contains(err.Error(), "references missing raw record") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("interior raw record deleted and renumbered", func(t *testing.T) {
		b := clone()
		var records []evidence.RawRecord
		if err := json.Unmarshal(b.Files["raw-records.json"], &records); err != nil {
			t.Fatal(err)
		}
		if len(records) < 3 {
			t.Fatalf("fixture has %d raw records", len(records))
		}
		drop := 1
		deleted := records[drop]
		kept := append([]evidence.RawRecord(nil), records[:drop]...)
		kept = append(kept, records[drop+1:]...)
		type remap struct {
			seq  uint64
			hash string
		}
		reseq := map[evidence.RawSource]map[uint64]remap{}
		chains := map[evidence.RawSource][]int{}
		for i, r := range kept {
			source := evidence.RawSource{SensorID: r.SensorID, BootID: r.BootID}
			chains[source] = append(chains[source], i)
		}
		for source, idxs := range chains {
			prev := ""
			for i, idx := range idxs {
				old := kept[idx].SourceSeq
				kept[idx].SourceSeq = uint64(i + 1)
				kept[idx].PreviousRecordSHA256 = prev
				hash, err := kept[idx].ComputedHash()
				if err != nil {
					t.Fatal(err)
				}
				kept[idx].RecordSHA256 = hash
				prev = hash
				if reseq[source] == nil {
					reseq[source] = map[uint64]remap{}
				}
				reseq[source][old] = remap{seq: kept[idx].SourceSeq, hash: hash}
			}
		}
		encoded, err := json.Marshal(kept)
		if err != nil {
			t.Fatal(err)
		}
		b.Files["raw-records.json"] = append(encoded, '\n')
		var rawFrames bytes.Buffer
		for _, r := range kept {
			frame, err := r.Frame()
			if err != nil {
				t.Fatal(err)
			}
			rawFrames.Write(frame)
		}
		b.Files["workload/raw-records.bin"] = rawFrames.Bytes()

		lines := bytes.Split(bytes.TrimRight(b.Files["tracked-events.jsonl"], "\n"), []byte("\n"))
		var mutated []map[string]any
		removed := false
		for _, line := range lines {
			var event map[string]any
			if err := json.Unmarshal(line, &event); err != nil {
				t.Fatal(err)
			}
			data, _ := event["data"].(map[string]any)
			ev, _ := data["evidence"].(map[string]any)
			if ev["rawRecordSha256"] == deleted.RecordSHA256 {
				removed = true
				continue
			}
			mutated = append(mutated, event)
		}
		if !removed {
			t.Fatal("no event references the deleted record")
		}
		for i, event := range mutated {
			event["seq"] = float64(i + 1)
			data, _ := event["data"].(map[string]any)
			source, _ := data["source"].(map[string]any)
			ev, _ := data["evidence"].(map[string]any)
			start, ok := ev["rawSourceSeqStart"].(float64)
			if !ok {
				continue
			}
			sensorID, _ := source["sensorId"].(string)
			bootID, _ := source["bootId"].(string)
			m, ok := reseq[evidence.RawSource{SensorID: sensorID, BootID: bootID}][uint64(start)]
			if !ok {
				continue
			}
			source["sourceSeq"] = float64(m.seq)
			ev["rawSourceSeqStart"] = float64(m.seq)
			ev["rawSourceSeqEnd"] = float64(m.seq)
			ev["rawRecordSha256"] = m.hash
		}
		var frames bytes.Buffer
		for _, event := range mutated {
			frame, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			frames.Write(frame)
			frames.WriteByte('\n')
		}
		b.Files["tracked-events.jsonl"] = frames.Bytes()
		b = repack(t, b, privateKey)
		if _, err := bundle.Validate(b, publicKey); err == nil || !strings.Contains(err.Error(), "head mismatch") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestBundleRejectsMutations(t *testing.T) {
	valid, publicKey, privateKey := produceBundle(t)
	wrongKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clone := func() bundle.Bundle {
		b := valid
		files := make(map[string][]byte, len(valid.Files))
		for k, v := range valid.Files {
			files[k] = append([]byte(nil), v...)
		}
		b.Files = files
		return b
	}
	for _, tc := range []struct {
		name   string
		mutate func(*bundle.Bundle)
		key    ed25519.PublicKey
		resign bool
	}{
		{"wrong key", func(b *bundle.Bundle) {}, wrongKey, false},
		{"changed file byte", func(b *bundle.Bundle) {
			b.Files["verification.json"][0] ^= 0xff
		}, publicKey, false},
		{"absent document", func(b *bundle.Bundle) {
			delete(b.Files, "sensor-health.json")
		}, publicKey, false},
		{"extra file", func(b *bundle.Bundle) {
			b.Files["extra.txt"] = []byte("x")
		}, publicKey, false},
		{"extra file resigned", func(b *bundle.Bundle) {
			b.Files["extra.txt"] = []byte("x")
		}, publicKey, true},
		{"traversal path", func(b *bundle.Bundle) {
			b.Files["../escape"] = []byte("x")
		}, publicKey, false},
		{"absolute path", func(b *bundle.Bundle) {
			b.Files["/abs"] = []byte("x")
		}, publicKey, false},
		{"backslash path", func(b *bundle.Bundle) {
			b.Files[`a\b`] = []byte("x")
		}, publicKey, false},
		{"colon path", func(b *bundle.Bundle) {
			b.Files["a:b"] = []byte("x")
		}, publicKey, false},
		{"stored count mismatch resigned", func(b *bundle.Bundle) {
			var v struct {
				Status                string    `json:"status"`
				Eligible              bool      `json:"eligible"`
				Summary               string    `json:"summary,omitempty"`
				CheckedAt             time.Time `json:"checkedAt,omitempty"`
				TrackedEventChainHead string    `json:"trackedEventChainHead,omitempty"`
				EventCount            uint64    `json:"eventCount,omitempty"`
			}
			if err := json.Unmarshal(bytes.TrimSpace(b.Files["verification.json"]), &v); err != nil {
				t.Fatal(err)
			}
			v.EventCount++
			encoded, _ := json.Marshal(v)
			b.Files["verification.json"] = append(encoded, '\n')
		}, publicKey, true},
		{"terminal event tampered resigned", func(b *bundle.Bundle) {
			data := bytes.Replace(b.Files["tracked-events.jsonl"], []byte(`"run/finish"`), []byte(`"run/finished"`), 1)
			b.Files["tracked-events.jsonl"] = data
		}, publicKey, true},
		{"missing raw reference resigned", func(b *bundle.Bundle) {
			frames := bytes.Split(bytes.TrimRight(b.Files["tracked-events.jsonl"], "\n"), []byte("\n"))
			var event map[string]any
			target := -1
			for i, frame := range frames {
				if err := json.Unmarshal(frame, &event); err != nil {
					t.Fatal(err)
				}
				if event["type"] == "process/exec" {
					target = i
					break
				}
			}
			if target < 0 {
				t.Fatal("no observation event found")
			}
			data := event["data"].(map[string]any)
			ev := data["evidence"].(map[string]any)
			ev["rawRecordSha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
			event["data"] = data
			frame, _ := json.Marshal(event)
			frames[target] = frame
			b.Files["tracked-events.jsonl"] = append(bytes.Join(frames, []byte("\n")), '\n')
		}, publicKey, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := clone()
			tc.mutate(&b)
			if tc.resign {
				b = repack(t, b, privateKey)
			}
			if _, err := bundle.Validate(b, tc.key); err == nil {
				t.Fatal("mutated bundle accepted")
			}
		})
	}
}
