package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/bundle"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
)

func (d *CompatDriver) writeManifest(runID string, run *compatRun, backendEvidence backend.BackendEvidence, health backend.SensorHealth, records []evidence.RawRecord, result api.VerificationResult) error {
	d.mu.Lock()
	root := d.manifestRoot
	key := append(ed25519.PrivateKey(nil), d.signingKey...)
	d.mu.Unlock()
	if root == "" {
		return nil
	}
	chainHead, err := d.store.RunHashHead(runID)
	if err != nil {
		return err
	}
	capabilities, err := d.backend.Describe(context.Background())
	if err != nil {
		return err
	}
	workloadDir, err := d.backend.RunDirectory(context.Background(), run.handle)
	if err != nil {
		return err
	}
	tracked, err := d.store.ExportEvents(runID)
	if err != nil {
		return err
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
		"capability-manifest.json": capabilities,
		"sensor-health.json":       health,
		"raw-records.json":         records,
		"verification.json":        result,
	} {
		if err := putJSON(name, v); err != nil {
			return err
		}
	}
	files["tracked-events.jsonl"] = tracked
	files["tracked-events.jsonl.sealed"] = []byte(chainHead + "\n")

	workloadRoot, err := os.OpenRoot(workloadDir)
	if err != nil {
		return err
	}
	defer workloadRoot.Close()
	readWorkload := func(name string) ([]byte, error) {
		info, err := workloadRoot.Lstat(name)
		if err != nil {
			return nil, fmt.Errorf("workload artifact %q: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("workload artifact %q is not a regular file", name)
		}
		file, err := workloadRoot.Open(name)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return io.ReadAll(file)
	}
	rawFrames, err := readWorkload("raw-records.bin")
	if err != nil {
		return err
	}
	files["workload/raw-records.bin"] = rawFrames
	for _, name := range backendEvidence.ArtifactIDs {
		if name == "" || filepath.Base(name) != name {
			return fmt.Errorf("unsafe backend artifact name %q", name)
		}
		content, err := readWorkload(name)
		if err != nil {
			return fmt.Errorf("read artifact %q: %w", name, err)
		}
		files["workload/"+name] = content
	}

	manifest := evidence.RunEvidenceManifest{
		SchemaVersion: "v1", RunID: runID,
		RunSpecDigest: digestJSON(run.spec), ObservationPlanDigest: digestJSON(run.plan),
		CapabilityManifestDigest: capabilities.Digest, SensorHealthDigest: digestJSON(health),
		TrackedEventChainHead: chainHead, RawChainHeads: backendEvidence.RawChainHeads,
		SealedAt: time.Now().UTC(),
	}
	published, err := buildEvidenceBundle(key, manifest, files)
	if err != nil {
		return err
	}
	manifestJSON, err := json.MarshalIndent(published.Manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestJSON = append(manifestJSON, '\n')
	publicKey, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("invalid manifest signing key")
	}
	if _, err := bundle.Validate(published, publicKey); err != nil {
		return fmt.Errorf("evidence bundle self-validation failed: %w", err)
	}
	bundleJSON, err := json.Marshal(published)
	if err != nil {
		return err
	}
	bundleJSON = append(bundleJSON, '\n')
	runDir := filepath.Join(root, "runs", runID)
	if err := writeFileAtomic(filepath.Join(runDir, "evidence-manifest.json"), manifestJSON); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(runDir, "evidence-bundle.json"), bundleJSON)
}

func buildEvidenceBundle(key ed25519.PrivateKey, manifest evidence.RunEvidenceManifest, files map[string][]byte) (bundle.Bundle, error) {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	leaves := []string{manifest.RunSpecDigest, manifest.ObservationPlanDigest, manifest.CapabilityManifestDigest, manifest.SensorHealthDigest, manifest.TrackedEventChainHead}
	for _, head := range manifest.RawChainHeads {
		leaves = append(leaves, head)
	}
	for _, path := range paths {
		hash := backend.SHA256Hex(files[path])
		manifest.Artifacts = append(manifest.Artifacts, evidence.ArtifactDigest{Path: path, SHA256: hash, Size: uint64(len(files[path]))})
		leaves = append(leaves, hash)
	}
	merkleRoot, err := evidence.ComputeMerkleRoot(leaves)
	if err != nil {
		return bundle.Bundle{}, err
	}
	manifest.MerkleRoot = merkleRoot
	signed, err := evidence.SignManifest(manifest, key)
	if err != nil {
		return bundle.Bundle{}, err
	}
	return bundle.Bundle{SchemaVersion: bundle.Version, RunID: manifest.RunID, Manifest: signed, Files: files}, nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".publish-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}
