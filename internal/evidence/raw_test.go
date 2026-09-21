package evidence

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestRawFrameAndChainAreByteExact(t *testing.T) {
	seed, err := ChainSeed(hash("run"), hash("plan"), "sensor", "boot")
	if err != nil {
		t.Fatal(err)
	}
	r1 := RawRecord{RunID: "run", SensorID: "sensor", BootID: "boot", SourceSeq: 1, RecordType: "x", Encoding: "binary", Payload: []byte{0, 1, 2}}
	r1.RecordSHA256, err = r1.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	r2 := RawRecord{RunID: "run", SensorID: "sensor", BootID: "boot", SourceSeq: 2, RecordType: "x", Encoding: "binary", Payload: []byte("two"), PreviousRecordSHA256: r1.RecordSHA256}
	r2.RecordSHA256, err = r2.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	head, err := ValidateChain([]RawRecord{r1, r2}, seed)
	if err != nil || head == "" {
		t.Fatalf("head=%q err=%v", head, err)
	}
	// A byte-level change changes the frame digest even when metadata is identical.
	changed := r1
	changed.Payload = []byte{0, 1, 3}
	if got, _ := changed.ComputedHash(); got == r1.RecordSHA256 {
		t.Fatal("payload mutation preserved frame hash")
	}
	bad := r2
	bad.RecordSHA256 = r1.RecordSHA256
	if _, err := ValidateChain([]RawRecord{r1, bad}, seed); err == nil {
		t.Fatal("forged record hash accepted")
	}
}

func TestRawRecordRejectsZeroSourceSequence(t *testing.T) {
	record := RawRecord{RunID: "run", SensorID: "sensor", BootID: "boot", RecordType: "test", Encoding: "binary"}
	record.RecordSHA256, _ = record.ComputedHash()
	if err := record.Validate(); err == nil {
		t.Fatal("accepted zero source sequence")
	}
}
func TestChainRejectsNonCanonicalFirstAndMissingPreviousHash(t *testing.T) {
	seed, _ := ChainSeed(hash("run"), hash("plan"), "sensor", "boot")
	r1 := RawRecord{RunID: "run", SensorID: "sensor", BootID: "boot", SourceSeq: 2, RecordType: "x", Encoding: "binary"}
	r1.RecordSHA256, _ = r1.ComputedHash()
	if _, err := ValidateChain([]RawRecord{r1}, seed); err == nil {
		t.Fatal("non-one first sequence accepted")
	}
	r1.SourceSeq = 1
	r1.RecordSHA256, _ = r1.ComputedHash()
	r2 := r1
	r2.SourceSeq = 2
	r2.RecordSHA256, _ = r2.ComputedHash()
	if _, err := ValidateChain([]RawRecord{r1, r2}, seed); err == nil {
		t.Fatal("missing previous record hash accepted")
	}
}

func TestChainSeedUsesDomainSeparatedLengthFraming(t *testing.T) {
	run, plan := hash("run"), hash("plan")
	a, err := ChainSeed(run, plan, "ab", "c")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ChainSeed(run, plan, "a", "bc")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("ambiguous concatenated identities have same seed")
	}
}

func TestChainSeedRejectsNonCanonicalDigestCase(t *testing.T) {
	if _, err := ChainSeed(hash("run"), strings.ToUpper(hash("plan")), "sensor", "boot"); err == nil {
		t.Fatal("accepted uppercase digest")
	}
}
func TestRawCoverageRejectsGapsAndDuplicates(t *testing.T) {
	rs := []RawRecord{{RunID: "r", SensorID: "s", BootID: "b", SourceSeq: 1}, {RunID: "r", SensorID: "s", BootID: "b", SourceSeq: 2}}
	c := []NormalizedCoverage{{Raw: RawRange{SensorID: "s", BootID: "b", Start: 1, End: 2}, EventID: "event"}}
	if err := ValidateRawCoverage(rs, c); err != nil {
		t.Fatal(err)
	}
	c = append(c, NormalizedCoverage{Raw: RawRange{SensorID: "s", BootID: "b", Start: 2, End: 2}, BatchID: "batch"})
	if err := ValidateRawCoverage(rs, c); err == nil {
		t.Fatal("double coverage accepted")
	}
}
func TestRawCoverageRejectsSparseHugeAndWrapRanges(t *testing.T) {
	rs := []RawRecord{{SensorID: "s", BootID: "b", SourceSeq: 1}}
	if err := ValidateRawCoverage(rs, []NormalizedCoverage{{Raw: RawRange{SensorID: "s", BootID: "b", Start: 1, End: math.MaxUint64}, EventID: "e"}}); err == nil {
		t.Fatal("huge sparse range accepted")
	}
	if err := ValidateRawCoverage(rs, []NormalizedCoverage{{Raw: RawRange{SensorID: "s", BootID: "b", Start: math.MaxUint64, End: 1}, EventID: "e"}}); err == nil {
		t.Fatal("wrapping range accepted")
	}
}

func TestRawCoverageKeepsSourceIdentityFieldsSeparate(t *testing.T) {
	records := []RawRecord{
		{SensorID: "a\x00b", BootID: "c", SourceSeq: 1},
		{SensorID: "a", BootID: "b\x00c", SourceSeq: 1},
	}
	coverage := []NormalizedCoverage{
		{Raw: RawRange{SensorID: "a\x00b", BootID: "c", Start: 1, End: 1}, EventID: "one"},
		{Raw: RawRange{SensorID: "a", BootID: "b\x00c", Start: 1, End: 1}, EventID: "two"},
	}
	if err := ValidateRawCoverage(records, coverage); err != nil {
		t.Fatalf("distinct sources collided: %v", err)
	}
}

func TestManifestRejectsUnsafeAndDuplicateArtifactPaths(t *testing.T) {
	digest := hash("digest")
	manifest := RunEvidenceManifest{
		SchemaVersion: "v1", RunID: "run", RunSpecDigest: digest, ObservationPlanDigest: digest,
		CapabilityManifestDigest: digest, SensorHealthDigest: digest, TrackedEventChainHead: digest,
		MerkleRoot: digest, SealedAt: time.Unix(1, 0).UTC(),
		Artifacts: []ArtifactDigest{{Path: "../outside", SHA256: digest}},
	}
	if err := manifest.Validate(); err == nil {
		t.Fatal("accepted traversal artifact path")
	}
	manifest.Artifacts = []ArtifactDigest{{Path: "logs/events.jsonl", SHA256: digest}, {Path: "logs/events.jsonl", SHA256: digest}}
	if err := manifest.Validate(); err == nil {
		t.Fatal("accepted duplicate artifact path")
	}
}
func hash(s string) string {
	r := RawRecord{RunID: s, SensorID: s, BootID: s, SourceSeq: 1, RecordType: s, Encoding: s, Payload: []byte(s)}
	h, _ := r.ComputedHash()
	return h
}
