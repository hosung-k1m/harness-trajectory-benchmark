package verification

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/eventlog"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/plaintext"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/profile"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/projection"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/replay"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

// These cases mirror the tracked-event mutations in scripts/schema_check.py.
// The independent schema check and the Go validator must agree on the corpus.
func TestPhase0TrackedEventSchemaParity(t *testing.T) {
	file, err := os.Open("../../testdata/golden/tracked-events.v1.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	log, err := eventlog.DecodeJSONL(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range log {
		if err := events.ValidateEvent(event); err != nil {
			t.Fatalf("golden event %d: %v", event.Seq, err)
		}
	}
	tests := []struct {
		name   string
		mutate func(*events.TrackedEvent)
	}{
		{"zero sequence", func(e *events.TrackedEvent) { e.Seq = 0 }},
		{"empty type", func(e *events.TrackedEvent) { e.Type = "" }},
		{"null data", func(e *events.TrackedEvent) { e.Data = json.RawMessage("null") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			event := log[0]
			tc.mutate(&event)
			if err := events.ValidateEvent(event); err == nil {
				t.Fatal("Go validator accepted a schema-negative event")
			}
		})
	}
}

func TestPhase0EvidenceSchemaParity(t *testing.T) {
	record := evidence.RawRecord{
		RunID: "run", SensorID: "sensor", BootID: "boot", SourceSeq: 1,
		RecordType: "test", Encoding: "binary", Payload: []byte("payload"),
		RecordSHA256: "0431ce86610432c4bcf96f2a4f3b53f5e2378771cf138a6281922727b8e2975b",
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("schema-positive raw record: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*evidence.RawRecord)
	}{
		{"zero sequence", func(r *evidence.RawRecord) { r.SourceSeq = 0 }},
		{"invalid digest", func(r *evidence.RawRecord) { r.RecordSHA256 = "bad" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := record
			tc.mutate(&bad)
			if err := bad.Validate(); err == nil {
				t.Fatal("Go validator accepted a schema-negative raw record")
			}
		})
	}

	digest := strings.Repeat("a", 64)
	manifest := evidence.RunEvidenceManifest{
		SchemaVersion: "v1", RunID: "run", RunSpecDigest: digest,
		ObservationPlanDigest: digest, CapabilityManifestDigest: digest,
		SensorHealthDigest: digest, TrackedEventChainHead: digest,
		RawChainHeads: map[string]string{}, Artifacts: []evidence.ArtifactDigest{},
		MerkleRoot: digest, SealedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("schema-positive manifest: %v", err)
	}
	manifest.MerkleRoot = "bad"
	if err := manifest.Validate(); err == nil {
		t.Fatal("Go validator accepted a schema-negative manifest")
	}
}

func TestPhase0GoldenAcceptance(t *testing.T) {
	file, err := os.Open("../../testdata/golden/tracked-events.v1.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	log, err := eventlog.DecodeJSONL(file)
	if err != nil {
		t.Fatal(err)
	}

	surface, err := replay.Replay(log)
	if err != nil || len(surface) != 5 {
		t.Fatalf("conversation replay: surface=%d err=%v", len(surface), err)
	}
	analysis, err := projection.Build(log)
	if err != nil {
		t.Fatal(err)
	}
	if analysis.EventCount != 20 || analysis.SensorLossEvents != 1 || analysis.ModelExchanges["exchange-1"] != 3 {
		t.Fatalf("unexpected analysis: %#v", analysis)
	}

	egress := []byte("POST /v1/chat")
	ingress := []byte(`{"id":"chatcmpl-1","choices":[]}`)
	report, err := Verify(Input{
		Events: log,
		Flows: []plaintext.FlowAccounting{
			{ConnectionID: "conn-1", StreamID: "stream-1", Direction: "egress", Bytes: uint64(len(egress)), SHA256: backend.SHA256Hex(egress)},
			{ConnectionID: "conn-1", StreamID: "stream-1", Direction: "ingress", Bytes: uint64(len(ingress)), SHA256: backend.SHA256Hex(ingress)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.IntegrityValid || report.VerifiedEligible || report.PlaintextStreams != 2 || report.ModelEvents != 3 {
		t.Fatalf("unexpected verification report: %#v", report)
	}
	if report.EligibilityEvaluated || report.RawEvidenceValidated {
		t.Fatalf("verification stages were reported without inputs: %#v", report)
	}
	if len(report.Ineligibility) != 1 || !strings.Contains(report.Ineligibility[0], "sensor/drop") {
		t.Fatalf("unexpected eligibility reasons: %#v", report.Ineligibility)
	}
}

func TestProfileEligibilityDoesNotClaimCompletedVerification(t *testing.T) {
	digest := strings.Repeat("a", 64)
	eligibility := &EligibilityInput{
		RunSpec: backend.RunSpec{SchemaVersion: "v1", RunID: "run", HarnessDigest: digest, BenchmarkDigest: digest, PolicyDigest: digest, Profile: profile.VerifiedName, Verified: true},
		ObservationPlan: backend.ObservationPlan{
			SchemaVersion: "v1", PlaintextRequired: true, PreserveDestinations: true, OpaqueTrafficPolicy: backend.OpaqueTrafficDeny,
			Requirements: []backend.ObservationRequirement{{EventFamily: "network/plaintext", MinimumObservation: backend.ObservationComplete, MinimumEnforcement: backend.EnforcementSynchronous, Retention: "full", RequiredForVerifiedRun: true}},
		},
		CapabilityManifest: backend.CapabilityManifest{
			SchemaVersion: "v1", Backend: "test", Version: "1", TrustDomain: "host",
			Capabilities: []backend.Capability{{EventFamily: "network/plaintext", Observation: backend.ObservationComplete, Enforcement: backend.EnforcementSynchronous, Retention: "full"}},
		},
		SensorHealth: backend.SensorHealth{SchemaVersion: "v1", Sources: []backend.SensorSourceHealth{{SensorID: "sensor", BootID: "boot", Started: true, Drained: true, Stopped: true}}},
	}

	report, err := Verify(Input{Eligibility: eligibility})
	if err != nil {
		t.Fatal(err)
	}
	if !report.EligibilityEvaluated || !report.ProfileEligible || report.VerifiedEligible {
		t.Fatalf("unexpected phase 0 eligibility report: %#v", report)
	}
}

func TestRawEvidenceStageRequiresCoverageAndMatchingChainHead(t *testing.T) {
	runDigest := strings.Repeat("a", 64)
	planDigest := strings.Repeat("b", 64)
	record := evidence.RawRecord{RunID: "run", SensorID: "sensor", BootID: "boot", SourceSeq: 1, RecordType: "test", Encoding: "binary", Payload: []byte("payload")}
	var err error
	record.RecordSHA256, err = record.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := evidence.ChainSeed(runDigest, planDigest, record.SensorID, record.BootID)
	if err != nil {
		t.Fatal(err)
	}
	head, err := evidence.ValidateChain([]evidence.RawRecord{record}, seed)
	if err != nil {
		t.Fatal(err)
	}
	source := evidence.RawSource{SensorID: record.SensorID, BootID: record.BootID}
	report, err := Verify(Input{
		RawRecords:               []evidence.RawRecord{record},
		RawCoverage:              []evidence.NormalizedCoverage{{Raw: evidence.RawRange{SensorID: record.SensorID, BootID: record.BootID, Start: 1, End: 1}, EventID: "event"}},
		RawRunSpecDigest:         runDigest,
		RawObservationPlanDigest: planDigest,
		ExpectedRawChainHeads:    map[evidence.RawSource]string{source: head},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.RawEvidenceValidated || !report.RawEvidenceIntegrityValid || report.VerifiedEligible {
		t.Fatalf("unexpected raw evidence report: %#v", report)
	}
}

func TestVerifyRejectsDroppedPlaintextAtFlowBoundary(t *testing.T) {
	file, err := os.Open("../../testdata/golden/tracked-events.v1.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	log, err := eventlog.DecodeJSONL(file)
	if err != nil {
		t.Fatal(err)
	}
	// A flow accounting record that omits bytes observed by the plaintext
	// assembler must fail closed; otherwise dropped evidence could look valid.
	_, err = Verify(Input{Events: log, Flows: []plaintext.FlowAccounting{{
		ConnectionID: "conn-1", StreamID: "stream-1", Direction: "egress",
		Bytes: 1, SHA256: backend.SHA256Hex([]byte("wrong")),
	}}})
	if err == nil {
		t.Fatal("Verify accepted dropped or mismatched plaintext accounting")
	}
}
