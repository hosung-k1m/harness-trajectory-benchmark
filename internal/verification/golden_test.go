package verification

import (
	"os"
	"strings"
	"testing"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/eventlog"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/plaintext"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/profile"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/projection"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/replay"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
)

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
