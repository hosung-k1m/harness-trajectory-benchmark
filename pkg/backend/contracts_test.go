package backend

import (
	"strings"
	"testing"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

func TestRunSpecRejectsNonCanonicalDigestCase(t *testing.T) {
	upper := strings.ToUpper(digest("run"))
	spec := RunSpec{SchemaVersion: "v1", RunID: "run", HarnessDigest: upper, BenchmarkDigest: digest("benchmark"), PolicyDigest: digest("policy")}
	if err := spec.Validate(); err == nil {
		t.Fatal("accepted uppercase digest")
	}
}

func digest(s string) string { return SHA256Hex([]byte(s)) }

func TestVerifiedPlanAndCapabilityValidation(t *testing.T) {
	plan := ObservationPlan{SchemaVersion: "v1", PlaintextRequired: true, PreserveDestinations: true, OpaqueTrafficPolicy: OpaqueTrafficDeny, Requirements: []ObservationRequirement{{EventFamily: "network/plaintext", MinimumObservation: ObservationComplete, MinimumEnforcement: EnforcementSynchronous, Retention: "full", RequiredForVerifiedRun: true}}}
	manifest := CapabilityManifest{SchemaVersion: "v1", Backend: "test", Version: "1", TrustDomain: "host", Capabilities: []Capability{{EventFamily: "network/plaintext", Observation: ObservationComplete, Enforcement: EnforcementSynchronous, Retention: "full"}}}
	if err := ValidatePlanAgainstManifest(plan, manifest, true); err != nil {
		t.Fatal(err)
	}
	plan.OpaqueTrafficPolicy = OpaqueTrafficAllow
	if err := ValidatePlanAgainstManifest(plan, manifest, true); err == nil {
		t.Fatal("verified opaque policy accepted")
	}
}

func TestNetworkPlaintextShape(t *testing.T) {
	off := uint64(0)
	p := events.NetworkPlaintext{Boundary: "sandbox", CapturePoint: "tap", ConnectionID: "c", StreamID: "s", Transport: "tcp", Direction: "egress", Sequence: 1, Offset: &off, Protocol: events.ProtocolIdentity{Name: "raw"}, Payload: events.CapturedBytes{Encoding: "utf8", Inline: "hello", Length: 5, SHA256: digest("hello")}, Capture: events.PlaintextCapture{Method: "native-plaintext", Backend: "test"}}
	if err := ValidateNetworkPlaintext(p); err != nil {
		t.Fatal(err)
	}
	p.Payload.SHA256 = "bad"
	if err := ValidateNetworkPlaintext(p); err == nil {
		t.Fatal("bad hash shape accepted")
	}
}

func TestVerifiedHealthRequiresExpectedObservedCoverage(t *testing.T) {
	health := SensorHealth{SchemaVersion: "v1", Sources: []SensorSourceHealth{{
		SensorID: "sensor", BootID: "boot", ExpectedStart: 1, ExpectedEnd: 2,
		ObservedStart: 1, ObservedEnd: 1, Started: true, Drained: true, Stopped: true,
	}}}
	if err := health.VerifiedEligible(); err == nil {
		t.Fatal("accepted incomplete source range without an accounted gap")
	}
	health.Sources[0].ObservedEnd = 2
	if err := health.VerifiedEligible(); err != nil {
		t.Fatal(err)
	}
}

func TestSensorHealthKeepsIdentityFieldsSeparate(t *testing.T) {
	health := SensorHealth{SchemaVersion: "v1", Sources: []SensorSourceHealth{
		{SensorID: "a\x00b", BootID: "c"},
		{SensorID: "a", BootID: "b\x00c"},
	}}
	if err := health.Validate(); err != nil {
		t.Fatalf("distinct sensor sources collided: %v", err)
	}
}
