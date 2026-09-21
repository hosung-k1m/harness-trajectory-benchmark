package profile

import (
	"strings"
	"testing"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
)

func TestValidateVerifiedRunBehavior(t *testing.T) {
	digest := strings.Repeat("a", 64)
	spec := backend.RunSpec{SchemaVersion: "v1", RunID: "run", HarnessDigest: digest, BenchmarkDigest: digest, PolicyDigest: digest, Profile: VerifiedName, Verified: true}
	plan := backend.ObservationPlan{
		SchemaVersion: "v1", PlaintextRequired: true, PreserveDestinations: true, OpaqueTrafficPolicy: backend.OpaqueTrafficDeny,
		Requirements: []backend.ObservationRequirement{{EventFamily: "network/plaintext", MinimumObservation: backend.ObservationComplete, MinimumEnforcement: backend.EnforcementSynchronous, Retention: "full", RequiredForVerifiedRun: true}},
	}
	manifest := backend.CapabilityManifest{
		SchemaVersion: "v1", Backend: "test", Version: "1", TrustDomain: "host",
		Capabilities: []backend.Capability{{EventFamily: "network/plaintext", Observation: backend.ObservationComplete, Enforcement: backend.EnforcementSynchronous, Retention: "full"}},
	}
	health := backend.SensorHealth{SchemaVersion: "v1", Sources: []backend.SensorSourceHealth{{SensorID: "sensor", BootID: "boot", Started: true, Drained: true, Stopped: true}}}

	if err := ValidateVerifiedRun(spec, plan, manifest, health); err != nil {
		t.Fatal(err)
	}
	spec.Verified = false
	if err := ValidateVerifiedRun(spec, plan, manifest, health); err == nil {
		t.Fatal("accepted a run not declared verified")
	}
	spec.Verified = true
	spec.Profile = "best-effort"
	if err := ValidateVerifiedRun(spec, plan, manifest, health); err == nil {
		t.Fatal("accepted a different evidence profile")
	}
	spec.Profile = VerifiedName
	health.Sources[0].Drops = 1
	if err := ValidateVerifiedRun(spec, plan, manifest, health); err == nil {
		t.Fatal("accepted unhealthy sensor evidence")
	}
}
