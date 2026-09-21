// Package verification composes the Phase 0 contract validators into the
// evidence-integrity check used by fixtures and, later, the public verifier.
package verification

import (
	"encoding/json"
	"fmt"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/eventlog"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/openaivalidator"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/plaintext"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/profile"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/replay"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

type Input struct {
	Events      []events.TrackedEvent
	Flows       []plaintext.FlowAccounting
	RawRecords  []evidence.RawRecord
	RawCoverage []evidence.NormalizedCoverage
	// Resolver supplies immutable bytes when a plaintext event references an artifact.
	Resolver plaintext.ArtifactResolver
	// RawRunSpecDigest and RawObservationPlanDigest bind raw chains to the declared run.
	RawRunSpecDigest         string
	RawObservationPlanDigest string
	ExpectedRawChainHeads    map[evidence.RawSource]string
	Eligibility              *EligibilityInput
}

// EligibilityInput is deliberately a profile contract, not an inference from
// event shape. A nil value means eligibility has not been evaluated.
type EligibilityInput struct {
	RunSpec            backend.RunSpec
	ObservationPlan    backend.ObservationPlan
	CapabilityManifest backend.CapabilityManifest
	SensorHealth       backend.SensorHealth
}

type Report struct {
	// IntegrityValid is retained for compatibility and means log integrity only.
	IntegrityValid            bool `json:"integrityValid"`
	LogIntegrityValid         bool `json:"logIntegrityValid"`
	RawEvidenceValidated      bool `json:"rawEvidenceValidated"`
	RawEvidenceIntegrityValid bool `json:"rawEvidenceIntegrityValid"`
	EligibilityEvaluated      bool `json:"eligibilityEvaluated"`
	// ProfileEligible means the declared plan, capability, and health inputs pass
	// the Phase 0 profile gate. It is not a completed cryptographic verification.
	ProfileEligible bool `json:"profileEligible"`
	// VerifiedEligible remains false until the later public verifier validates
	// signatures, artifact hashes, and the complete leaderboard admission policy.
	VerifiedEligible  bool     `json:"verifiedEligible"`
	EventCount        uint64   `json:"eventCount"`
	SurfaceEventCount uint64   `json:"surfaceEventCount"`
	PlaintextStreams  uint64   `json:"plaintextStreams"`
	ModelEvents       uint64   `json:"modelEvents"`
	Ineligibility     []string `json:"ineligibility,omitempty"`
}

// Verify validates log integrity, conversation replay, plaintext reconstruction,
// independent flow accounting, optional raw coverage, and every pinned model
// request/response/chunk projection. Integrity and leaderboard eligibility are
// deliberately separate outcomes.
func Verify(input Input) (Report, error) {
	var report Report
	if err := eventlog.Validate(input.Events); err != nil {
		return report, err
	}

	assembler := plaintext.NewAssembler()
	if input.Resolver != nil {
		assembler = plaintext.NewAssemblerWithResolver(input.Resolver)
	}
	for _, event := range input.Events {
		switch event.Type {
		case "network/plaintext":
			var data struct {
				Details events.NetworkPlaintext `json:"details"`
			}
			if err := json.Unmarshal(event.Data, &data); err != nil {
				return report, fmt.Errorf("event %d plaintext: %w", event.Seq, err)
			}
			if err := assembler.Add(data.Details); err != nil {
				return report, fmt.Errorf("event %d plaintext: %w", event.Seq, err)
			}
		case "model/request", "model/stream-chunk", "model/response":
			var data struct {
				Details events.OpenAICompatibleExchange `json:"details"`
			}
			if err := json.Unmarshal(event.Data, &data); err != nil {
				return report, fmt.Errorf("event %d model projection: %w", event.Seq, err)
			}
			kind := map[string]string{
				"model/request":      "request",
				"model/stream-chunk": "chunk",
				"model/response":     "response",
			}[event.Type]
			if data.Details.Schema != "openai.chat-completions.v1" {
				return report, fmt.Errorf("event %d uses model schema %q", event.Seq, data.Details.Schema)
			}
			if err := openaivalidator.Validate(kind, data.Details.Body); err != nil {
				return report, fmt.Errorf("event %d %s: %w", event.Seq, kind, err)
			}
			report.ModelEvents++
		case "sensor/gap", "sensor/drop", "sensor/saturation", "sensor/parse-failure":
			report.Ineligibility = append(report.Ineligibility, event.Type)
		case "network/plaintext-failure", "sensor/bypass-attempt":
			report.Ineligibility = append(report.Ineligibility, event.Type)
		}
	}

	if err := assembler.ReconcileFlows(input.Flows); err != nil {
		return report, err
	}
	if len(input.RawRecords) != 0 || len(input.RawCoverage) != 0 || len(input.ExpectedRawChainHeads) != 0 {
		if err := evidence.ValidateRawCoverage(input.RawRecords, input.RawCoverage); err != nil {
			return report, err
		}
		if err := validateRawChains(input); err != nil {
			return report, err
		}
		report.RawEvidenceValidated = true
		report.RawEvidenceIntegrityValid = true
	}
	surface, err := replay.Replay(input.Events)
	if err != nil {
		return report, err
	}
	report.EventCount = uint64(len(input.Events))
	report.SurfaceEventCount = uint64(len(surface))
	report.PlaintextStreams = uint64(len(assembler.StreamKeys()))
	report.LogIntegrityValid = true
	report.IntegrityValid = true
	if input.Eligibility != nil {
		report.EligibilityEvaluated = true
		if err := profile.ValidateVerifiedRun(input.Eligibility.RunSpec, input.Eligibility.ObservationPlan, input.Eligibility.CapabilityManifest, input.Eligibility.SensorHealth); err != nil {
			report.Ineligibility = append(report.Ineligibility, "profile: "+err.Error())
		}
		if len(report.Ineligibility) == 0 {
			report.ProfileEligible = true
		}
	}
	return report, nil
}

func validateRawChains(input Input) error {
	if input.RawRunSpecDigest == "" || input.RawObservationPlanDigest == "" {
		return fmt.Errorf("raw records require run spec and observation plan digests")
	}
	chains := map[evidence.RawSource][]evidence.RawRecord{}
	for _, r := range input.RawRecords {
		source := evidence.RawSource{SensorID: r.SensorID, BootID: r.BootID}
		chains[source] = append(chains[source], r)
	}
	if len(chains) != len(input.ExpectedRawChainHeads) {
		return fmt.Errorf("raw chain heads do not match supplied chains")
	}
	for key, records := range chains {
		seed, err := evidence.ChainSeed(input.RawRunSpecDigest, input.RawObservationPlanDigest, records[0].SensorID, records[0].BootID)
		if err != nil {
			return err
		}
		head, err := evidence.ValidateChain(records, seed)
		if err != nil {
			return fmt.Errorf("raw chain %q/%q: %w", key.SensorID, key.BootID, err)
		}
		if expected, ok := input.ExpectedRawChainHeads[key]; !ok || expected != head {
			return fmt.Errorf("raw chain %q/%q head mismatch or missing", key.SensorID, key.BootID)
		}
	}
	return nil
}
