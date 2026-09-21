// Package profile contains resolved evidence profiles.
package profile

import (
	"errors"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
)

const VerifiedName = "verified.v1"

// VerifiedPlan rejects configurations that would make the verified claim false.
func VerifiedPlan(plan backend.ObservationPlan) error { return plan.VerifiedInvariant() }

// ValidateVerifiedRun performs the profile checks which are available before
// signature verification: strict plan, resolved capability, and actual health.
func ValidateVerifiedRun(spec backend.RunSpec, plan backend.ObservationPlan, capabilities backend.CapabilityManifest, health backend.SensorHealth) error {
	if !spec.Verified {
		return errors.New("run is not declared verified")
	}
	if spec.Profile != VerifiedName {
		return errors.New("run does not declare the verified.v1 profile")
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	if err := plan.VerifiedInvariant(); err != nil {
		return err
	}
	if err := backend.ValidatePlanAgainstManifest(plan, capabilities, true); err != nil {
		return err
	}
	return health.VerifiedEligible()
}
