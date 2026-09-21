// Package backend defines the public, backend-neutral execution contract.
package backend

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

const (
	ObservationComplete    = "complete"
	ObservationConditional = "conditional"
	ObservationBestEffort  = "best_effort"
	ObservationSampled     = "sampled"
	ObservationAggregated  = "aggregated"
	ObservationUnsupported = "unsupported"

	EnforcementSynchronous = "synchronous"
	EnforcementEventual    = "eventual"
	EnforcementAuditOnly   = "audit_only"
	EnforcementUnsupported = "unsupported"
	OpaqueTrafficDeny      = "deny"
	OpaqueTrafficAllow     = "allow"
)

// RunSpec is the immutable, declared input to one execution.
type RunSpec struct {
	SchemaVersion   string            `json:"schemaVersion"`
	RunID           string            `json:"runId"`
	HarnessDigest   string            `json:"harnessDigest"`
	BenchmarkDigest string            `json:"benchmarkDigest"`
	PolicyDigest    string            `json:"policyDigest"`
	Profile         string            `json:"profile"`
	Verified        bool              `json:"verified"`
	Labels          map[string]string `json:"labels,omitempty"`
}

func (r RunSpec) Validate() error {
	if strings.TrimSpace(r.SchemaVersion) == "" || strings.TrimSpace(r.RunID) == "" {
		return errors.New("run spec requires schemaVersion and runId")
	}
	for name, digest := range map[string]string{"harnessDigest": r.HarnessDigest, "benchmarkDigest": r.BenchmarkDigest, "policyDigest": r.PolicyDigest} {
		if !isSHA256(digest) {
			return fmt.Errorf("run spec %s must be a sha256 hex digest", name)
		}
	}
	return nil
}

type ObservationRequirement struct {
	EventFamily            string `json:"eventFamily"`
	MinimumObservation     string `json:"minimumObservation"`
	MinimumEnforcement     string `json:"minimumEnforcement"`
	Retention              string `json:"retention"`
	RequiredForVerifiedRun bool   `json:"requiredForVerifiedRun"`
}

func (r ObservationRequirement) Validate() error {
	if r.EventFamily == "" || !validObservation(r.MinimumObservation) || !validEnforcement(r.MinimumEnforcement) || r.Retention == "" {
		return fmt.Errorf("invalid observation requirement for %q", r.EventFamily)
	}
	return nil
}

type ObservationPlan struct {
	SchemaVersion        string                   `json:"schemaVersion"`
	Requirements         []ObservationRequirement `json:"requirements"`
	SensorConfigs        []json.RawMessage        `json:"sensorConfigs"`
	PlaintextRequired    bool                     `json:"plaintextRequired"`
	PreserveDestinations bool                     `json:"preserveDestinations"`
	OpaqueTrafficPolicy  string                   `json:"opaqueTrafficPolicy"`
}

func (p ObservationPlan) Validate() error {
	if p.SchemaVersion == "" {
		return errors.New("observation plan requires schemaVersion")
	}
	if p.OpaqueTrafficPolicy != OpaqueTrafficDeny && p.OpaqueTrafficPolicy != OpaqueTrafficAllow {
		return fmt.Errorf("invalid opaque traffic policy %q", p.OpaqueTrafficPolicy)
	}
	seen := make(map[string]bool)
	for _, r := range p.Requirements {
		if err := r.Validate(); err != nil {
			return err
		}
		if seen[r.EventFamily] {
			return fmt.Errorf("duplicate observation requirement %q", r.EventFamily)
		}
		seen[r.EventFamily] = true
	}
	return nil
}

// VerifiedInvariant validates the stricter profile-independent verified rules.
func (p ObservationPlan) VerifiedInvariant() error {
	if !p.PlaintextRequired || !p.PreserveDestinations || p.OpaqueTrafficPolicy != OpaqueTrafficDeny {
		return errors.New("verified run requires plaintext, destination preservation, and deny opaque traffic")
	}
	return nil
}

type Capability struct {
	EventFamily string            `json:"eventFamily"`
	Observation string            `json:"observation"`
	Enforcement string            `json:"enforcement"`
	Retention   string            `json:"retention"`
	Details     map[string]string `json:"details,omitempty"`
}

type CapabilityManifest struct {
	SchemaVersion string       `json:"schemaVersion"`
	Backend       string       `json:"backend"`
	Version       string       `json:"version"`
	TrustDomain   string       `json:"trustDomain"`
	Capabilities  []Capability `json:"capabilities"`
	Digest        string       `json:"digest,omitempty"`
}

func (m CapabilityManifest) Validate() error {
	if m.SchemaVersion == "" || m.Backend == "" || m.Version == "" || m.TrustDomain == "" {
		return errors.New("capability manifest requires schemaVersion, backend, version, and trustDomain")
	}
	seen := map[string]bool{}
	for _, c := range m.Capabilities {
		if c.EventFamily == "" || !validObservation(c.Observation) || !validEnforcement(c.Enforcement) || c.Retention == "" {
			return fmt.Errorf("invalid capability %q", c.EventFamily)
		}
		if seen[c.EventFamily] {
			return fmt.Errorf("duplicate capability %q", c.EventFamily)
		}
		seen[c.EventFamily] = true
	}
	if m.Digest != "" && !isSHA256(m.Digest) {
		return errors.New("capability manifest digest must be sha256 hex")
	}
	return nil
}

// ValidatePlanAgainstManifest rejects capabilities that are weaker than required.
func ValidatePlanAgainstManifest(plan ObservationPlan, manifest CapabilityManifest, verified bool) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	if verified {
		if err := plan.VerifiedInvariant(); err != nil {
			return err
		}
	}
	byFamily := make(map[string]Capability, len(manifest.Capabilities))
	for _, c := range manifest.Capabilities {
		byFamily[c.EventFamily] = c
	}
	for _, req := range plan.Requirements {
		c, ok := byFamily[req.EventFamily]
		if !ok {
			return fmt.Errorf("backend lacks capability %q", req.EventFamily)
		}
		if observationRank(c.Observation) > observationRank(req.MinimumObservation) {
			return fmt.Errorf("capability %q observation %q does not meet %q", req.EventFamily, c.Observation, req.MinimumObservation)
		}
		if enforcementRank(c.Enforcement) > enforcementRank(req.MinimumEnforcement) {
			return fmt.Errorf("capability %q enforcement %q does not meet %q", req.EventFamily, c.Enforcement, req.MinimumEnforcement)
		}
		if verified && req.RequiredForVerifiedRun && (c.Observation == ObservationUnsupported || c.Enforcement == EnforcementUnsupported) {
			return fmt.Errorf("verified requirement %q unsupported", req.EventFamily)
		}
	}
	return nil
}

type SensorSourceHealth struct {
	SensorID          string `json:"sensorId"`
	BootID            string `json:"bootId"`
	ExpectedStart     uint64 `json:"expectedStart"`
	ExpectedEnd       uint64 `json:"expectedEnd"`
	ObservedStart     uint64 `json:"observedStart"`
	ObservedEnd       uint64 `json:"observedEnd"`
	Gaps              uint64 `json:"gaps"`
	Duplicates        uint64 `json:"duplicates"`
	Drops             uint64 `json:"drops"`
	ParseFailures     uint64 `json:"parseFailures"`
	PlaintextFailures uint64 `json:"plaintextFailures"`
	StreamGaps        uint64 `json:"streamGaps"`
	UnreconciledFlows uint64 `json:"unreconciledFlows"`
	Started           bool   `json:"started"`
	Drained           bool   `json:"drained"`
	Stopped           bool   `json:"stopped"`
}

type SensorHealth struct {
	SchemaVersion     string               `json:"schemaVersion"`
	Sources           []SensorSourceHealth `json:"sources"`
	AppenderDrops     uint64               `json:"appenderDrops"`
	OpaqueConnections uint64               `json:"opaqueConnections"`
}

func (h SensorHealth) Validate() error {
	if h.SchemaVersion == "" {
		return errors.New("sensor health requires schemaVersion")
	}
	type sourceIdentity struct {
		sensorID string
		bootID   string
	}
	seen := map[sourceIdentity]bool{}
	for _, s := range h.Sources {
		key := sourceIdentity{sensorID: s.SensorID, bootID: s.BootID}
		if s.SensorID == "" || s.BootID == "" || seen[key] {
			return fmt.Errorf("invalid or duplicate sensor source")
		}
		seen[key] = true
		if !validSequenceRange(s.ExpectedStart, s.ExpectedEnd) {
			return fmt.Errorf("invalid expected range for sensor %s", s.SensorID)
		}
		if !validSequenceRange(s.ObservedStart, s.ObservedEnd) {
			return fmt.Errorf("invalid observed range for sensor %s", s.SensorID)
		}
	}
	return nil
}
func (h SensorHealth) VerifiedEligible() error {
	if err := h.Validate(); err != nil {
		return err
	}
	if h.AppenderDrops != 0 || h.OpaqueConnections != 0 {
		return errors.New("health contains appender drops or opaque connections")
	}
	for _, s := range h.Sources {
		if !s.Started || !s.Drained || !s.Stopped || s.Gaps != 0 || s.Duplicates != 0 || s.Drops != 0 || s.ParseFailures != 0 || s.PlaintextFailures != 0 || s.StreamGaps != 0 || s.UnreconciledFlows != 0 {
			return fmt.Errorf("sensor %s is not verified-healthy", s.SensorID)
		}
		if s.ExpectedStart != s.ObservedStart || s.ExpectedEnd != s.ObservedEnd {
			return fmt.Errorf("sensor %s observed range does not match expected range", s.SensorID)
		}
	}
	return nil
}

func validSequenceRange(start, end uint64) bool {
	return start == 0 && end == 0 || start > 0 && end >= start
}

// Wire types are aliases, so execution code and the canonical trajectory log
// share exactly one JSON representation.
type NetworkPlaintext = events.NetworkPlaintext
type NetworkEndpoint = events.NetworkEndpoint
type ProtocolIdentity = events.ProtocolIdentity
type ArtifactSlice = events.ArtifactSlice
type CapturedBytes = events.CapturedBytes
type PlaintextCapture = events.PlaintextCapture

func ValidateNetworkPlaintext(p NetworkPlaintext) error {
	return events.ValidateNetworkPlaintext(p)
}
func InlinePayloadBytes(p CapturedBytes) ([]byte, error) {
	if p.Artifact != nil {
		return nil, errors.New("artifact payload requires resolver")
	}
	if p.Encoding == "utf8" {
		return []byte(p.Inline), nil
	}
	return base64.StdEncoding.DecodeString(p.Inline)
}
func SHA256Hex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type RunHandle interface{ RunID() string }
type StartedRun struct {
	RunID     string    `json:"runId"`
	StartedAt time.Time `json:"startedAt"`
}
type ExitStatus struct {
	Code     int       `json:"code"`
	Reason   string    `json:"reason"`
	ExitedAt time.Time `json:"exitedAt"`
}
type StopReason string
type RunSnapshot struct {
	ID        string    `json:"id"`
	Digest    string    `json:"digest"`
	CreatedAt time.Time `json:"createdAt"`
}
type BackendEvidence struct {
	ArtifactIDs   []string          `json:"artifactIds"`
	RawChainHeads map[string]string `json:"rawChainHeads"`
	Digest        string            `json:"digest"`
}

// ExecutionBackend is deliberately lifecycle-only: it emits raw evidence and never owns global event order.
type ExecutionBackend interface {
	Describe(context.Context) (CapabilityManifest, error)
	Prepare(context.Context, RunSpec, ObservationPlan) (RunHandle, error)
	Start(context.Context, RunHandle) (StartedRun, error)
	Wait(context.Context, RunHandle) (ExitStatus, error)
	Stop(context.Context, RunHandle, StopReason) error
	Snapshot(context.Context, RunHandle) (RunSnapshot, error)
	FinalizeEvidence(context.Context, RunHandle) (BackendEvidence, SensorHealth, error)
	Destroy(context.Context, RunHandle) error
}

func validObservation(s string) bool { return observationRank(s) >= 0 }
func observationRank(s string) int {
	switch s {
	case ObservationComplete:
		return 0
	case ObservationConditional:
		return 1
	case ObservationBestEffort:
		return 2
	case ObservationSampled:
		return 3
	case ObservationAggregated:
		return 4
	case ObservationUnsupported:
		return 5
	}
	return -1
}
func validEnforcement(s string) bool { return enforcementRank(s) >= 0 }
func enforcementRank(s string) int {
	switch s {
	case EnforcementSynchronous:
		return 0
	case EnforcementEventual:
		return 1
	case EnforcementAuditOnly:
		return 2
	case EnforcementUnsupported:
		return 3
	}
	return -1
}
func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// SortedCapabilities returns a stable ordering suitable for canonical manifests.
func (m CapabilityManifest) SortedCapabilities() []Capability {
	out := append([]Capability(nil), m.Capabilities...)
	sort.Slice(out, func(i, j int) bool { return out[i].EventFamily < out[j].EventFamily })
	return out
}
