// Package normalizer converts compatibility-backend raw evidence into the
// canonical, unsequenced TrackedEvent candidates owned by the trusted appender.
package normalizer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

const (
	// CompatVersion identifies the stable mapping implemented in this package.
	CompatVersion = "compat-raw-v1"
	compatBackend = "compat-local-process"
	compatVersion = "phase1"
)

// CompatDigest is a stable identity for this mapping version. It is deliberately
// independent of execution time and input ordering.
var CompatDigest = digest([]byte("harness-trajectory-benchmark/normalizer/compat-raw-v1"))

// Result contains event candidates plus a complete, one-record-per-event
// coverage proof. Events intentionally have Seq and Time zero for Appender.
// Coverage is index-aligned 1:1 with Events, and each EventID is a provisional
// placeholder until bound by the trusted appender's caller.
type Result struct {
	Events   []events.TrackedEvent
	Coverage []evidence.NormalizedCoverage
	Version  string
	Digest   string
}

// BindCoverageEventIDs returns a copy of coverage whose EventID is the global
// sequence the trusted appender assigned to the event at the same index.
func BindCoverageEventIDs(coverage []evidence.NormalizedCoverage, seqs []uint64) ([]evidence.NormalizedCoverage, error) {
	if len(coverage) != len(seqs) {
		return nil, fmt.Errorf("coverage count %d does not match appended sequence count %d", len(coverage), len(seqs))
	}
	bound := make([]evidence.NormalizedCoverage, len(coverage))
	for i, c := range coverage {
		if seqs[i] == 0 {
			return nil, fmt.Errorf("coverage %d has no appended sequence", i)
		}
		c.EventID = strconv.FormatUint(seqs[i], 10)
		bound[i] = c
	}
	return bound, nil
}

// NormalizeCompat validates and maps a contiguous single-source compat raw
// stream. Unknown records are rejected: this normalizer never guesses facts.
func NormalizeCompat(records []evidence.RawRecord) (Result, error) {
	if err := validateRecords(records); err != nil {
		return Result{}, err
	}
	result := Result{Events: make([]events.TrackedEvent, 0, len(records)), Coverage: make([]evidence.NormalizedCoverage, 0, len(records)), Version: CompatVersion, Digest: CompatDigest}
	for _, record := range records {
		typ, err := eventType(record.RecordType)
		if err != nil {
			return Result{}, err
		}
		data, err := json.Marshal(events.ObservationData[map[string]string]{
			RunID:       record.RunID,
			Source:      events.Source{SensorID: record.SensorID, SensorType: "compat-local-process", Backend: compatBackend, BackendVersion: compatVersion, BootID: record.BootID, SourceSeq: record.SourceSeq, TrustDomain: "host-process"},
			Observation: observation(record),
			Evidence:    events.Evidence{RawRecordSHA256: record.RecordSHA256, RawStreamID: record.SensorID + "/" + record.BootID, RawSourceSeqStart: record.SourceSeq, RawSourceSeqEnd: record.SourceSeq, NormalizerSHA256: CompatDigest, NormalizerVersion: CompatVersion, ObservationLayer: "compatibility-backend", ObservationMethod: "local-process-stream"},
			Details:     map[string]string{"recordType": record.RecordType, "encoding": record.Encoding, "payloadBase64": base64.StdEncoding.EncodeToString(record.Payload), "payloadSHA256": digest(record.Payload)},
		})
		if err != nil {
			return Result{}, err
		}
		candidate := events.TrackedEvent{Type: typ, Data: data, Ignorable: true}
		// Validate after provisioning the only two fields Appender owns. This
		// catches a schema regression without assigning caller authority.
		probe := candidate
		probe.Seq, probe.Time = 1, 0
		if err := events.ValidateEvent(probe); err != nil {
			return Result{}, fmt.Errorf("normalize raw sequence %d: %w", record.SourceSeq, err)
		}
		result.Events = append(result.Events, candidate)
		result.Coverage = append(result.Coverage, evidence.NormalizedCoverage{Raw: evidence.RawRange{SensorID: record.SensorID, BootID: record.BootID, Start: record.SourceSeq, End: record.SourceSeq}, EventID: record.RecordSHA256})
	}
	if err := evidence.ValidateRawCoverage(records, result.Coverage); err != nil {
		return Result{}, err
	}
	return result, nil
}

func eventType(raw string) (string, error) {
	switch raw {
	case "process/start":
		return "process/exec", nil
	case "process/exit":
		return "process/exit", nil
	case "workload/stdout", "workload/stderr":
		return "stdio/chunk", nil
	case "runtime/snapshot":
		return "backend/snapshot", nil
	case "sensor/health":
		return "sensor/stop", nil
	default:
		return "", fmt.Errorf("unsupported compat raw record type %q", raw)
	}
}

func observation(record evidence.RawRecord) events.Observation {
	received := time.Unix(0, 0).UTC()
	if record.ObservedWallTime != nil {
		received = record.ObservedWallTime.UTC()
	}
	return events.Observation{MonotonicNS: record.ObservedMonotonicNS, WallTime: record.ObservedWallTime, ClockID: "compat-host-clock", ReceivedTime: received}
}

func validateRecords(records []evidence.RawRecord) error {
	if len(records) == 0 {
		return nil
	}
	first := records[0]
	if err := first.Validate(); err != nil {
		return fmt.Errorf("raw record 0: %w", err)
	}
	if first.SourceSeq != 1 || first.PreviousRecordSHA256 != "" {
		return errors.New("compat raw stream must begin at source sequence 1 without a previous record hash")
	}
	for i, record := range records[1:] {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("raw record %d: %w", i+1, err)
		}
		previous := records[i]
		if record.RunID != first.RunID || record.SensorID != first.SensorID || record.BootID != first.BootID || record.SourceSeq != previous.SourceSeq+1 || record.PreviousRecordSHA256 != previous.RecordSHA256 {
			return fmt.Errorf("raw record %d breaks compat source lineage", i+1)
		}
	}
	return nil
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
