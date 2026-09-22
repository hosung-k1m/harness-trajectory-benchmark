package normalizer

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/llmnormalizer"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

const MockVersion = "mock-raw-v1"

var MockDigest = digest([]byte("harness-trajectory-benchmark/normalizer/mock-raw-v1"))

func NormalizeMock(records []evidence.RawRecord) (Result, error) {
	if err := validateMockRecords(records); err != nil {
		return Result{}, err
	}
	result := Result{Events: make([]events.TrackedEvent, 0, len(records)), Coverage: make([]evidence.NormalizedCoverage, 0, len(records)), Version: MockVersion, Digest: MockDigest}
	for _, record := range records {
		details, err := mockDetails(record)
		if err != nil {
			return Result{}, fmt.Errorf("normalize raw sequence %d: %w", record.SourceSeq, err)
		}
		data, err := json.Marshal(events.ObservationData[json.RawMessage]{
			RunID:       record.RunID,
			Source:      events.Source{SensorID: record.SensorID, SensorType: "mock", Backend: "mock-data", BackendVersion: "phase1", BootID: record.BootID, SourceSeq: record.SourceSeq, TrustDomain: "mock"},
			Observation: mockObservation(record),
			Evidence:    events.Evidence{RawRecordSHA256: record.RecordSHA256, RawStreamID: record.SensorID + "/" + record.BootID, RawSourceSeqStart: record.SourceSeq, RawSourceSeqEnd: record.SourceSeq, NormalizerSHA256: MockDigest, NormalizerVersion: MockVersion, ObservationLayer: "mock", ObservationMethod: "fixture-replay"},
			Details:     details,
		})
		if err != nil {
			return Result{}, err
		}
		candidate := events.TrackedEvent{Type: record.RecordType, Data: data, Ignorable: true}
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

func mockDetails(record evidence.RawRecord) (json.RawMessage, error) {
	switch record.RecordType {
	case "process/exec", "file/write", "dns/query", "network/flow", "network/plaintext", "sensor/drop", "network/plaintext-failure", "sensor/bypass-attempt":
		return json.RawMessage(record.Payload), nil
	case "model/request", "model/response", "model/stream-chunk", "model/usage":
		var input llmnormalizer.Input
		if err := json.Unmarshal(record.Payload, &input); err != nil {
			return nil, fmt.Errorf("decode provider input: %w", err)
		}
		kind := map[string]llmnormalizer.Kind{
			"model/request":      llmnormalizer.KindRequest,
			"model/stream-chunk": llmnormalizer.KindChunk,
			"model/response":     llmnormalizer.KindResponse,
			"model/usage":        llmnormalizer.KindResponse,
		}[record.RecordType]
		if input.Kind != kind {
			return nil, fmt.Errorf("provider input kind %q does not match record type %q", input.Kind, record.RecordType)
		}
		projection, err := llmnormalizer.Normalize(input)
		if err != nil {
			return nil, err
		}
		if record.RecordType == "model/usage" {
			if projection.Usage == nil {
				return nil, errors.New("model/usage record projected no provider usage")
			}
			return json.Marshal(*projection.Usage)
		}
		return json.Marshal(projection.Exchange)
	default:
		return nil, fmt.Errorf("unsupported mock raw record type %q", record.RecordType)
	}
}

func mockObservation(record evidence.RawRecord) events.Observation {
	received := time.Unix(0, 0).UTC()
	if record.ObservedWallTime != nil {
		received = record.ObservedWallTime.UTC()
	}
	return events.Observation{MonotonicNS: record.ObservedMonotonicNS, WallTime: record.ObservedWallTime, ClockID: "mock-fixture-clock", ReceivedTime: received}
}

func validateMockRecords(records []evidence.RawRecord) error {
	sources := map[evidence.RawSource][]evidence.RawRecord{}
	order := []evidence.RawSource{}
	runID := ""
	for i, record := range records {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("raw record %d: %w", i, err)
		}
		if runID == "" {
			runID = record.RunID
		} else if record.RunID != runID {
			return fmt.Errorf("raw record %d has mismatched run ID", i)
		}
		source := evidence.RawSource{SensorID: record.SensorID, BootID: record.BootID}
		if _, ok := sources[source]; !ok {
			order = append(order, source)
		}
		sources[source] = append(sources[source], record)
	}
	for _, source := range order {
		chain := sources[source]
		for i, record := range chain {
			previous := ""
			if i > 0 {
				previous = chain[i-1].RecordSHA256
			}
			if record.SourceSeq != uint64(i)+1 || record.PreviousRecordSHA256 != previous {
				return fmt.Errorf("raw record %q/%q sequence %d breaks source lineage", source.SensorID, source.BootID, record.SourceSeq)
			}
		}
	}
	return nil
}
