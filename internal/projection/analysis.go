// Package projection derives analysis views from the immutable event log.
// Views never modify source events and always retain the canonical sequence.
package projection

import (
	"encoding/json"
	"fmt"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/eventlog"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

// Analysis is a compact, deterministic summary suitable for contract tests and
// as a foundation for richer indexed views in later phases.
type Analysis struct {
	EventCount       uint64            `json:"eventCount"`
	TypeCounts       map[string]uint64 `json:"typeCounts"`
	PlaintextBytes   map[string]uint64 `json:"plaintextBytes"`
	ModelExchanges   map[string]uint64 `json:"modelExchanges"`
	SensorLossEvents uint64            `json:"sensorLossEvents"`
}

// Build validates the canonical log before deriving any view from it.
func Build(log []events.TrackedEvent) (Analysis, error) {
	if err := eventlog.Validate(log); err != nil {
		return Analysis{}, err
	}
	out := Analysis{
		EventCount:     uint64(len(log)),
		TypeCounts:     make(map[string]uint64),
		PlaintextBytes: make(map[string]uint64),
		ModelExchanges: make(map[string]uint64),
	}
	for _, event := range log {
		out.TypeCounts[event.Type]++
		switch event.Type {
		case "network/plaintext":
			var data struct {
				Details events.NetworkPlaintext `json:"details"`
			}
			if err := json.Unmarshal(event.Data, &data); err != nil {
				return Analysis{}, fmt.Errorf("event %d plaintext projection: %w", event.Seq, err)
			}
			out.PlaintextBytes[data.Details.Direction] += data.Details.Payload.Length
		case "model/request", "model/stream-chunk", "model/response":
			var data struct {
				Details events.OpenAICompatibleExchange `json:"details"`
			}
			if err := json.Unmarshal(event.Data, &data); err != nil {
				return Analysis{}, fmt.Errorf("event %d model projection: %w", event.Seq, err)
			}
			out.ModelExchanges[data.Details.ModelExchangeID]++
		case "sensor/gap", "sensor/drop", "sensor/saturation", "sensor/parse-failure":
			out.SensorLossEvents++
		}
	}
	return out, nil
}
