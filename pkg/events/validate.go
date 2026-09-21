package events

import (
	"encoding/json"
	"fmt"
	"strings"
)

var coreEventTypes = map[string]struct{}{
	"turn/start": {}, "user/message": {}, "request/header": {}, "request/context": {}, "llm/retry": {}, "step/start": {}, "assistant/chunk": {}, "assistant/message": {}, "tool/call": {}, "tool/result": {}, "step/end": {}, "turn/end": {}, "compaction/start": {}, "compaction/summary": {}, "compaction/end": {}, "session/end-seed": {},
}

// IsObservationType identifies types whose data is required to carry the
// raw-evidence reference that makes an observed fact auditable.
func IsObservationType(t string) bool {
	for _, prefix := range []string{"sensor/", "process/", "resource/", "policy/", "system/", "stdio/", "file/", "ipc/", "dns/", "network/", "tls/", "http/", "model/", "mcp/", "verifier/"} {
		if strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}

// IsKnownType covers the v1 core and architecture event vocabulary. Unknown
// types are valid only when ignorable, so older replayers can safely skip them.
func IsKnownType(t string) bool {
	if _, ok := coreEventTypes[t]; ok {
		return true
	}
	_, ok := extensionEventTypes[t]
	return ok
}

func required(s, field string) error {
	if s == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

func validateCore(t string, raw json.RawMessage) error {
	_, ok := coreEventTypes[t]
	if !ok {
		return nil
	}
	if !isJSONObject(raw) {
		return fmt.Errorf("data must be a JSON object")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	has := func(k string) bool { _, ok := m[k]; return ok }
	switch t {
	case "turn/start":
		var d TurnStartData
		if err := decodeStrict(raw, &d); err != nil {
			return err
		}
		if d.Turn == 0 {
			return fmt.Errorf("turn must be positive")
		}
	case "user/message":
		var d UserMessageData
		if err := decodeStrict(raw, &d); err != nil {
			return err
		}
		if err := required(d.ID, "id"); err != nil {
			return err
		}
		if d.Role != "user" {
			return fmt.Errorf("user/message role must be user")
		}
		if err := required(d.Source.Kind, "source.kind"); err != nil {
			return err
		}
		if !has("content") {
			return fmt.Errorf("content is required")
		}
		if err := validateContent(d.Content, "text", "image"); err != nil {
			return err
		}
	case "request/header":
		var d RequestHeaderData
		if err := decodeStrict(raw, &d); err != nil {
			return err
		}
		if !has("header") || d.Reason == "" {
			return fmt.Errorf("header and reason are required")
		}
		if !oneOf(d.Reason, "initial", "resume", "change", "series") {
			return fmt.Errorf("invalid request header reason %q", d.Reason)
		}
		for _, tool := range d.Header.Tools {
			if tool.Name == "" || tool.Description == "" || !isJSONObject(tool.Parameters) {
				return fmt.Errorf("invalid request tool schema")
			}
		}
	case "request/context":
		var d RequestContextData
		if err := decodeStrict(raw, &d); err != nil {
			return err
		}
		if d.Provider == "" || d.Model == "" || d.ContextWindow == 0 {
			return fmt.Errorf("provider, model, and positive contextWindow are required")
		}
	case "llm/retry":
		var d LLMRetryData
		if err := decodeStrict(raw, &d); err != nil {
			return err
		}
		if d.Retry == 0 || d.MaxRetries == 0 || d.Failure.Code == "" {
			return fmt.Errorf("retry, maxRetries, and failure.code are required")
		}
	case "step/start", "step/end":
		var d StepData
		if err := decodeStrict(raw, &d); err != nil {
			return err
		}
		if d.Turn == 0 || d.Step == 0 {
			return fmt.Errorf("turn and step must be positive")
		}
	case "assistant/chunk":
		var d AssistantChunkData
		if err := decodeStrict(raw, &d); err != nil {
			return err
		}
		if d.Turn == 0 || d.Step == 0 || !isJSONObject(d.Chunk) {
			return fmt.Errorf("turn, step, and chunk are required")
		}
	case "assistant/message":
		var d AssistantMessageData
		if err := decodeStrict(raw, &d); err != nil {
			return err
		}
		if d.Turn == 0 || d.Step == 0 || d.Message.ID == "" || d.Message.Role != "assistant" {
			return fmt.Errorf("turn, step, and assistant message are required")
		}
		if d.Message.Source.Kind != "model" || d.Message.Source.Provider == "" || d.Message.Source.Model == "" {
			return fmt.Errorf("assistant message requires model source")
		}
		if err := validateContent(d.Message.Content, "text", "reasoning", "tool-call"); err != nil {
			return err
		}
	case "tool/call":
		var d ToolCallData
		if err := decodeStrict(raw, &d); err != nil {
			return err
		}
		if d.Turn == 0 || d.Step == 0 || d.CallID == "" || d.Name == "" {
			return fmt.Errorf("turn, step, callId, and name are required")
		}
		if !json.Valid([]byte(d.Arguments)) {
			return fmt.Errorf("tool arguments must be valid JSON")
		}
	case "tool/result":
		var d ToolResultData
		if err := decodeStrict(raw, &d); err != nil {
			return err
		}
		if d.Turn == 0 || d.Step == 0 || d.Message.ID == "" || d.Message.Role != "user" || d.Message.Source.Kind != "tool" || d.Message.Source.CallID == "" {
			return fmt.Errorf("tool result requires a user/tool message with callId")
		}
		if len(d.Message.Content) != 1 {
			return fmt.Errorf("tool result requires exactly one content block")
		}
		if err := validateContent(d.Message.Content, "tool-result"); err != nil {
			return err
		}
		if d.Message.Content[0].ToolCallID != d.Message.Source.CallID {
			return fmt.Errorf("tool result call identifiers do not match")
		}
	case "turn/end":
		var d TurnEndData
		if err := decodeStrict(raw, &d); err != nil {
			return err
		}
		if d.Turn == 0 || !isJSONObject(d.Reason) {
			return fmt.Errorf("turn and reason are required")
		}
		var reason struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(d.Reason, &reason); err != nil || !oneOf(reason.Kind, "completed", "aborted", "error", "max-tokens", "interrupted") {
			return fmt.Errorf("invalid turn end reason")
		}
	case "compaction/start", "compaction/summary", "compaction/end":
		var d CompactionData
		if err := decodeStrict(raw, &d); err != nil {
			return err
		}
		if d.StartSeq == 0 || d.EndSeq == 0 || d.StartSeq > d.EndSeq {
			return fmt.Errorf("compaction range must be non-empty and ordered")
		}
	case "session/end-seed":
		if m == nil || len(m) != 0 {
			return fmt.Errorf("session/end-seed data must be empty object")
		}
	}
	return nil
}

func validateEvidence(raw json.RawMessage) error {
	var probe struct {
		RunID       string          `json:"runId"`
		Source      *Source         `json:"source"`
		Observation *Observation    `json:"observation"`
		Evidence    *Evidence       `json:"evidence"`
		Details     json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return err
	}
	if probe.RunID == "" || probe.Source == nil || probe.Observation == nil || !isJSONObject(probe.Details) {
		return fmt.Errorf("observation-backed event requires runId, source, observation, and details")
	}
	s := probe.Source
	if s.SensorID == "" || s.SensorType == "" || s.Backend == "" || s.BackendVersion == "" || s.BootID == "" || s.SourceSeq == 0 || s.TrustDomain == "" {
		return fmt.Errorf("incomplete source identity")
	}
	if probe.Observation.ClockID == "" || probe.Observation.ReceivedTime.IsZero() {
		return fmt.Errorf("incomplete observation timing")
	}
	if probe.Evidence == nil {
		return fmt.Errorf("observation-backed event requires data.evidence")
	}
	e := probe.Evidence
	if !isSHA256(e.RawRecordSHA256) || e.RawStreamID == "" || e.RawSourceSeqStart == 0 || e.RawSourceSeqEnd < e.RawSourceSeqStart || !isSHA256(e.NormalizerSHA256) || e.NormalizerVersion == "" || e.ObservationLayer == "" || e.ObservationMethod == "" {
		return fmt.Errorf("incomplete evidence reference")
	}
	return nil
}

// ValidateEvent validates the envelope and discriminator-specific payload.
// Sequence/lineage depend on log context and are checked by eventlog.Validator.
func ValidateEvent(e TrackedEvent) error {
	if e.Seq == 0 {
		return fmt.Errorf("seq must be positive")
	}
	if e.Time < 0 {
		return fmt.Errorf("time must be unix epoch milliseconds")
	}
	if e.Type == "" {
		return fmt.Errorf("type is required")
	}
	if !isJSONObject(e.Data) {
		return fmt.Errorf("data must be a JSON object")
	}
	if err := ValidateSurfaceOp(e.SurfaceOp); err != nil {
		return err
	}
	if !IsKnownType(e.Type) && !e.Ignorable {
		return fmt.Errorf("unknown event type %q must be ignorable", e.Type)
	}
	if _, extension := extensionEventTypes[e.Type]; extension && !e.Ignorable {
		return fmt.Errorf("extension event %q must be ignorable", e.Type)
	}
	if IsObservationType(e.Type) {
		if !e.Ignorable {
			return fmt.Errorf("observation event %q must be ignorable", e.Type)
		}
		if err := validateEvidence(e.Data); err != nil {
			return err
		}
	}
	if e.Type == "network/plaintext" {
		var d struct {
			Details NetworkPlaintext `json:"details"`
		}
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return err
		}
		if err := ValidateNetworkPlaintext(d.Details); err != nil {
			return err
		}
	}
	if e.Type == "model/request" || e.Type == "model/stream-chunk" || e.Type == "model/response" {
		var d struct {
			Details OpenAICompatibleExchange `json:"details"`
		}
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return err
		}
		x := d.Details
		if x.Schema != "openai.chat-completions.v1" || x.Provider == "" || x.ProviderModel == "" || x.Endpoint == "" || x.ModelExchangeID == "" || len(x.Body) == 0 || !json.Valid(x.Body) {
			return fmt.Errorf("invalid OpenAI-compatible model exchange")
		}
	}
	if e.Type == "model/usage" {
		var d struct {
			Details ModelUsage `json:"details"`
		}
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return err
		}
		q := d.Details.Quality
		if !validUsageQuality(q.InputTokens) || !validUsageQuality(q.OutputTokens) || !validUsageQuality(q.CacheReadTokens) || !validUsageQuality(q.CacheWriteTokens) || !validUsageQuality(q.ReasoningTokens) || !validUsageQuality(q.TotalTokens) {
			return fmt.Errorf("model/usage requires quality for every counter")
		}
	}
	return validateCore(e.Type, e.Data)
}
