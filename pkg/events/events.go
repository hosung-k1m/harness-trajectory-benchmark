// Package events defines the version 1 append-only trajectory contract.
package events

import (
	"encoding/json"
	"fmt"
	"time"
)

const SchemaVersion = "tracked-events.v1"

// TrackedEvent is the single normalized, ordered run log envelope.
type TrackedEvent struct {
	Seq             uint64          `json:"seq"`
	Time            int64           `json:"time"`
	Type            string          `json:"type"`
	Data            json.RawMessage `json:"data"`
	Ignorable       bool            `json:"ignorable,omitempty"`
	SourceEventSeqs []uint64        `json:"sourceEventSeqs,omitempty"`
	SurfaceOp       json.RawMessage `json:"surfaceOp,omitempty"`
}

// AppendSurfaceOp preserves the historical JSON string union representation.
func AppendSurfaceOp() json.RawMessage { return json.RawMessage(`"append"`) }

// ReplaceSurfaceOp is the object arm of the historical surface-op union.
type ReplaceSurfaceOp struct {
	Op    string `json:"op"`
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

func NewReplaceSurfaceOp(start, end uint64) (json.RawMessage, error) {
	if start == 0 || end == 0 || start > end {
		return nil, fmt.Errorf("replace range must be non-empty and ordered")
	}
	b, err := json.Marshal(ReplaceSurfaceOp{Op: "replace", Start: start, End: end})
	return b, err
}

func ValidateSurfaceOp(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var appendOp string
	if err := json.Unmarshal(raw, &appendOp); err == nil {
		if appendOp == "append" {
			return nil
		}
		return fmt.Errorf("surfaceOp string must be append")
	}
	var replace ReplaceSurfaceOp
	if err := decodeStrict(raw, &replace); err != nil {
		return fmt.Errorf("invalid surfaceOp: %w", err)
	}
	if replace.Op != "replace" || replace.Start == 0 || replace.End == 0 || replace.Start > replace.End {
		return fmt.Errorf("invalid replace surfaceOp")
	}
	return nil
}

// ContentBlock intentionally retains extensible block-specific fields while
// preserving the discriminated content shape used by the harness.
type ContentBlock struct {
	Type       string          `json:"type"`
	Text       string          `json:"text,omitempty"`
	ID         string          `json:"id,omitempty"`
	Name       string          `json:"name,omitempty"`
	Arguments  string          `json:"arguments,omitempty"`
	ToolCallID string          `json:"toolCallId,omitempty"`
	IsError    *bool           `json:"isError,omitempty"`
	Attachment json.RawMessage `json:"attachment,omitempty"`
	Content    json.RawMessage `json:"content,omitempty"`
}
type MessageSource struct {
	Kind        string          `json:"kind"`
	Plugin      string          `json:"plugin,omitempty"`
	Form        string          `json:"form,omitempty"`
	CallID      string          `json:"callId,omitempty"`
	Provider    string          `json:"provider,omitempty"`
	Model       string          `json:"model,omitempty"`
	ReplayState json.RawMessage `json:"replayState,omitempty"`
	Sections    json.RawMessage `json:"sections,omitempty"`
	Summary     string          `json:"summary,omitempty"`
}
type Message struct {
	ID      string         `json:"id"`
	Role    string         `json:"role"`
	Content []ContentBlock `json:"content"`
	Source  MessageSource  `json:"source"`
}
type TokenUsage struct {
	InputTokens      *uint64 `json:"inputTokens,omitempty"`
	CacheReadTokens  *uint64 `json:"cacheReadTokens,omitempty"`
	CacheWriteTokens *uint64 `json:"cacheWriteTokens,omitempty"`
	OutputTokens     *uint64 `json:"outputTokens,omitempty"`
	ReasoningTokens  *uint64 `json:"reasoningTokens,omitempty"`
	TotalTokens      *uint64 `json:"totalTokens,omitempty"`
}

// Typed payloads for every core event in trackedEvents.md.
type TurnStartData struct {
	Turn uint64 `json:"turn"`
}
type UserMessageData struct {
	ID      string         `json:"id"`
	Role    string         `json:"role"`
	Content []ContentBlock `json:"content"`
	Source  MessageSource  `json:"source"`
}
type ToolSchema struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}
type LLMCallConfig struct {
	Temperature     *float64 `json:"temperature,omitempty"`
	MaxTokens       *uint64  `json:"maxTokens,omitempty"`
	ReasoningEffort string   `json:"reasoningEffort,omitempty"`
	Stop            []string `json:"stop,omitempty"`
}
type RequestHeader struct {
	System          string        `json:"system"`
	Tools           []ToolSchema  `json:"tools"`
	Config          LLMCallConfig `json:"config"`
	AdapterDefaults LLMCallConfig `json:"adapterDefaults,omitempty"`
}
type RequestHeaderData struct {
	Header       RequestHeader `json:"header"`
	Reason       string        `json:"reason"`
	StartsSeries bool          `json:"startsSeries,omitempty"`
}
type RequestContextData struct {
	Provider      string `json:"provider"`
	Model         string `json:"model"`
	ContextWindow uint64 `json:"contextWindow"`
}
type RetryFailure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type LLMRetryData struct {
	Retry      uint64       `json:"retry"`
	MaxRetries uint64       `json:"maxRetries"`
	DelayMS    uint64       `json:"delayMs"`
	Failure    RetryFailure `json:"failure"`
}
type StepData struct {
	Turn uint64 `json:"turn"`
	Step uint64 `json:"step"`
}
type AssistantChunkData struct {
	Turn  uint64          `json:"turn"`
	Step  uint64          `json:"step"`
	Chunk json.RawMessage `json:"chunk"`
}
type AssistantMessageData struct {
	Turn        uint64      `json:"turn"`
	Step        uint64      `json:"step"`
	Message     Message     `json:"message"`
	Usage       *TokenUsage `json:"usage,omitempty"`
	Interrupted bool        `json:"interrupted,omitempty"`
}
type ToolCallData struct {
	Turn      uint64 `json:"turn"`
	Step      uint64 `json:"step"`
	CallID    string `json:"callId"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}
type ToolResultData struct {
	Turn    uint64          `json:"turn"`
	Step    uint64          `json:"step"`
	Message Message         `json:"message"`
	Error   json.RawMessage `json:"error,omitempty"`
	Meta    json.RawMessage `json:"meta,omitempty"`
}
type TurnEndData struct {
	Turn   uint64          `json:"turn"`
	Reason json.RawMessage `json:"reason"`
}
type CompactionData struct {
	StartSeq uint64         `json:"startSeq"`
	EndSeq   uint64         `json:"endSeq"`
	Summary  []ContentBlock `json:"summary,omitempty"`
}
type SessionEndSeedData struct{}

// ObservationData is mandatory for facts derived from a sensor, normalizer, or verifier.
type ObservationData[T any] struct {
	RunID       string       `json:"runId"`
	Source      Source       `json:"source"`
	Observation Observation  `json:"observation"`
	Subject     *Subject     `json:"subject,omitempty"`
	Outcome     *Outcome     `json:"outcome,omitempty"`
	Correlation *Correlation `json:"correlation,omitempty"`
	Evidence    Evidence     `json:"evidence"`
	Details     T            `json:"details"`
}
type Source struct {
	SensorID       string `json:"sensorId"`
	SensorType     string `json:"sensorType"`
	Backend        string `json:"backend"`
	BackendVersion string `json:"backendVersion"`
	BootID         string `json:"bootId"`
	SourceSeq      uint64 `json:"sourceSeq"`
	TrustDomain    string `json:"trustDomain"`
}
type Observation struct {
	MonotonicNS  *uint64    `json:"monotonicNs"`
	WallTime     *time.Time `json:"wallTime"`
	ClockID      string     `json:"clockId"`
	ReceivedTime time.Time  `json:"receivedTime"`
}
type Subject struct {
	ProcessID        string `json:"processId,omitempty"`
	ParentProcessID  string `json:"parentProcessId,omitempty"`
	Executable       string `json:"executable,omitempty"`
	ExecutableSHA256 string `json:"executableSha256,omitempty"`
	ActorID          string `json:"actorId,omitempty"`
}
type Outcome struct {
	Result  string `json:"result"`
	Errno   *int   `json:"errno,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
type Correlation struct {
	FlowID          string `json:"flowId,omitempty"`
	TLSSessionID    string `json:"tlsSessionId,omitempty"`
	HTTPRequestID   string `json:"httpRequestId,omitempty"`
	ModelExchangeID string `json:"modelExchangeId,omitempty"`
	MCPSessionID    string `json:"mcpSessionId,omitempty"`
	ToolCallID      string `json:"toolCallId,omitempty"`
	TraceID         string `json:"traceId,omitempty"`
}
type Evidence struct {
	RawRecordSHA256   string `json:"rawRecordSha256"`
	RawStreamID       string `json:"rawStreamId"`
	RawSourceSeqStart uint64 `json:"rawSourceSeqStart"`
	RawSourceSeqEnd   uint64 `json:"rawSourceSeqEnd"`
	NormalizerSHA256  string `json:"normalizerSha256"`
	NormalizerVersion string `json:"normalizerVersion"`
	ObservationLayer  string `json:"observationLayer"`
	ObservationMethod string `json:"observationMethod"`
}

type NetworkPlaintext struct {
	Boundary     string           `json:"boundary"`
	CapturePoint string           `json:"capturePoint"`
	ConnectionID string           `json:"connectionId"`
	StreamID     string           `json:"streamId"`
	Transport    string           `json:"transport"`
	Direction    string           `json:"direction"`
	Sequence     uint64           `json:"sequence"`
	Offset       *uint64          `json:"offset,omitempty"`
	EndOfStream  bool             `json:"endOfStream,omitempty"`
	Source       NetworkEndpoint  `json:"source"`
	Destination  NetworkEndpoint  `json:"destination"`
	Protocol     ProtocolIdentity `json:"protocol"`
	Payload      CapturedBytes    `json:"payload"`
	Capture      PlaintextCapture `json:"capture"`
}
type NetworkEndpoint struct {
	IP       string `json:"ip,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}
type ProtocolIdentity struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	MediaType string `json:"mediaType,omitempty"`
}
type CapturedBytes struct {
	Encoding string         `json:"encoding"`
	Inline   string         `json:"inline,omitempty"`
	Artifact *ArtifactSlice `json:"artifact,omitempty"`
	Length   uint64         `json:"length"`
	SHA256   string         `json:"sha256"`
}
type ArtifactSlice struct {
	ArtifactID string `json:"artifactId"`
	Offset     uint64 `json:"offset"`
	Length     uint64 `json:"length"`
}
type PlaintextCapture struct {
	Method                   string `json:"method"`
	Backend                  string `json:"backend"`
	OriginalSecurityProtocol string `json:"originalSecurityProtocol,omitempty"`
	KeyMaterialDigest        string `json:"keyMaterialDigest,omitempty"`
	Verified                 bool   `json:"verified"`
}
type OpenAICompatibleExchange struct {
	Schema          string          `json:"schema"`
	Provider        string          `json:"provider"`
	ProviderModel   string          `json:"providerModel"`
	Endpoint        string          `json:"endpoint"`
	RequestID       string          `json:"requestId,omitempty"`
	ModelExchangeID string          `json:"modelExchangeId"`
	Body            json.RawMessage `json:"body"`
	Extensions      json.RawMessage `json:"extensions,omitempty"`
}
type UsageQuality struct {
	InputTokens      string `json:"inputTokens"`
	OutputTokens     string `json:"outputTokens"`
	CacheReadTokens  string `json:"cacheReadTokens"`
	CacheWriteTokens string `json:"cacheWriteTokens"`
	ReasoningTokens  string `json:"reasoningTokens"`
	TotalTokens      string `json:"totalTokens"`
}
type ModelUsage struct {
	InputTokens      *uint64      `json:"inputTokens"`
	OutputTokens     *uint64      `json:"outputTokens"`
	CacheReadTokens  *uint64      `json:"cacheReadTokens"`
	CacheWriteTokens *uint64      `json:"cacheWriteTokens"`
	ReasoningTokens  *uint64      `json:"reasoningTokens"`
	TotalTokens      *uint64      `json:"totalTokens"`
	Quality          UsageQuality `json:"quality"`
}

// CorrectionData records a new fact about an earlier immutable event. It does
// not alter either the prior envelope or its payload.
type CorrectionData struct {
	SupersedesSeq uint64          `json:"supersedesSeq"`
	Reason        string          `json:"reason"`
	Corrected     json.RawMessage `json:"corrected"`
}
