package events

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSurfaceOpWireShapeAndValidation(t *testing.T) {
	if got := string(AppendSurfaceOp()); got != `"append"` {
		t.Fatalf("append wire shape = %s", got)
	}
	raw, err := NewReplaceSurfaceOp(2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); got != `{"op":"replace","start":2,"end":4}` {
		t.Fatalf("replace wire shape = %s", got)
	}
	if err := ValidateSurfaceOp(json.RawMessage(`{"op":"replace","start":4,"end":2}`)); err == nil {
		t.Fatal("accepted reverse range")
	}
	if err := ValidateSurfaceOp(json.RawMessage(`{"op":"replace","start":2,"end":4,"extra":true}`)); err == nil {
		t.Fatal("accepted unknown replace field")
	}
	if err := ValidateSurfaceOp(json.RawMessage(`null`)); err == nil {
		t.Fatal("accepted explicit null surface operation")
	}
}

func TestCorePayloadsRejectMalformedShapes(t *testing.T) {
	cases := []TrackedEvent{
		{Seq: 1, Type: "request/header", Data: json.RawMessage(`{"header":"wrong","reason":"initial"}`)},
		{Seq: 1, Type: "session/end-seed", Data: json.RawMessage(`null`)},
		{Seq: 1, Type: "turn/end", Data: json.RawMessage(`{"turn":1,"reason":"completed"}`)},
		{Seq: 1, Type: "user/message", Data: json.RawMessage(`{"id":"u","role":"user","content":[{"type":"reasoning","text":"no"}],"source":{"kind":"user"}}`)},
		{Seq: 1, Type: "assistant/message", Data: json.RawMessage(`{"turn":1,"step":1,"message":{"id":"a","role":"assistant","content":[{"type":"tool-result","toolCallId":"c","content":[],"isError":false}],"source":{"kind":"model","provider":"p","model":"m"}}}`)},
		{Seq: 1, Type: "tool/result", Data: json.RawMessage(`{"turn":1,"step":1,"message":{"id":"r","role":"user","content":[{"type":"tool-result","toolCallId":"different","content":[],"isError":false}],"source":{"kind":"tool","callId":"call"}}}`)},
		{Seq: 1, Type: "tool/result", Data: json.RawMessage(`{"turn":1,"step":1,"message":{"id":"r","role":"user","content":[{"type":"tool-result","toolCallId":"call","content":[]}],"source":{"kind":"tool","callId":"call"}}}`)},
	}
	for _, event := range cases {
		if err := ValidateEvent(event); err == nil {
			t.Errorf("accepted malformed %s", event.Type)
		}
	}
}

func TestExtensionEventsMustBeIgnorable(t *testing.T) {
	event := TrackedEvent{Seq: 1, Type: "run/start", Data: json.RawMessage(`{}`)}
	if err := ValidateEvent(event); err == nil {
		t.Fatal("accepted non-ignorable extension event")
	}
	event.Type = "vendor/custom"
	event.Ignorable = true
	if err := ValidateEvent(event); err != nil {
		t.Fatalf("rejected ignorable vendor extension: %v", err)
	}
}

func TestObservationEvidenceAndPlaintextAreFullyValidated(t *testing.T) {
	offset := uint64(0)
	payload := []byte("hello")
	digest := sha256.Sum256(payload)
	details := NetworkPlaintext{
		Boundary: "sandbox", CapturePoint: "tap", ConnectionID: "c", StreamID: "s",
		Transport: "tcp", Direction: "egress", Sequence: 1, Offset: &offset,
		Source: NetworkEndpoint{IP: "10.0.0.2", Port: 1234}, Destination: NetworkEndpoint{Hostname: "example.test", Port: 443},
		Protocol: ProtocolIdentity{Name: "raw"},
		Payload:  CapturedBytes{Encoding: "utf8", Inline: string(payload), Length: uint64(len(payload)), SHA256: fmtHash(digest)},
		Capture:  PlaintextCapture{Method: "native-plaintext", Backend: "test", Verified: true},
	}
	event := observedEvent("network/plaintext", details)
	if err := ValidateEvent(event); err != nil {
		t.Fatal(err)
	}

	invalid := details
	invalid.Transport = "bogus"
	if err := ValidateEvent(observedEvent("network/plaintext", invalid)); err == nil {
		t.Fatal("accepted unsupported transport")
	}
	invalid = details
	invalid.Sequence = 0
	if err := ValidateEvent(observedEvent("network/plaintext", invalid)); err == nil {
		t.Fatal("accepted zero stream sequence")
	}
	invalid = details
	invalid.Payload.SHA256 = "not-a-digest"
	if err := ValidateEvent(observedEvent("network/plaintext", invalid)); err == nil {
		t.Fatal("accepted invalid payload digest")
	}

	badEvidence := observedEvent("process/exec", map[string]string{"processId": "p"})
	var data map[string]json.RawMessage
	if err := json.Unmarshal(badEvidence.Data, &data); err != nil {
		t.Fatal(err)
	}
	var evidence Evidence
	if err := json.Unmarshal(data["evidence"], &evidence); err != nil {
		t.Fatal(err)
	}
	evidence.RawRecordSHA256 = "x"
	data["evidence"], _ = json.Marshal(evidence)
	badEvidence.Data, _ = json.Marshal(data)
	if err := ValidateEvent(badEvidence); err == nil {
		t.Fatal("accepted invalid evidence digest")
	}
}

func TestModelUsageQualityEnum(t *testing.T) {
	usage := ModelUsage{Quality: UsageQuality{
		InputTokens: "provider_reported", OutputTokens: "provider_reported",
		CacheReadTokens: "unavailable", CacheWriteTokens: "unavailable",
		ReasoningTokens: "unavailable", TotalTokens: "derived_from_provider_reported",
	}}
	event := observedEvent("model/usage", usage)
	if err := ValidateEvent(event); err != nil {
		t.Fatal(err)
	}
	usage.Quality.InputTokens = "invented"
	if err := ValidateEvent(observedEvent("model/usage", usage)); err == nil {
		t.Fatal("accepted unknown usage quality")
	}
}

func observedEvent[T any](eventType string, details T) TrackedEvent {
	now := time.Unix(1, 0).UTC()
	data, _ := json.Marshal(ObservationData[T]{
		RunID: "run", Source: Source{SensorID: "sensor", SensorType: "test", Backend: "test", BackendVersion: "1", BootID: "boot", SourceSeq: 1, TrustDomain: "host"},
		Observation: Observation{ClockID: "wall", ReceivedTime: now},
		Evidence:    Evidence{RawRecordSHA256: strings.Repeat("a", 64), RawStreamID: "sensor/boot", RawSourceSeqStart: 1, RawSourceSeqEnd: 1, NormalizerSHA256: strings.Repeat("b", 64), NormalizerVersion: "1", ObservationLayer: "test", ObservationMethod: "test"},
		Details:     details,
	})
	return TrackedEvent{Seq: 1, Time: 1, Type: eventType, Data: data, Ignorable: true}
}

func fmtHash(sum [32]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range sum {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return string(out)
}

func TestCoreAndObservationValidation(t *testing.T) {
	e := TrackedEvent{Seq: 1, Time: 0, Type: "tool/call", Data: json.RawMessage(`{"turn":1,"step":1,"callId":"c","name":"x","arguments":"{}"}`)}
	if err := ValidateEvent(e); err != nil {
		t.Fatal(err)
	}
	e = TrackedEvent{Seq: 1, Time: 0, Type: "process/exec", Ignorable: true, Data: json.RawMessage(`{"details":{}}`)}
	if err := ValidateEvent(e); err == nil || !strings.Contains(err.Error(), "observation") {
		t.Fatalf("wanted evidence failure, got %v", err)
	}
	e.Ignorable = false
	if err := ValidateEvent(e); err == nil || !strings.Contains(err.Error(), "ignorable") {
		t.Fatalf("wanted ignorable failure, got %v", err)
	}
}
