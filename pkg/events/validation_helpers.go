package events

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var extensionEventTypes = map[string]struct{}{
	"run/start": {}, "run/observation-plan": {}, "backend/prepared": {}, "backend/started": {}, "backend/stopped": {}, "backend/snapshot": {}, "run/finish": {},
	"sensor/start": {}, "sensor/heartbeat": {}, "sensor/stop": {}, "sensor/restart": {}, "sensor/gap": {}, "sensor/drop": {}, "sensor/saturation": {}, "sensor/parse-failure": {}, "sensor/clock-skew": {}, "sensor/bypass-attempt": {},
	"process/create": {}, "process/exec": {}, "process/exit": {}, "process/signal": {}, "process/credential-change": {}, "resource/sample": {}, "policy/decision": {}, "system/log": {}, "stdio/chunk": {},
	"file/open": {}, "file/read": {}, "file/write": {}, "file/close": {}, "file/rename": {}, "file/delete": {}, "file/metadata-change": {}, "file/executable-map": {}, "file/snapshot-diff": {},
	"ipc/pipe-create": {}, "ipc/read": {}, "ipc/write": {}, "ipc/unix-connect": {}, "ipc/unix-accept": {}, "ipc/shared-memory": {},
	"dns/query": {}, "dns/response": {}, "network/socket-create": {}, "network/bind": {}, "network/listen": {}, "network/connect": {}, "network/accept": {}, "network/flow-open": {}, "network/flow-update": {}, "network/flow-close": {}, "network/plaintext": {}, "network/plaintext-failure": {}, "network/packet-batch": {}, "network/route-decision": {}, "tls/session": {}, "http/request": {}, "http/response": {},
	"model/request": {}, "model/stream-chunk": {}, "model/response": {}, "model/usage": {}, "mcp/request": {}, "mcp/response": {}, "mcp/notification": {}, "mcp/tool-call": {}, "mcp/tool-result": {},
	"benchmark/start": {}, "benchmark/finish": {}, "verifier/start": {}, "verifier/result": {}, "artifact/created": {}, "evidence/checkpoint": {}, "evidence/sealed": {},
	"correction/event": {}, "event/correction": {},
}

func decodeStrict[T any](raw json.RawMessage, dst *T) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return errors.New("payload must contain one JSON value")
	}
	return nil
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && json.Valid(trimmed)
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validateContent(blocks []ContentBlock, allowed ...string) error {
	allowedTypes := make(map[string]struct{}, len(allowed))
	for _, blockType := range allowed {
		allowedTypes[blockType] = struct{}{}
	}
	for _, block := range blocks {
		if _, ok := allowedTypes[block.Type]; !ok {
			return fmt.Errorf("content block type %q is not allowed here", block.Type)
		}
		switch block.Type {
		case "text", "reasoning":
			if block.Text == "" {
				return fmt.Errorf("%s content requires text", block.Type)
			}
		case "image":
			if !isJSONObject(block.Attachment) {
				return errors.New("image content requires attachment")
			}
		case "tool-call":
			if block.ID == "" || block.Name == "" || !json.Valid([]byte(block.Arguments)) {
				return errors.New("invalid tool-call content")
			}
		case "tool-result":
			if block.ToolCallID == "" || block.IsError == nil || !isJSONArray(block.Content) {
				return errors.New("tool-result requires toolCallId, content, and isError")
			}
			var resultBlocks []ContentBlock
			if err := json.Unmarshal(block.Content, &resultBlocks); err != nil {
				return fmt.Errorf("tool-result content: %w", err)
			}
			if err := validateContent(resultBlocks, "text", "image"); err != nil {
				return fmt.Errorf("tool-result content: %w", err)
			}
		default:
			return fmt.Errorf("unknown content block type %q", block.Type)
		}
	}
	return nil
}

func isJSONArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '[' && json.Valid(trimmed)
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validUsageQuality(value string) bool {
	return oneOf(value, "provider_reported", "derived_from_provider_reported", "harness_reported", "client_estimated", "unavailable")
}

// ValidateNetworkPlaintext is the canonical semantic validator for the shared wire type.
func ValidateNetworkPlaintext(p NetworkPlaintext) error {
	if p.Boundary != "sandbox" || p.CapturePoint == "" || p.ConnectionID == "" || p.StreamID == "" || p.Sequence == 0 || !oneOf(p.Direction, "ingress", "egress") || p.Protocol.Name == "" || p.Capture.Method == "" || p.Capture.Backend == "" {
		return errors.New("invalid plaintext record identity")
	}
	if !oneOf(p.Transport, "tcp", "udp", "quic", "icmp", "raw-ip") {
		return fmt.Errorf("unsupported transport %q", p.Transport)
	}
	if oneOf(p.Transport, "tcp", "quic") && p.Offset == nil {
		return errors.New("stream transport requires offset")
	}
	if oneOf(p.Transport, "udp", "icmp", "raw-ip") && p.Offset != nil {
		return errors.New("datagram transport must omit offset")
	}
	if !oneOf(p.Payload.Encoding, "utf8", "base64") {
		return errors.New("payload encoding must be utf8 or base64")
	}
	if p.Payload.Artifact != nil && p.Payload.Inline != "" {
		return errors.New("payload cannot use inline and artifact representations")
	}
	if p.Payload.Artifact == nil && p.Payload.Inline == "" && p.Payload.Length != 0 {
		return errors.New("non-empty payload requires inline or artifact representation")
	}
	if p.Payload.Artifact != nil && (p.Payload.Artifact.ArtifactID == "" || p.Payload.Artifact.Length != p.Payload.Length) {
		return errors.New("invalid payload artifact slice")
	}
	if !isSHA256(p.Payload.SHA256) {
		return errors.New("payload sha256 must be lowercase sha256 hex")
	}
	if p.Capture.KeyMaterialDigest != "" && !isSHA256(p.Capture.KeyMaterialDigest) {
		return errors.New("key material digest must be lowercase sha256 hex")
	}
	if p.Payload.Artifact == nil {
		payload, err := inlinePayloadBytes(p.Payload)
		if err != nil {
			return err
		}
		if uint64(len(payload)) != p.Payload.Length {
			return errors.New("plaintext length mismatch")
		}
		digest := sha256.Sum256(payload)
		if hex.EncodeToString(digest[:]) != p.Payload.SHA256 {
			return errors.New("plaintext hash mismatch")
		}
	}
	return nil
}

func inlinePayloadBytes(p CapturedBytes) ([]byte, error) {
	if p.Encoding == "utf8" {
		return []byte(p.Inline), nil
	}
	return base64.StdEncoding.DecodeString(p.Inline)
}
