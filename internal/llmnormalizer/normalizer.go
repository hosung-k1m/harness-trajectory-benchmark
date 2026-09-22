// Package llmnormalizer converts captured provider-native exchanges into the
// repository's pinned OpenAI Chat Completions projection. It never estimates
// usage and does not replace the provider-native plaintext evidence.
package llmnormalizer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/openaivalidator"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

type Kind string

const (
	KindRequest  Kind = "request"
	KindResponse Kind = "response"
	KindChunk    Kind = "chunk"

	ProviderOpenAICompatible = "openai-compatible"
	ProviderAnthropic        = "anthropic"
)

type Input struct {
	Kind            Kind
	Provider        string
	ProviderModel   string
	Endpoint        string
	RequestID       string
	ModelExchangeID string
	NativeBody      json.RawMessage
}

type Projection struct {
	Exchange events.OpenAICompatibleExchange
	Usage    *events.ModelUsage
}

// Normalize fails closed for unsupported providers or invalid projections.
func Normalize(input Input) (Projection, error) {
	if input.ProviderModel == "" || input.Endpoint == "" || input.ModelExchangeID == "" {
		return Projection{}, errors.New("provider model, endpoint, and model exchange ID are required")
	}
	if input.Kind != KindRequest && input.Kind != KindResponse && input.Kind != KindChunk {
		return Projection{}, fmt.Errorf("unsupported exchange kind %q", input.Kind)
	}
	if !json.Valid(input.NativeBody) {
		return Projection{}, errors.New("native body is not valid JSON")
	}

	var body json.RawMessage
	var usage *events.ModelUsage
	var err error
	switch input.Provider {
	case ProviderOpenAICompatible:
		body = append(json.RawMessage(nil), input.NativeBody...)
		if input.Kind == KindResponse {
			usage, err = openAIUsage(input.NativeBody)
		}
	case ProviderAnthropic:
		body, usage, err = normalizeAnthropic(input.Kind, input.NativeBody)
	default:
		return Projection{}, fmt.Errorf("unsupported provider %q", input.Provider)
	}
	if err != nil {
		return Projection{}, err
	}
	if err := openaivalidator.Validate(string(input.Kind), body); err != nil {
		return Projection{}, fmt.Errorf("normalized %s: %w", input.Kind, err)
	}
	return Projection{
		Exchange: events.OpenAICompatibleExchange{
			Schema: "openai.chat-completions.v1", Provider: input.Provider, ProviderModel: input.ProviderModel,
			Endpoint: input.Endpoint, RequestID: input.RequestID, ModelExchangeID: input.ModelExchangeID, Body: body,
		},
		Usage: usage,
	}, nil
}

type providerUsage struct {
	PromptTokens             *uint64 `json:"prompt_tokens"`
	CompletionTokens         *uint64 `json:"completion_tokens"`
	TotalTokens              *uint64 `json:"total_tokens"`
	InputTokens              *uint64 `json:"input_tokens"`
	OutputTokens             *uint64 `json:"output_tokens"`
	CacheReadInputTokens     *uint64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens *uint64 `json:"cache_creation_input_tokens"`
	PromptDetails            struct {
		CachedTokens *uint64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	CompletionDetails struct {
		ReasoningTokens *uint64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
}

func openAIUsage(body json.RawMessage) (*events.ModelUsage, error) {
	var response struct {
		Usage *providerUsage `json:"usage"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	if response.Usage == nil {
		return nil, nil
	}
	u := response.Usage
	return usageProjection(u.PromptTokens, u.CompletionTokens, u.PromptDetails.CachedTokens, nil, u.CompletionDetails.ReasoningTokens, u.TotalTokens, false), nil
}

func usageProjection(input, output, cacheRead, cacheWrite, reasoning, total *uint64, totalDerived bool) *events.ModelUsage {
	quality := func(v *uint64) string {
		if v == nil {
			return "unavailable"
		}
		return "provider_reported"
	}
	totalQuality := quality(total)
	if total != nil && totalDerived {
		totalQuality = "derived_from_provider_reported"
	}
	return &events.ModelUsage{
		InputTokens: input, OutputTokens: output, CacheReadTokens: cacheRead, CacheWriteTokens: cacheWrite, ReasoningTokens: reasoning, TotalTokens: total,
		Quality: events.UsageQuality{
			InputTokens: quality(input), OutputTokens: quality(output), CacheReadTokens: quality(cacheRead),
			CacheWriteTokens: quality(cacheWrite), ReasoningTokens: quality(reasoning), TotalTokens: totalQuality,
		},
	}
}

type anthropicRequest struct {
	Model    string          `json:"model"`
	System   json.RawMessage `json:"system"`
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	Tools []struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"input_schema"`
	} `json:"tools"`
	Temperature *float64        `json:"temperature"`
	Stop        json.RawMessage `json:"stop_sequences"`
	Stream      *bool           `json:"stream"`
}

func normalizeAnthropic(kind Kind, body json.RawMessage) (json.RawMessage, *events.ModelUsage, error) {
	switch kind {
	case KindRequest:
		return normalizeAnthropicRequest(body)
	case KindResponse:
		return normalizeAnthropicResponse(body)
	case KindChunk:
		return nil, nil, errors.New("Anthropic streaming chunks require stateful event assembly and are not supported")
	default:
		return nil, nil, fmt.Errorf("unsupported Anthropic exchange kind %q", kind)
	}
}

func normalizeAnthropicRequest(body json.RawMessage) (json.RawMessage, *events.ModelUsage, error) {
	var native anthropicRequest
	if err := json.Unmarshal(body, &native); err != nil {
		return nil, nil, err
	}
	messages := make([]map[string]any, 0, len(native.Messages)+1)
	if len(native.System) != 0 && string(native.System) != "null" {
		messages = append(messages, map[string]any{"role": "system", "content": native.System})
	}
	for _, message := range native.Messages {
		messages = append(messages, map[string]any{"role": message.Role, "content": message.Content})
	}
	tools := make([]map[string]any, 0, len(native.Tools))
	for _, tool := range native.Tools {
		tools = append(tools, map[string]any{"type": "function", "function": map[string]any{"name": tool.Name, "description": tool.Description, "parameters": tool.InputSchema}})
	}
	projection := map[string]any{"model": native.Model, "messages": messages}
	if len(tools) != 0 {
		projection["tools"] = tools
	}
	if native.Temperature != nil {
		projection["temperature"] = *native.Temperature
	}
	if len(native.Stop) != 0 && string(native.Stop) != "null" {
		projection["stop"] = native.Stop
	}
	if native.Stream != nil {
		projection["stream"] = *native.Stream
	}
	encoded, err := json.Marshal(projection)
	return encoded, nil, err
}

type anthropicResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Content []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`
	StopReason string        `json:"stop_reason"`
	Usage      providerUsage `json:"usage"`
}

func normalizeAnthropicResponse(body json.RawMessage) (json.RawMessage, *events.ModelUsage, error) {
	var native anthropicResponse
	if err := json.Unmarshal(body, &native); err != nil {
		return nil, nil, err
	}
	var textParts []string
	var calls []map[string]any
	for _, block := range native.Content {
		switch block.Type {
		case "text":
			textParts = append(textParts, block.Text)
		case "tool_use":
			if !json.Valid(block.Input) {
				return nil, nil, errors.New("Anthropic tool input is not valid JSON")
			}
			calls = append(calls, map[string]any{"id": block.ID, "type": "function", "function": map[string]any{"name": block.Name, "arguments": string(block.Input)}})
		default:
			return nil, nil, fmt.Errorf("unsupported Anthropic content block %q", block.Type)
		}
	}
	message := map[string]any{"role": "assistant"}
	if len(textParts) != 0 {
		message["content"] = strings.Join(textParts, "")
	}
	if len(calls) != 0 {
		message["tool_calls"] = calls
	}
	finish, err := anthropicFinishReason(native.StopReason)
	if err != nil {
		return nil, nil, err
	}
	projection := map[string]any{
		"id": native.ID, "object": "chat.completion", "model": native.Model,
		"choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": finish}},
	}
	usage := native.Usage
	if usage.InputTokens != nil || usage.OutputTokens != nil {
		if usage.InputTokens == nil || usage.OutputTokens == nil {
			return nil, nil, errors.New("Anthropic usage must report both input and output tokens")
		}
		total := sumIfPresent(usage.InputTokens, usage.OutputTokens)
		if total == nil {
			return nil, nil, errors.New("Anthropic usage token total overflow")
		}
		projection["usage"] = map[string]any{"prompt_tokens": *usage.InputTokens, "completion_tokens": *usage.OutputTokens, "total_tokens": *total}
		encoded, marshalErr := json.Marshal(projection)
		return encoded, usageProjection(usage.InputTokens, usage.OutputTokens, usage.CacheReadInputTokens, usage.CacheCreationInputTokens, nil, total, true), marshalErr
	}
	encoded, marshalErr := json.Marshal(projection)
	return encoded, nil, marshalErr
}

func anthropicFinishReason(reason string) (string, error) {
	switch reason {
	case "end_turn", "stop_sequence":
		return "stop", nil
	case "max_tokens":
		return "length", nil
	case "tool_use":
		return "tool_calls", nil
	default:
		return "", fmt.Errorf("unsupported Anthropic stop reason %q", reason)
	}
}

func sumIfPresent(a, b *uint64) *uint64 {
	if a == nil || b == nil {
		return nil
	}
	total := *a + *b
	if total < *a {
		return nil
	}
	return &total
}
