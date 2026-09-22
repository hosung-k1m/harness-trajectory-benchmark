package llmnormalizer

import (
	"encoding/json"
	"testing"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/openaivalidator"
)

func TestNormalizeOpenAICompatiblePreservesProviderUsage(t *testing.T) {
	native := json.RawMessage(`{"id":"call-1","object":"chat.completion","model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10,"prompt_tokens_details":{"cached_tokens":2},"completion_tokens_details":{"reasoning_tokens":1}}}`)
	projection, err := Normalize(Input{
		Kind: KindResponse, Provider: ProviderOpenAICompatible, ProviderModel: "gpt-test",
		Endpoint: "https://provider.example/v1/chat/completions", ModelExchangeID: "exchange-1", NativeBody: native,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(projection.Exchange.Body) != string(native) {
		t.Fatal("OpenAI-compatible body was rewritten")
	}
	if projection.Usage == nil || value(projection.Usage.InputTokens) != 7 || value(projection.Usage.CacheReadTokens) != 2 || value(projection.Usage.ReasoningTokens) != 1 {
		t.Fatalf("unexpected usage: %+v", projection.Usage)
	}
	if projection.Usage.CacheWriteTokens != nil || projection.Usage.Quality.CacheWriteTokens != "unavailable" {
		t.Fatal("missing cache-write usage was silently synthesized")
	}
}

func TestNormalizeOpenAIUsageMissingFieldsRemainUnavailable(t *testing.T) {
	projection, err := Normalize(Input{Kind: KindResponse, Provider: ProviderOpenAICompatible, ProviderModel: "m", Endpoint: "https://example.test", ModelExchangeID: "x", NativeBody: json.RawMessage(`{"id":"x","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if projection.Usage != nil {
		t.Fatalf("provider-missing usage was synthesized: %+v", projection.Usage)
	}
}

func TestNormalizeAnthropicRequestAndResponse(t *testing.T) {
	tests := []struct {
		name string
		in   Input
	}{
		{
			name: "request",
			in: Input{Kind: KindRequest, Provider: ProviderAnthropic, ProviderModel: "claude-test", Endpoint: "https://api.anthropic.com/v1/messages", ModelExchangeID: "x",
				NativeBody: json.RawMessage(`{"model":"claude-test","system":"be precise","messages":[{"role":"user","content":"hello"}],"tools":[{"name":"lookup","description":"find","input_schema":{"type":"object","properties":{"q":{"type":"string"}}}}],"max_tokens":100}`)},
		},
		{
			name: "response",
			in: Input{Kind: KindResponse, Provider: ProviderAnthropic, ProviderModel: "claude-test", Endpoint: "https://api.anthropic.com/v1/messages", ModelExchangeID: "x", RequestID: "req",
				NativeBody: json.RawMessage(`{"id":"msg-1","model":"claude-test","content":[{"type":"text","text":"working"},{"type":"tool_use","id":"tool-1","name":"lookup","input":{"q":"x"}}],"stop_reason":"tool_use","usage":{"input_tokens":11,"output_tokens":4,"cache_read_input_tokens":5}}`)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projection, err := Normalize(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if err := openaivalidator.Validate(string(tt.in.Kind), projection.Exchange.Body); err != nil {
				t.Fatalf("projection does not validate: %v\n%s", err, projection.Exchange.Body)
			}
			if tt.in.Kind == KindResponse {
				if projection.Usage == nil || value(projection.Usage.TotalTokens) != 15 || projection.Usage.Quality.TotalTokens != "derived_from_provider_reported" {
					t.Fatalf("unexpected response usage: %+v", projection.Usage)
				}
			}
		})
	}
}

func TestNormalizeFailsClosed(t *testing.T) {
	valid := Input{Kind: KindRequest, Provider: ProviderOpenAICompatible, ProviderModel: "m", Endpoint: "https://example.test", ModelExchangeID: "x", NativeBody: json.RawMessage(`{"model":"m","messages":[{"role":"user","content":"x"}]}`)}
	tests := []struct {
		name   string
		mutate func(*Input)
	}{
		{name: "unknown provider", mutate: func(in *Input) { in.Provider = "other" }},
		{name: "unknown kind", mutate: func(in *Input) { in.Kind = "usage" }},
		{name: "missing endpoint", mutate: func(in *Input) { in.Endpoint = "" }},
		{name: "missing exchange", mutate: func(in *Input) { in.ModelExchangeID = "" }},
		{name: "invalid native JSON", mutate: func(in *Input) { in.NativeBody = json.RawMessage(`{`) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := valid
			tt.mutate(&in)
			if _, err := Normalize(in); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}

func value(v *uint64) uint64 {
	if v == nil {
		return 0
	}
	return *v
}
