package openaivalidator

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFixtures(t *testing.T) {
	cases := []struct{ kind, file string }{{"request", "request.json"}, {"response", "response.json"}, {"chunk", "chunk.json"}, {"tool", "tool.json"}, {"usage", "usage.json"}}
	for _, tc := range cases {
		for _, dir := range []string{"valid", "invalid"} {
			raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "openai-chat-completions-v1", "fixtures", dir, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			got := Validate(tc.kind, raw) == nil
			if got != (dir == "valid") {
				t.Errorf("%s/%s validation = %v", dir, tc.file, got)
			}
		}
	}
}

func TestRequestRejectsUnknownRole(t *testing.T) {
	raw := []byte(`{"model":"gpt-test","messages":[{"role":"wizard","content":"hello"}]}`)
	if err := Validate("request", raw); err == nil {
		t.Fatal("accepted unknown message role")
	}
}

func TestResponseRequiresTypedChoices(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"id":"x","object":"chat.completion","model":"m","choices":[{}]}`),
		[]byte(`{"id":"x","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"user","content":"x"},"finish_reason":"stop"}]}`),
		[]byte(`{"id":"x","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"invented"}]}`),
	}
	for _, raw := range cases {
		if err := Validate("response", raw); err == nil {
			t.Errorf("accepted malformed response: %s", raw)
		}
	}
}

func TestChunkRequiresIndexAndDelta(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"id":"x","object":"chat.completion.chunk","model":"m","choices":[{"delta":{}}]}`),
		[]byte(`{"id":"x","object":"chat.completion.chunk","model":"m","choices":[{"index":0}]}`),
	}
	for _, raw := range cases {
		if err := Validate("chunk", raw); err == nil {
			t.Errorf("accepted malformed chunk: %s", raw)
		}
	}
}

func TestUsageRejectsMissingFractionalAndUnknownShapes(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"prompt_tokens":1,"completion_tokens":2}`),
		[]byte(`{"prompt_tokens":1.5,"completion_tokens":2,"total_tokens":3}`),
		[]byte(`{"prompt_tokens":1,"completion_tokens":2,"total_tokens":-1}`),
	}
	for _, raw := range cases {
		if err := Validate("usage", raw); err == nil {
			t.Errorf("accepted malformed usage: %s", raw)
		}
	}
}
