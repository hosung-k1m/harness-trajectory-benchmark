// Package openaivalidator validates the pinned OpenAI-compatible v1 boundary.
package openaivalidator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

type message struct {
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	ToolCalls []toolCall      `json:"tool_calls"`
}

type functionTool struct {
	Type     string `json:"type"`
	Function struct {
		Name       string          `json:"name"`
		Parameters json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type toolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type requestBody struct {
	Model    string         `json:"model"`
	Messages []message      `json:"messages"`
	Tools    []functionTool `json:"tools"`
}

type usageBody struct {
	PromptTokens     *uint64 `json:"prompt_tokens"`
	CompletionTokens *uint64 `json:"completion_tokens"`
	TotalTokens      *uint64 `json:"total_tokens"`
}

type responseChoice struct {
	Index        *int            `json:"index"`
	Message      *message        `json:"message"`
	FinishReason json.RawMessage `json:"finish_reason"`
}

type responseBody struct {
	ID      string           `json:"id"`
	Object  string           `json:"object"`
	Model   string           `json:"model"`
	Choices []responseChoice `json:"choices"`
	Usage   *usageBody       `json:"usage"`
}

type chunkChoice struct {
	Index        *int            `json:"index"`
	Delta        json.RawMessage `json:"delta"`
	FinishReason json.RawMessage `json:"finish_reason"`
}

type chunkBody struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Model   string        `json:"model"`
	Choices []chunkChoice `json:"choices"`
}

func Validate(kind string, raw []byte) error {
	if !jsonObject(raw) {
		return fmt.Errorf("%s must be one JSON object", kind)
	}
	switch kind {
	case "request":
		var body requestBody
		if err := json.Unmarshal(raw, &body); err != nil {
			return err
		}
		return validateRequest(body)
	case "response":
		var body responseBody
		if err := json.Unmarshal(raw, &body); err != nil {
			return err
		}
		return validateResponse(body)
	case "chunk":
		var body chunkBody
		if err := json.Unmarshal(raw, &body); err != nil {
			return err
		}
		return validateChunk(body)
	case "tool":
		var tool functionTool
		if err := json.Unmarshal(raw, &tool); err != nil {
			return err
		}
		return validateTool(tool)
	case "usage":
		var usage usageBody
		if err := json.Unmarshal(raw, &usage); err != nil {
			return err
		}
		return validateUsage(usage)
	default:
		return fmt.Errorf("unknown schema kind %q", kind)
	}
}

func validateRequest(body requestBody) error {
	if body.Model == "" || len(body.Messages) == 0 {
		return errors.New("model and at least one message are required")
	}
	for i, message := range body.Messages {
		if err := validateMessage(message, false); err != nil {
			return fmt.Errorf("message %d: %w", i, err)
		}
	}
	for i, tool := range body.Tools {
		if err := validateTool(tool); err != nil {
			return fmt.Errorf("tool %d: %w", i, err)
		}
	}
	return nil
}

func validateMessage(value message, response bool) error {
	if response {
		if value.Role != "assistant" {
			return errors.New("response message role must be assistant")
		}
	} else if !oneOf(value.Role, "system", "user", "assistant", "tool", "developer") {
		return fmt.Errorf("unknown message role %q", value.Role)
	}
	if len(value.Content) == 0 && len(value.ToolCalls) == 0 {
		return errors.New("message requires content or tool_calls")
	}
	if len(value.Content) != 0 && !json.Valid(value.Content) {
		return errors.New("message content must be valid JSON")
	}
	for i, call := range value.ToolCalls {
		if call.ID == "" || call.Type != "function" || call.Function.Name == "" || !json.Valid([]byte(call.Function.Arguments)) {
			return fmt.Errorf("invalid tool call %d", i)
		}
	}
	return nil
}

func validateTool(tool functionTool) error {
	if tool.Type != "function" || tool.Function.Name == "" {
		return errors.New("tool type and function name are required")
	}
	if !jsonObject(tool.Function.Parameters) {
		return errors.New("function parameters must be an object schema")
	}
	var schema struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(tool.Function.Parameters, &schema); err != nil {
		return err
	}
	if schema.Type != "object" {
		return errors.New("function parameters type must be object")
	}
	return nil
}

func validateResponse(body responseBody) error {
	if body.ID == "" || body.Model == "" || body.Object != "chat.completion" || len(body.Choices) == 0 {
		return errors.New("invalid chat completion identity or choices")
	}
	for i, choice := range body.Choices {
		if choice.Index == nil || *choice.Index < 0 || choice.Message == nil {
			return fmt.Errorf("choice %d requires non-negative index and message", i)
		}
		if err := validateMessage(*choice.Message, true); err != nil {
			return fmt.Errorf("choice %d: %w", i, err)
		}
		if err := validateFinishReason(choice.FinishReason, false); err != nil {
			return fmt.Errorf("choice %d: %w", i, err)
		}
	}
	if body.Usage != nil {
		return validateUsage(*body.Usage)
	}
	return nil
}

func validateChunk(body chunkBody) error {
	if body.ID == "" || body.Model == "" || body.Object != "chat.completion.chunk" {
		return errors.New("invalid chat completion chunk identity")
	}
	for i, choice := range body.Choices {
		if choice.Index == nil || *choice.Index < 0 || !jsonObject(choice.Delta) {
			return fmt.Errorf("choice %d requires non-negative index and delta", i)
		}
		if len(choice.FinishReason) != 0 {
			if err := validateFinishReason(choice.FinishReason, true); err != nil {
				return fmt.Errorf("choice %d: %w", i, err)
			}
		}
	}
	return nil
}

func validateFinishReason(raw json.RawMessage, nullable bool) error {
	if len(raw) == 0 {
		return errors.New("finish_reason is required")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if nullable {
			return nil
		}
		return errors.New("finish_reason cannot be null in a completed response")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return errors.New("finish_reason must be a string or null")
	}
	if !oneOf(value, "stop", "length", "tool_calls", "content_filter", "function_call") {
		return fmt.Errorf("unknown finish_reason %q", value)
	}
	return nil
}

func validateUsage(usage usageBody) error {
	if usage.PromptTokens == nil || usage.CompletionTokens == nil || usage.TotalTokens == nil {
		return errors.New("prompt_tokens, completion_tokens, and total_tokens are required")
	}
	return nil
}

func jsonObject(raw []byte) bool {
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
