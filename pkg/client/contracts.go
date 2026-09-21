package client

import (
	"encoding/json"
	"time"
)

// Public contract types deliberately do not expose internal/api implementation types.
type RunSpec struct {
	SchemaVersion string                     `json:"schemaVersion"`
	Harness       string                     `json:"harness"`
	Suite         string                     `json:"suite"`
	Backend       string                     `json:"backend"`
	Parameters    map[string]json.RawMessage `json:"parameters,omitempty"`
	Verified      bool                       `json:"verified,omitempty"`
}
type CreateRunRequest struct {
	Spec           RunSpec `json:"spec"`
	IdempotencyKey string  `json:"idempotencyKey,omitempty"`
}
type LifecycleMutation struct {
	Action         string `json:"action"`
	IdempotencyKey string `json:"idempotencyKey,omitempty"`
	Reason         string `json:"reason,omitempty"`
}
type Run struct {
	ID        string    `json:"id"`
	Spec      RunSpec   `json:"spec"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}
type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
}
type CapabilityManifest struct {
	Backend       string   `json:"backend"`
	Version       string   `json:"version"`
	SchemaVersion string   `json:"schemaVersion"`
	Capabilities  []string `json:"capabilities"`
}
type Compatibility struct {
	APIVersions     []string `json:"apiVersions"`
	Schemas         []string `json:"schemas"`
	CLIVersion      string   `json:"cliVersion,omitempty"`
	StreamingFormat []string `json:"streamingFormats"`
}
