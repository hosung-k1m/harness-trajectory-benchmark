// Package client is a small Go client for the versioned benchmark control plane.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// APIError is returned for non-successful control-plane responses.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

func New(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTPClient: http.DefaultClient}
}
func (c *Client) CreateRun(ctx context.Context, req CreateRunRequest) (Run, error) {
	var out Run
	return out, c.do(ctx, http.MethodPost, "/v1/runs", req, req.IdempotencyKey, &out)
}
func (c *Client) GetRun(ctx context.Context, id string) (Run, error) {
	var out Run
	return out, c.do(ctx, http.MethodGet, "/v1/runs/"+url.PathEscape(id), nil, "", &out)
}
func (c *Client) Lifecycle(ctx context.Context, id string, m LifecycleMutation) (Run, error) {
	var out Run
	return out, c.do(ctx, http.MethodPost, "/v1/runs/"+url.PathEscape(id)+"/lifecycle", m, m.IdempotencyKey, &out)
}
func (c *Client) ListRuns(ctx context.Context, cursor string, limit int) (Page[Run], error) {
	var out Page[Run]
	if limit <= 0 {
		limit = 100
	}
	path := "/v1/runs?cursor=" + url.QueryEscape(cursor) + fmt.Sprintf("&limit=%d", limit)
	return out, c.do(ctx, http.MethodGet, path, nil, "", &out)
}
func (c *Client) Compatibility(ctx context.Context) (Compatibility, error) {
	var out Compatibility
	return out, c.do(ctx, http.MethodGet, "/v1/compatibility", nil, "", &out)
}
func (c *Client) Backends(ctx context.Context) (Page[CapabilityManifest], error) {
	var out Page[CapabilityManifest]
	return out, c.do(ctx, http.MethodGet, "/v1/backends", nil, "", &out)
}
func (c *Client) Events(ctx context.Context, id string) ([]events.TrackedEvent, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/runs/"+url.PathEscape(id)+"/events", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/x-ndjson")
	res, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return nil, readError(res)
	}
	var out []events.TrackedEvent
	d := json.NewDecoder(res.Body)
	for {
		var e events.TrackedEvent
		if err := d.Decode(&e); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}
func (c *Client) do(ctx context.Context, method, path string, input any, key string, out any) error {
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	res, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return readError(res)
	}
	return decodeJSON(res.Body, out)
}
func (c *Client) http() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}
func readError(res *http.Response) error {
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if decodeJSON(res.Body, &body) == nil && body.Error.Code != "" {
		return &APIError{StatusCode: res.StatusCode, Code: body.Error.Code, Message: body.Error.Message}
	}
	return &APIError{StatusCode: res.StatusCode, Code: "infrastructure", Message: "control plane returned " + res.Status}
}

func decodeJSON(r io.Reader, out any) error {
	d := json.NewDecoder(r)
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("response body must contain exactly one JSON document")
		}
		return err
	}
	return nil
}
