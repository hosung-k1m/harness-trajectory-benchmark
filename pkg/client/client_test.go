package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientRequestAndErrorContracts(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/runs":
			if r.Method == http.MethodGet {
				if r.URL.Query().Get("cursor") != "a b&c" || r.URL.Query().Get("limit") != "7" {
					t.Fatalf("bad query: %s", r.URL.RawQuery)
				}
				_, _ = w.Write([]byte(`{"items":[]}`))
				return
			}
			if r.Header.Get("Idempotency-Key") != "key" || r.Header.Get("Content-Type") != "application/json" {
				t.Fatal("missing request headers")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"code":"policy","message":"denied"}}`))
		default:
			if strings.HasPrefix(r.URL.Path, "/v1/runs/a/") {
				if !strings.Contains(r.URL.EscapedPath(), "a%2Fb") {
					t.Fatalf("run ID was not escaped: %q", r.URL.EscapedPath())
				}
				_, _ = w.Write([]byte(`{"id":"a/b"}`))
				return
			}
			t.Fatalf("unexpected request %s", r.URL)
		}
	}))
	defer s.Close()
	c := New(s.URL)
	_, err := c.CreateRun(context.Background(), CreateRunRequest{IdempotencyKey: "key"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict || apiErr.Code != "policy" {
		t.Fatalf("unexpected error: %#v", err)
	}
	_, _ = c.ListRuns(context.Background(), "a b&c", 7)
	_, _ = c.GetRun(context.Background(), "a/b")
}

func TestClientContextAndMalformedBodies(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/runs":
			_, _ = w.Write([]byte(`{} trailing`))
		case "/v1/runs/id/events":
			_, _ = w.Write([]byte("{bad}\n"))
		default:
			_, _ = w.Write([]byte(`{} trailing`))
		}
	}))
	defer s.Close()
	c := New(s.URL)
	if _, err := c.GetRun(context.Background(), "x"); err == nil {
		t.Fatal("expected malformed JSON error")
	}
	if _, err := c.Events(context.Background(), "id"); err == nil {
		t.Fatal("expected malformed JSONL error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Compatibility(ctx); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestListRunsUsesDefaultLimit(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("limit"); got != "100" {
			t.Fatalf("limit=%q, want 100", got)
		}
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer s.Close()

	if _, err := New(s.URL).ListRuns(context.Background(), "", 0); err != nil {
		t.Fatal(err)
	}
}
