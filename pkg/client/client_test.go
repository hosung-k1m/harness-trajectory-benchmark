package client

import (
	"context"
	"encoding/json"
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

func TestClientTrajectoryAndEvidenceContracts(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/runs/run/trajectory":
			if r.URL.Query().Get("limit") != "2" {
				t.Fatalf("trajectory query: %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"items":[{"seq":1,"time":0,"type":"run/start","data":{},"ignorable":true}]}`))
		case "/v1/runs/run/trajectory/export":
			w.Header().Set("Content-Type", "application/x-ndjson")
			_, _ = w.Write([]byte("{\"seq\":1}\n"))
		case "/v1/runs/run/evidence":
			_, _ = w.Write([]byte(`{"runId":"run","status":"not_collected"}`))
		case "/v1/runs/run/evidence/export":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schemaVersion":"htb.evidence-bundle.v1"}`))
		default:
			t.Fatalf("unexpected request %s", r.URL)
		}
	}))
	defer s.Close()
	c := New(s.URL)
	trajectory, err := c.Trajectory(context.Background(), "run", "", 2)
	if err != nil || len(trajectory.Items) != 1 || trajectory.Items[0].Seq != 1 {
		t.Fatalf("trajectory=%#v err=%v", trajectory, err)
	}
	export, err := c.ExportTrajectory(context.Background(), "run")
	if err != nil || string(export) != "{\"seq\":1}\n" {
		t.Fatalf("export=%q err=%v", export, err)
	}
	report, err := c.Evidence(context.Background(), "run")
	if err != nil || report.Status != "not_collected" {
		t.Fatalf("evidence=%#v err=%v", report, err)
	}
	bundle, err := c.ExportEvidence(context.Background(), "run")
	if err != nil || string(bundle) != `{"schemaVersion":"htb.evidence-bundle.v1"}` {
		t.Fatalf("bundle=%q err=%v", bundle, err)
	}
}

func TestCreateRunPreservesParametersAndVerified(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request CreateRunRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if !request.Spec.Verified || string(request.Spec.Parameters["command"]) != `["sh","-c","true"]` {
			t.Fatalf("request = %#v", request)
		}
		_, _ = w.Write([]byte(`{"id":"run","spec":{"schemaVersion":"v1","harness":"h","suite":"s","backend":"compat","parameters":{"command":["sh","-c","true"]},"verified":true}}`))
	}))
	defer s.Close()
	got, err := New(s.URL).CreateRun(context.Background(), CreateRunRequest{Spec: RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "compat", Parameters: map[string]json.RawMessage{"command": json.RawMessage(`["sh","-c","true"]`)}, Verified: true}})
	if err != nil || !got.Spec.Verified || string(got.Spec.Parameters["command"]) != `["sh","-c","true"]` {
		t.Fatalf("run=%#v err=%v", got, err)
	}
}
