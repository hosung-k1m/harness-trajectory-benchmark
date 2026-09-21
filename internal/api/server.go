package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

// Store is deliberately small: it provides a contract-test implementation, not execution.
type Store struct {
	mu          sync.Mutex
	runs        map[string]Run
	events      map[string][]Event
	idempotency map[string]idempotencyRecord
	next        uint64
}

type idempotencyRecord struct {
	run     Run
	request string
}

func NewStore() *Store {
	return &Store{runs: map[string]Run{}, events: map[string][]Event{}, idempotency: map[string]idempotencyRecord{}}
}
func (s *Store) create(req CreateRunRequest) (Run, error) {
	if req.Spec.SchemaVersion != "v1" || req.Spec.Harness == "" || req.Spec.Suite == "" || req.Spec.Backend == "" {
		return Run{}, &APIError{"validation", "spec requires schemaVersion v1, harness, suite, and backend"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.IdempotencyKey != "" {
		key := "create:" + req.IdempotencyKey
		request := createRequestFingerprint(req)
		if prior, ok := s.idempotency[key]; ok {
			if prior.request != request {
				return Run{}, &APIError{"conflict", "idempotency key was used for a different request"}
			}
			return prior.run, nil
		}
	}
	s.next++
	now := time.Now().UTC()
	r := Run{ID: fmt.Sprintf("run-%06d", s.next), Spec: req.Spec, Status: "created", CreatedAt: now, UpdatedAt: now}
	s.runs[r.ID] = r
	s.events[r.ID] = nil
	if req.IdempotencyKey != "" {
		s.idempotency["create:"+req.IdempotencyKey] = idempotencyRecord{run: r, request: createRequestFingerprint(req)}
	}
	return r, nil
}
func (s *Store) mutate(id string, m LifecycleMutation) (Run, error) {
	if m.Action != "start" && m.Action != "stop" {
		return Run{}, &APIError{"validation", "action must be start or stop"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if !ok {
		return Run{}, &APIError{"not_found", "run not found"}
	}
	key := "mutation:" + id + ":" + m.IdempotencyKey
	if m.IdempotencyKey != "" {
		request := lifecycleFingerprint(m)
		if prior, ok := s.idempotency[key]; ok {
			if prior.request != request {
				return Run{}, &APIError{"conflict", "idempotency key was used for a different request"}
			}
			return prior.run, nil
		}
	}
	if m.Action == "start" {
		if r.Status != "created" {
			return Run{}, &APIError{"conflict", "only created runs can start"}
		}
		r.Status = "running"
	} else {
		if r.Status != "running" {
			return Run{}, &APIError{"conflict", "only running runs can stop"}
		}
		r.Status = "stopped"
	}
	r.UpdatedAt = time.Now().UTC()
	s.runs[id] = r
	es := s.events[id]
	eventType := "run/start"
	if m.Action == "stop" {
		eventType = "run/finish"
	}
	data, _ := json.Marshal(map[string]string{"reason": m.Reason})
	s.events[id] = append(es, events.TrackedEvent{Seq: uint64(len(es) + 1), Time: r.UpdatedAt.UnixMilli(), Type: eventType, Data: data, Ignorable: true})
	if m.IdempotencyKey != "" {
		s.idempotency[key] = idempotencyRecord{run: r, request: lifecycleFingerprint(m)}
	}
	return r, nil
}
func (s *Store) get(id string) (Run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	return r, ok
}
func (s *Store) list() []Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Run, 0, len(s.runs))
	for _, r := range s.runs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (s *Store) runEvents(id string) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events[id]...)
}

func createRequestFingerprint(v CreateRunRequest) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func lifecycleFingerprint(v LifecycleMutation) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func NewHandler(store *Store) http.Handler {
	if store == nil {
		store = NewStore()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/compatibility", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			method(w, http.MethodGet)
			return
		}
		writeJSON(w, http.StatusOK, Compatibility{APIVersions: []string{"v1"}, Schemas: []string{OpenAIChatCompletionsSchema}, StreamingFormat: []string{"application/x-ndjson", "text/event-stream"}})
	})
	mux.HandleFunc("/v1/schemas", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			method(w, http.MethodGet)
			return
		}
		writeJSON(w, http.StatusOK, Page[string]{Items: []string{"control-api.v1", OpenAIChatCompletionsSchema}})
	})
	mux.HandleFunc("/v1/backends", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			method(w, http.MethodGet)
			return
		}
		writeJSON(w, http.StatusOK, Page[CapabilityManifest]{Items: []CapabilityManifest{{Backend: "gvisor", Version: "phase0", SchemaVersion: "v1", Capabilities: []string{"declarative-runs"}}}})
	})
	mux.HandleFunc("/v1/runs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req CreateRunRequest
			if err := decode(r, &req); err != nil {
				bad(w, err)
				return
			}
			if req.IdempotencyKey == "" {
				req.IdempotencyKey = r.Header.Get("Idempotency-Key")
			}
			run, err := store.create(req)
			respond(w, http.StatusCreated, run, err)
			return
		}
		if r.Method == http.MethodGet {
			items := store.list()
			offset, limit, err := pagination(r)
			if err != nil {
				bad(w, err)
				return
			}
			if offset > len(items) {
				bad(w, fmt.Errorf("cursor is beyond available results"))
				return
			}
			end := len(items)
			if limit <= len(items)-offset {
				end = offset + limit
			}
			p := Page[Run]{Items: items[offset:end]}
			if end < len(items) {
				p.NextCursor = strconv.Itoa(end)
			}
			writeJSON(w, http.StatusOK, p)
			return
		}
		method(w, http.MethodGet+", "+http.MethodPost)
	})
	mux.HandleFunc("/v1/runs/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/runs/"), "/")
		if len(parts) < 1 || parts[0] == "" {
			http.NotFound(w, r)
			return
		}
		id := parts[0]
		if len(parts) == 1 {
			if r.Method != http.MethodGet {
				method(w, http.MethodGet)
				return
			}
			run, ok := store.get(id)
			if !ok {
				respond(w, 0, nil, &APIError{"not_found", "run not found"})
				return
			}
			writeJSON(w, http.StatusOK, run)
			return
		}
		if len(parts) == 2 && parts[1] == "lifecycle" {
			if r.Method != http.MethodPost {
				method(w, http.MethodPost)
				return
			}
			var m LifecycleMutation
			if err := decode(r, &m); err != nil {
				bad(w, err)
				return
			}
			if m.IdempotencyKey == "" {
				m.IdempotencyKey = r.Header.Get("Idempotency-Key")
			}
			run, err := store.mutate(id, m)
			respond(w, http.StatusOK, run, err)
			return
		}
		if len(parts) == 2 && parts[1] == "events" {
			if r.Method != http.MethodGet {
				method(w, http.MethodGet)
				return
			}
			if _, ok := store.get(id); !ok {
				respond(w, 0, nil, &APIError{"not_found", "run not found"})
				return
			}
			events := store.runEvents(id)
			if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
				w.Header().Set("Content-Type", "text/event-stream")
				for _, e := range events {
					b, _ := json.Marshal(e)
					fmt.Fprintf(w, "event: tracked\ndata: %s\n\n", b)
				}
				return
			}
			w.Header().Set("Content-Type", "application/x-ndjson")
			for _, e := range events {
				_ = json.NewEncoder(w).Encode(e)
			}
			return
		}
		http.NotFound(w, r)
	})
	return mux
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("request body must contain exactly one JSON document")
		}
		return err
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func bad(w http.ResponseWriter, e error) { respond(w, 0, nil, &APIError{"validation", e.Error()}) }
func respond(w http.ResponseWriter, status int, v any, e error) {
	if e == nil {
		writeJSON(w, status, v)
		return
	}
	ae, ok := e.(*APIError)
	if !ok {
		ae = &APIError{"internal", e.Error()}
	}
	code := http.StatusBadRequest
	if ae.Code == "not_found" {
		code = http.StatusNotFound
	}
	if ae.Code == "conflict" {
		code = http.StatusConflict
	}
	writeJSON(w, code, map[string]any{"error": ae})
}
func pagination(r *http.Request) (int, int, error) {
	q := r.URL.Query()
	offset := 0
	limit := 100
	if raw, ok := q["cursor"]; ok && len(raw) > 0 {
		if len(raw) != 1 {
			return 0, 0, fmt.Errorf("cursor must be specified once")
		}
		if raw[0] != "" {
			v, err := strconv.ParseUint(raw[0], 10, strconv.IntSize)
			if err != nil {
				return 0, 0, fmt.Errorf("cursor must be a non-negative integer")
			}
			offset = int(v)
		}
	}
	if raw, ok := q["limit"]; ok && len(raw) > 0 {
		if len(raw) != 1 {
			return 0, 0, fmt.Errorf("limit must be specified once")
		}
		if raw[0] != "" {
			v, err := strconv.ParseUint(raw[0], 10, strconv.IntSize)
			if err != nil || v == 0 || v > 100 {
				return 0, 0, fmt.Errorf("limit must be an integer from 1 to 100")
			}
			limit = int(v)
		}
	}
	return offset, limit, nil
}
func method(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": map[string]string{"code": "method_not_allowed", "message": "method not allowed"}})
}
