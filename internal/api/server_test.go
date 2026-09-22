package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateIdempotencyAndStream(t *testing.T) {
	s := httptest.NewServer(NewHandler(NewStore()))
	defer s.Close()
	body := []byte(`{"spec":{"schemaVersion":"v1","harness":"h","suite":"s","backend":"gvisor"}}`)
	request := func() *http.Request {
		r, _ := http.NewRequest(http.MethodPost, s.URL+"/v1/runs", bytes.NewReader(body))
		r.Header.Set("Idempotency-Key", "same")
		return r
	}
	a, e := http.DefaultClient.Do(request())
	if e != nil {
		t.Fatal(e)
	}
	if a.StatusCode != http.StatusCreated {
		t.Fatal(a.Status)
	}
	var one Run
	if err := json.NewDecoder(a.Body).Decode(&one); err != nil {
		t.Fatal(err)
	}
	a.Body.Close()
	b, err := http.DefaultClient.Do(request())
	if err != nil {
		t.Fatal(err)
	}
	var two Run
	if err := json.NewDecoder(b.Body).Decode(&two); err != nil {
		t.Fatal(err)
	}
	b.Body.Close()
	if one.ID != two.ID {
		t.Fatal("create did not deduplicate")
	}
	m, err := http.NewRequest(http.MethodPost, s.URL+"/v1/runs/"+one.ID+"/lifecycle", bytes.NewBufferString(`{"action":"start"}`))
	if err != nil {
		t.Fatal(err)
	}
	m.Header.Set("Idempotency-Key", "start")
	res, err := http.DefaultClient.Do(m)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	ev, err := http.Get(s.URL + "/v1/runs/" + one.ID + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Body.Close()
	var event map[string]any
	if err := json.NewDecoder(ev.Body).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event["seq"] != float64(1) || event["type"] != "run/start" {
		t.Fatalf("unexpected event: %#v", event)
	}
}

func TestHandlerRejectsInvalidPaginationAndExtraJSON(t *testing.T) {
	h := NewHandler(NewStore())
	for _, target := range []string{"/v1/runs?cursor=-1", "/v1/runs?cursor=not-a-number", "/v1/runs?cursor=999999999999999999999999", "/v1/runs?limit=-1", "/v1/runs?limit=101"} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", target, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/runs", bytes.NewBufferString(`{"spec":{"schemaVersion":"v1","harness":"h","suite":"s","backend":"b"}} {}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("extra JSON got %d", w.Code)
	}
}

func TestPaginationEmptyCursorStillHonorsLimit(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/runs?cursor=&limit=7", nil)
	offset, limit, err := pagination(r)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 0 || limit != 7 {
		t.Fatalf("got offset=%d limit=%d", offset, limit)
	}
}

func TestHandlerRoutesAndIdempotencyContracts(t *testing.T) {
	h := NewHandler(nil)
	for _, target := range []string{"/v1/compatibility", "/v1/schemas", "/v1/backends"} {
		r := httptest.NewRequest(http.MethodPost, target, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s got %d", target, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/runs/missing/events", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing events got %d", w.Code)
	}

	create := func(harness string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/v1/runs", bytes.NewBufferString(`{"spec":{"schemaVersion":"v1","harness":"`+harness+`","suite":"s","backend":"b"}}`))
		r.Header.Set("Idempotency-Key", "same")
		h.ServeHTTP(w, r)
		return w
	}
	if got := create("one").Code; got != http.StatusCreated {
		t.Fatal(got)
	}
	if got := create("two").Code; got != http.StatusConflict {
		t.Fatalf("reuse got %d", got)
	}
}

func TestDecodeRejectsTrailingNonWhitespace(t *testing.T) {
	err := decode(httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{} {}`)), &map[string]any{})
	if err == nil || err == io.EOF {
		t.Fatal("expected trailing document error")
	}
}

func TestTrajectoryEvidenceAndWebSurface(t *testing.T) {
	store := NewStore()
	run, err := store.create(CreateRunRequest{Spec: RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.AppendEvent(run.ID, Event{Type: "run/start", Data: json.RawMessage(`{}`), Ignorable: true})
	if err != nil || first.Seq != 1 {
		t.Fatalf("append = %#v, %v", first, err)
	}
	if _, err := store.AppendEvent(run.ID, Event{Seq: 2, Type: "run/start", Data: json.RawMessage(`{}`), Ignorable: true}); err == nil {
		t.Fatal("expected caller-supplied sequence rejection")
	}
	if err := store.SetEvidenceVerification(run.ID, VerificationResult{Status: "ineligible", Summary: "no evidence backend"}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(store)
	for _, tc := range []struct {
		path        string
		contentType string
		contains    string
	}{
		{"/v1/runs/" + run.ID + "/trajectory?limit=1", "application/json", `"seq":1`},
		{"/v1/runs/" + run.ID + "/trajectory/export", "application/x-ndjson", `"seq":1`},
		{"/v1/runs/" + run.ID + "/evidence", "application/json", `"status":"verification_recorded"`},
		{"/web/", "text/html", "/v1/runs"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), tc.contentType) || !strings.Contains(w.Body.String(), tc.contains) {
				t.Fatalf("status=%d type=%q body=%q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
			}
		})
	}
}

type memoryEventLog struct{ events []Event }

func (l *memoryEventLog) Append(event Event) (Event, error) {
	event.Seq = uint64(len(l.events) + 1)
	event.Time = 1
	l.events = append(l.events, event)
	return event, nil
}
func (l *memoryEventLog) Snapshot() []Event { return append([]Event(nil), l.events...) }

func TestStoreCanDelegateToDurableAppenderBoundary(t *testing.T) {
	log := &memoryEventLog{}
	store := NewStoreWithEventLogFactory(func(run Run) (EventLog, error) {
		if run.ID == "" {
			t.Fatal("run ID was not assigned before log creation")
		}
		return log, nil
	})
	run, err := store.create(CreateRunRequest{Spec: RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendEvent(run.ID, Event{Type: "run/start", Data: json.RawMessage(`{}`), Ignorable: true}); err != nil {
		t.Fatal(err)
	}
	got, ok := store.Events(run.ID)
	if !ok || len(got) != 1 || got[0].Seq != 1 || len(log.events) != 1 {
		t.Fatalf("store events=%#v log=%#v", got, log.events)
	}
}

type fakeRunDriver struct {
	calls                []string
	prepareErr, startErr error
	stopErr              error
	observedCanceledCtx  bool
}

func (d *fakeRunDriver) Prepare(ctx context.Context, run Run) error {
	d.calls = append(d.calls, "prepare:"+run.ID)
	d.observedCanceledCtx = d.observedCanceledCtx || ctx.Err() != nil
	if d.prepareErr != nil {
		return d.prepareErr
	}
	return ctx.Err()
}
func (d *fakeRunDriver) Start(ctx context.Context, id string) error {
	d.calls = append(d.calls, "start:"+id)
	d.observedCanceledCtx = d.observedCanceledCtx || ctx.Err() != nil
	if d.startErr != nil {
		return d.startErr
	}
	return ctx.Err()
}
func (d *fakeRunDriver) Stop(ctx context.Context, id, reason string) error {
	d.calls = append(d.calls, "stop:"+id+":"+reason)
	d.observedCanceledCtx = d.observedCanceledCtx || ctx.Err() != nil
	if d.stopErr != nil {
		return d.stopErr
	}
	return ctx.Err()
}

func TestRunDriverLifecycleOrderAndFailureStatePreservation(t *testing.T) {
	driver := &fakeRunDriver{}
	store := NewStoreWithRunDriver(driver)
	run, err := store.create(CreateRunRequest{Spec: RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.mutate(run.ID, LifecycleMutation{Action: "start"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.mutate(run.ID, LifecycleMutation{Action: "stop", Reason: "requested"}); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(driver.calls, ","), "prepare:"+run.ID+",start:"+run.ID+",stop:"+run.ID+":requested"; got != want {
		t.Fatalf("calls=%q want %q", got, want)
	}

	for _, tc := range []struct {
		name   string
		setup  func(*fakeRunDriver)
		action string
		status string
	}{
		{"start", func(d *fakeRunDriver) { d.startErr = errors.New("start failed") }, "start", "created"},
		{"stop", func(d *fakeRunDriver) { d.stopErr = errors.New("stop failed") }, "stop", "running"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeRunDriver{}
			s := NewStoreWithRunDriver(d)
			r, err := s.create(CreateRunRequest{Spec: RunSpec{SchemaVersion: "v1", Harness: "h", Suite: "s", Backend: "b"}})
			if err != nil {
				t.Fatal(err)
			}
			if tc.action == "stop" {
				if _, err := s.mutate(r.ID, LifecycleMutation{Action: "start"}); err != nil {
					t.Fatal(err)
				}
			}
			tc.setup(d)
			if _, err := s.mutate(r.ID, LifecycleMutation{Action: tc.action}); err == nil {
				t.Fatal("expected driver error")
			} else if apiErr, ok := err.(*APIError); !ok || apiErr.Code != "execution" {
				t.Fatalf("error=%v", err)
			}
			got, _ := s.get(r.ID)
			if got.Status != tc.status {
				t.Fatalf("status=%q want %q", got.Status, tc.status)
			}
		})
	}
}

func TestRunDriverUsesHTTPRequestContextAndPreservesCreateFailure(t *testing.T) {
	driver := &fakeRunDriver{}
	store := NewStoreWithRunDriver(driver)
	h := NewHandler(store)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/runs", bytes.NewBufferString(`{"spec":{"schemaVersion":"v1","harness":"h","suite":"s","backend":"b"}}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), `"code":"execution"`) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !driver.observedCanceledCtx || len(store.list()) != 0 {
		t.Fatalf("driver cancellation=%t runs=%#v", driver.observedCanceledCtx, store.list())
	}
}
