package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
