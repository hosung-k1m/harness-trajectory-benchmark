package appender

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

func TestAppendAssignsDurableSequenceAndTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	fixed := time.UnixMilli(1234)
	a.now = func() time.Time { return fixed }

	got, err := a.Append(seed())
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != 1 || got.Time != fixed.UnixMilli() {
		t.Fatalf("event = %#v, want seq 1 at %d", got, fixed.UnixMilli())
	}
	frame, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(got)
	if string(frame) != string(want)+"\n" {
		t.Fatalf("persisted frame = %q, want %q", frame, append(want, '\n'))
	}
}

func TestAppendRejectsCallerAuthoritiesAndBadLineage(t *testing.T) {
	a, err := Open(filepath.Join(t.TempDir(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	for _, tc := range []struct {
		name  string
		event events.TrackedEvent
	}{
		{"caller seq", events.TrackedEvent{Seq: 1, Type: "session/end-seed", Data: json.RawMessage(`{}`)}},
		{"caller time", events.TrackedEvent{Time: 1, Type: "session/end-seed", Data: json.RawMessage(`{}`)}},
		{"future lineage", events.TrackedEvent{Type: "session/end-seed", Data: json.RawMessage(`{}`), SourceEventSeqs: []uint64{1}}},
		{"duplicate lineage", events.TrackedEvent{Type: "session/end-seed", Data: json.RawMessage(`{}`), SourceEventSeqs: []uint64{0, 0}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := a.Append(tc.event); err == nil {
				t.Fatal("Append accepted invalid input")
			}
		})
	}
	if a.NextSeq() != 1 {
		t.Fatalf("next seq = %d, want 1", a.NextSeq())
	}
}

func TestRestartRecoveryAndHashHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.Append(seed())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	a, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	second, err := a.Append(events.TrackedEvent{Type: "session/end-seed", Data: json.RawMessage(`{}`), SourceEventSeqs: []uint64{first.Seq}})
	if err != nil {
		t.Fatal(err)
	}
	if second.Seq != 2 {
		t.Fatalf("recovered sequence = %d, want 2", second.Seq)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var head [sha256.Size]byte
	for _, frame := range strings.SplitAfter(string(b), "\n") {
		if frame == "" {
			continue
		}
		head = chain(head, []byte(frame))
	}
	if got, want := a.HashHead(), hex.EncodeToString(head[:]); got != want {
		t.Fatalf("head = %s, want %s", got, want)
	}
}

func TestOpenFailsClosedForInvalidTails(t *testing.T) {
	valid, _ := json.Marshal(events.TrackedEvent{Seq: 1, Time: 1, Type: "session/end-seed", Data: json.RawMessage(`{}`)})
	for _, tc := range []struct {
		name string
		body string
	}{
		{"partial", string(valid)},
		{"bad json", "{not-json}\n"},
		{"gap", `{"seq":2,"time":1,"type":"session/end-seed","data":{}}` + "\n"},
		{"empty frame", string(valid) + "\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.jsonl")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path); err == nil {
				t.Fatal("Open accepted corrupt log")
			}
		})
	}
}

func TestConcurrentAppendIsGapFree(t *testing.T) {
	a, err := Open(filepath.Join(t.TempDir(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	const writers = 32
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := a.Append(seed())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	log := a.Snapshot()
	if len(log) != writers {
		t.Fatalf("events = %d, want %d", len(log), writers)
	}
	for i, event := range log {
		if event.Seq != uint64(i+1) {
			t.Fatalf("event %d seq = %d", i, event.Seq)
		}
	}
	if got := len(a.Since(uint64(writers))); got != 0 {
		t.Fatalf("Since tail returned %d events", got)
	}
}

func TestSealPersistsAndClosePreventsLateAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Append(seed()); err != nil {
		t.Fatal(err)
	}
	if err := a.Seal(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Append(seed()); !errors.Is(err, ErrSealed) {
		t.Fatalf("Append after Seal error = %v, want ErrSealed", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	a, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Append(seed()); !errors.Is(err, ErrSealed) {
		t.Fatalf("Append after reopening sealed log error = %v, want ErrSealed", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := Open(filepath.Join(t.TempDir(), "close.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Append(seed()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Append after Close error = %v, want ErrClosed", err)
	}
}

func TestSealedLogRejectsPostSealMutation(t *testing.T) {
	writeSealedLog := func(t *testing.T) string {
		path := filepath.Join(t.TempDir(), "events.jsonl")
		a, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err := a.Append(seed()); err != nil {
				t.Fatal(err)
			}
		}
		if err := a.Seal(); err != nil {
			t.Fatal(err)
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("modified final event", func(t *testing.T) {
		path := writeSealedLog(t)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		const marker = `"data":{}`
		last := bytes.LastIndex(b, []byte(marker))
		if last < 0 {
			t.Fatal("fixture frame not found")
		}
		mutated := append([]byte(nil), b[:last]...)
		mutated = append(mutated, `"data":{"mutated":true}`...)
		b = append(mutated, b[last+len(marker):]...)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path); err == nil {
			t.Fatal("Open accepted a mutated sealed log")
		}
	})

	t.Run("deleted final event", func(t *testing.T) {
		path := writeSealedLog(t)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cut := bytes.LastIndexByte(b[:len(b)-1], '\n')
		if err := os.WriteFile(path, b[:cut+1], 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path); err == nil {
			t.Fatal("Open accepted a truncated sealed log")
		}
	})

	t.Run("appended final event", func(t *testing.T) {
		path := writeSealedLog(t)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(`{"seq":3,"time":1,"type":"session/end-seed","data":{}}` + "\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path); err == nil {
			t.Fatal("Open accepted an extended sealed log")
		}
	})
}

func TestSealRejectsConflictingPreexistingMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Append(seed()); err != nil {
		t.Fatal(err)
	}
	if a.Sealed() {
		t.Fatal("Sealed before Seal")
	}
	if err := os.WriteFile(path+".sealed", []byte("deadbeef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Seal(); err == nil {
		t.Fatal("Seal accepted a conflicting preexisting marker")
	}
	if a.Sealed() {
		t.Fatal("conflicting marker marked the log sealed")
	}
	if _, err := a.Append(seed()); err != nil {
		t.Fatalf("Append after rejected Seal error = %v", err)
	}
}

func seed() events.TrackedEvent {
	return events.TrackedEvent{Type: "session/end-seed", Data: json.RawMessage(`{}`)}
}
