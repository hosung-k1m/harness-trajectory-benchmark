package eventlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

func TestGoldenLogIsAccepted(t *testing.T) {
	p := filepath.Join("..", "..", "testdata", "golden", "tracked-events.v1.jsonl")
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	log, err := DecodeJSONL(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 20 {
		t.Fatalf("got %d events", len(log))
	}
}

func TestRejectsGapAndForwardLineage(t *testing.T) {
	base := events.TrackedEvent{Seq: 1, Time: 0, Type: "session/end-seed", Data: []byte(`{}`)}
	if err := Validate([]events.TrackedEvent{base, {Seq: 3, Time: 0, Type: "session/end-seed", Data: []byte(`{}`)}}); err == nil || !strings.Contains(err.Error(), "want 2") {
		t.Fatalf("gap: %v", err)
	}
	bad := base
	bad.Seq = 2
	bad.SourceEventSeqs = []uint64{2}
	if err := Validate([]events.TrackedEvent{base, bad}); err == nil || !strings.Contains(err.Error(), "not earlier") {
		t.Fatalf("lineage: %v", err)
	}
}
