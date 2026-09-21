package replay

import (
	"testing"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

func TestReplaceRewritesOnlySurfaceProjection(t *testing.T) {
	replace, err := events.NewReplaceSurfaceOp(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	log := []events.TrackedEvent{{Seq: 1, Type: "user/message", SurfaceOp: events.AppendSurfaceOp()}, {Seq: 2, Type: "assistant/message", SurfaceOp: events.AppendSurfaceOp()}, {Seq: 3, Type: "sensor/drop", Ignorable: true}, {Seq: 4, Type: "compaction/summary", SurfaceOp: replace}}
	got, err := Replay(log)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Seq != 4 {
		t.Fatalf("surface=%+v", got)
	}
	if string(got[0].SurfaceOp) != string(replace) {
		t.Fatal("wire shape changed")
	}
}
