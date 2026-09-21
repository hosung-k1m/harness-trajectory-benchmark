package projection

import (
	"os"
	"testing"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/eventlog"
)

func TestBuildGoldenAnalysis(t *testing.T) {
	file, err := os.Open("../../testdata/golden/tracked-events.v1.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	log, err := eventlog.DecodeJSONL(file)
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := Build(log)
	if err != nil {
		t.Fatal(err)
	}
	if analysis.EventCount != uint64(len(log)) || analysis.PlaintextBytes["egress"] != 13 || analysis.PlaintextBytes["ingress"] != 32 {
		t.Fatalf("unexpected analysis: %#v", analysis)
	}
}
