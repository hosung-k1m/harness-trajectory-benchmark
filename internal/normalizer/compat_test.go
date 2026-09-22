package normalizer

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/appender"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

func TestNormalizeCompatMapsRecordsWithExactLineage(t *testing.T) {
	records := rawRecords(t, "process/start", "workload/stdout", "workload/stderr", "process/exit", "runtime/snapshot", "sensor/health")
	got, err := NormalizeCompat(records)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"process/exec", "stdio/chunk", "stdio/chunk", "process/exit", "backend/snapshot", "sensor/stop"}
	if len(got.Events) != len(want) || len(got.Coverage) != len(want) {
		t.Fatalf("events=%d coverage=%d", len(got.Events), len(got.Coverage))
	}
	for i, typ := range want {
		t.Run(typ, func(t *testing.T) {
			e := got.Events[i]
			if e.Type != typ || !e.Ignorable || e.Seq != 0 || e.Time != 0 {
				t.Fatalf("event = %#v", e)
			}
			var data events.ObservationData[map[string]string]
			if err := json.Unmarshal(e.Data, &data); err != nil {
				t.Fatal(err)
			}
			if data.Evidence.RawRecordSHA256 != records[i].RecordSHA256 || data.Evidence.RawSourceSeqStart != records[i].SourceSeq || data.Evidence.RawSourceSeqEnd != records[i].SourceSeq || data.Source.SourceSeq != records[i].SourceSeq {
				t.Fatalf("lineage = %#v", data)
			}
			if got.Coverage[i].EventID != records[i].RecordSHA256 {
				t.Fatalf("coverage = %#v", got.Coverage[i])
			}
		})
	}
	if err := evidence.ValidateRawCoverage(records, got.Coverage); err != nil {
		t.Fatal(err)
	}
	if got.Version != CompatVersion || got.Digest != CompatDigest {
		t.Fatalf("descriptor = %#v", got)
	}
}

func TestBindCoverageEventIDs(t *testing.T) {
	records := rawRecords(t, "process/start", "workload/stdout", "process/exit")
	result, err := NormalizeCompat(records)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("binds appended sequences", func(t *testing.T) {
		bound, err := BindCoverageEventIDs(result.Coverage, []uint64{2, 5, 9})
		if err != nil {
			t.Fatal(err)
		}
		for i, want := range []string{"2", "5", "9"} {
			if bound[i].EventID != want {
				t.Fatalf("coverage %d EventID = %q want %q", i, bound[i].EventID, want)
			}
			if bound[i].Raw != result.Coverage[i].Raw {
				t.Fatalf("coverage %d Raw changed: %#v", i, bound[i])
			}
		}
		if result.Coverage[0].EventID != records[0].RecordSHA256 {
			t.Fatal("BindCoverageEventIDs mutated its input")
		}
		if err := evidence.ValidateRawCoverage(records, bound); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("length mismatch", func(t *testing.T) {
		if _, err := BindCoverageEventIDs(result.Coverage, []uint64{1, 2}); err == nil {
			t.Fatal("accepted mismatched lengths")
		}
	})
	t.Run("zero sequence", func(t *testing.T) {
		if _, err := BindCoverageEventIDs(result.Coverage, []uint64{1, 0, 3}); err == nil {
			t.Fatal("accepted a zero sequence")
		}
	})
	t.Run("empty", func(t *testing.T) {
		bound, err := BindCoverageEventIDs(nil, nil)
		if err != nil || len(bound) != 0 {
			t.Fatalf("bound=%#v err=%v", bound, err)
		}
	})
}

func TestNormalizeCompatRejectsInvalidAndUnknown(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]evidence.RawRecord)
	}{
		{"unknown-type", func(r []evidence.RawRecord) { r[0].RecordType = "network/connect"; rehash(t, r) }},
		{"invalid-hash", func(r []evidence.RawRecord) { r[0].RecordSHA256 = "bad" }},
		{"broken-lineage", func(r []evidence.RawRecord) { r[1].SourceSeq = 3; rehash(t, r) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			records := rawRecords(t, "process/start", "process/exit")
			tc.mutate(records)
			if _, err := NormalizeCompat(records); err == nil {
				t.Fatal("NormalizeCompat succeeded")
			}
		})
	}
}

func TestNormalizeCompatAppenderCompatibility(t *testing.T) {
	result, err := NormalizeCompat(rawRecords(t, "process/start", "process/exit"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := appender.Open(t.TempDir() + "/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	for i, candidate := range result.Events {
		appended, err := a.Append(candidate)
		if err != nil {
			t.Fatalf("Append event %d: %v", i, err)
		}
		if appended.Seq != uint64(i+1) || appended.Time == 0 {
			t.Fatalf("appended = %#v", appended)
		}
	}
}

func rawRecords(t *testing.T, types ...string) []evidence.RawRecord {
	t.Helper()
	now := time.Unix(100, 0).UTC()
	records := make([]evidence.RawRecord, 0, len(types))
	prev := ""
	for i, typ := range types {
		r := evidence.RawRecord{RunID: "run", SensorID: "compat-local-process", BootID: "boot", SourceSeq: uint64(i + 1), ObservedWallTime: &now, RecordType: typ, Encoding: "binary", Payload: []byte(typ), PreviousRecordSHA256: prev}
		hash, err := r.ComputedHash()
		if err != nil {
			t.Fatal(err)
		}
		r.RecordSHA256 = hash
		prev = hash
		records = append(records, r)
	}
	return records
}
func rehash(t *testing.T, records []evidence.RawRecord) {
	t.Helper()
	for i := range records {
		if i == 0 {
			records[i].PreviousRecordSHA256 = ""
		} else {
			records[i].PreviousRecordSHA256 = records[i-1].RecordSHA256
		}
		h, err := records[i].ComputedHash()
		if err != nil {
			t.Fatal(err)
		}
		records[i].RecordSHA256 = h
	}
}
