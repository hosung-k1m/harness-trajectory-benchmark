package controlplane

import (
	"strings"
	"testing"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
)

func headRecord(t *testing.T, sensor, boot string, seq uint64) evidence.RawRecord {
	t.Helper()
	r := evidence.RawRecord{RunID: "run", SensorID: sensor, BootID: boot, SourceSeq: seq, RecordType: "x", Encoding: "json", Payload: []byte(`{"x":1}`)}
	hash, err := r.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	r.RecordSHA256 = hash
	return r
}

func TestExpectedHeads(t *testing.T) {
	headA := strings.Repeat("a", 64)
	headB := strings.Repeat("b", 64)
	for _, tc := range []struct {
		name    string
		records []evidence.RawRecord
		heads   map[string]string
		want    map[evidence.RawSource]string
		wantErr string
	}{
		{
			name:    "empty records",
			records: nil,
			heads:   map[string]string{"s1": headA},
			want:    map[evidence.RawSource]string{},
		},
		{
			name: "multi-source map",
			records: []evidence.RawRecord{
				headRecord(t, "s1", "b1", 1),
				headRecord(t, "s1", "b1", 2),
				headRecord(t, "s2", "b2", 1),
			},
			heads: map[string]string{"s1": headA, "s2": headB},
			want: map[evidence.RawSource]string{
				{SensorID: "s1", BootID: "b1"}: headA,
				{SensorID: "s2", BootID: "b2"}: headB,
			},
		},
		{
			name:    "missing head",
			records: []evidence.RawRecord{headRecord(t, "s1", "b1", 1)},
			heads:   map[string]string{"s2": headB},
			wantErr: `backend reported no raw chain head for sensor "s1"`,
		},
		{
			name:    "empty head",
			records: []evidence.RawRecord{headRecord(t, "s1", "b1", 1)},
			heads:   map[string]string{"s1": ""},
			wantErr: `backend reported no raw chain head for sensor "s1"`,
		},
		{
			name: "two boot IDs for one sensor",
			records: []evidence.RawRecord{
				headRecord(t, "s1", "b1", 1),
				headRecord(t, "s1", "b2", 2),
			},
			heads:   map[string]string{"s1": headA},
			wantErr: `ambiguous raw chain head for sensor "s1"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expectedHeads(tc.records, tc.heads)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %#v want %#v", got, tc.want)
			}
			for source, head := range tc.want {
				if got[source] != head {
					t.Fatalf("got %#v want %#v", got, tc.want)
				}
			}
		})
	}
}
