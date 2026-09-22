package normalizer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/evidence"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/llmnormalizer"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

const mockRequestBody = `{"model":"mock-model","messages":[{"role":"user","content":"hello"}]}`
const mockResponseBody = `{"id":"mock-response","object":"chat.completion","model":"mock-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`

func mockModelInput(t *testing.T, kind llmnormalizer.Kind, body string) []byte {
	t.Helper()
	payload, err := json.Marshal(llmnormalizer.Input{Kind: kind, Provider: llmnormalizer.ProviderOpenAICompatible, ProviderModel: "mock-model", Endpoint: "https://provider.example.test/v1/chat/completions", ModelExchangeID: "mock-exchange", NativeBody: json.RawMessage(body)})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func mockRecords(t *testing.T, sensor string, payloads ...struct {
	typ     string
	payload []byte
}) []evidence.RawRecord {
	t.Helper()
	now := time.Unix(100, 0).UTC()
	records := make([]evidence.RawRecord, 0, len(payloads))
	prev := ""
	for i, p := range payloads {
		r := evidence.RawRecord{RunID: "run", SensorID: sensor, BootID: "mock-boot-1", SourceSeq: uint64(i + 1), ObservedWallTime: &now, RecordType: p.typ, Encoding: "json", Payload: p.payload, PreviousRecordSHA256: prev}
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

func mockRecord(t *testing.T, sensor string, seq uint64, prev, typ string, payload []byte) evidence.RawRecord {
	t.Helper()
	now := time.Unix(100, 0).UTC()
	r := evidence.RawRecord{RunID: "run", SensorID: sensor, BootID: "mock-boot-1", SourceSeq: seq, ObservedWallTime: &now, RecordType: typ, Encoding: "json", Payload: payload, PreviousRecordSHA256: prev}
	hash, err := r.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	r.RecordSHA256 = hash
	return r
}

func TestNormalizeMockMapsRawAndModelRecords(t *testing.T) {
	records := mockRecords(t, "mock-system",
		struct {
			typ     string
			payload []byte
		}{"process/exec", []byte(`{"processId":"proc-1","argv":["fixture"]}`)},
		struct {
			typ     string
			payload []byte
		}{"file/write", []byte(`{"fileId":"file-1","path":"/workspace/result.txt","bytes":3}`)},
		struct {
			typ     string
			payload []byte
		}{"dns/query", []byte(`{"queryName":"provider.example.test","queryType":"A"}`)},
	)
	provider := mockRecords(t, "mock-provider",
		struct {
			typ     string
			payload []byte
		}{"model/request", mockModelInput(t, llmnormalizer.KindRequest, mockRequestBody)},
		struct {
			typ     string
			payload []byte
		}{"model/response", mockModelInput(t, llmnormalizer.KindResponse, mockResponseBody)},
		struct {
			typ     string
			payload []byte
		}{"model/usage", mockModelInput(t, llmnormalizer.KindResponse, mockResponseBody)},
	)
	records = append(records, provider...)
	got, err := NormalizeMock(records)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != len(records) || len(got.Coverage) != len(records) {
		t.Fatalf("events=%d coverage=%d records=%d", len(got.Events), len(got.Coverage), len(records))
	}
	if got.Version != MockVersion || got.Digest != MockDigest {
		t.Fatalf("descriptor = %#v", got)
	}
	for i, record := range records {
		e := got.Events[i]
		if e.Type != record.RecordType || !e.Ignorable || e.Seq != 0 || e.Time != 0 {
			t.Fatalf("event %d = %#v", i, e)
		}
		var data events.ObservationData[json.RawMessage]
		if err := json.Unmarshal(e.Data, &data); err != nil {
			t.Fatal(err)
		}
		if data.Source.SensorType != "mock" || data.Source.Backend != "mock-data" || data.Source.BackendVersion != "phase1" || data.Source.TrustDomain != "mock" {
			t.Fatalf("event %d provenance = %#v", i, data.Source)
		}
		if data.Evidence.NormalizerVersion != MockVersion || data.Evidence.NormalizerSHA256 != MockDigest || data.Evidence.ObservationLayer != "mock" || data.Evidence.ObservationMethod != "fixture-replay" {
			t.Fatalf("event %d evidence = %#v", i, data.Evidence)
		}
		if data.Evidence.RawRecordSHA256 != record.RecordSHA256 {
			t.Fatalf("event %d lineage = %#v", i, data.Evidence)
		}
	}
	var usage events.ModelUsage
	var envelope struct {
		Details events.ModelUsage `json:"details"`
	}
	if err := json.Unmarshal(got.Events[5].Data, &envelope); err != nil {
		t.Fatal(err)
	}
	usage = envelope.Details
	if usage.InputTokens == nil || *usage.InputTokens != 7 || usage.TotalTokens == nil || *usage.TotalTokens != 10 || usage.Quality.InputTokens != "provider_reported" {
		t.Fatalf("usage = %#v", usage)
	}
	if err := evidence.ValidateRawCoverage(records, got.Coverage); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeMockRejectsInvalidInput(t *testing.T) {
	valid := func() []evidence.RawRecord {
		return mockRecords(t, "mock-system", struct {
			typ     string
			payload []byte
		}{"process/exec", []byte(`{"processId":"proc-1"}`)})
	}
	cases := []struct {
		name    string
		records func() []evidence.RawRecord
	}{
		{"unknown-type", func() []evidence.RawRecord {
			r := valid()
			r[0].RecordType = "network/connect"
			rehash(t, r)
			return r
		}},
		{"invalid-source-order", func() []evidence.RawRecord {
			r := mockRecords(t, "mock-system",
				struct {
					typ     string
					payload []byte
				}{"process/exec", []byte(`{"a":1}`)},
				struct {
					typ     string
					payload []byte
				}{"file/write", []byte(`{"b":2}`)},
			)
			r[1].SourceSeq = 7
			rehash(t, r)
			return r
		}},
		{"unknown-provider", func() []evidence.RawRecord {
			input := llmnormalizer.Input{Kind: llmnormalizer.KindRequest, Provider: "bogus", ProviderModel: "m", Endpoint: "e", ModelExchangeID: "x", NativeBody: json.RawMessage(mockRequestBody)}
			payload, _ := json.Marshal(input)
			return mockRecords(t, "mock-provider", struct {
				typ     string
				payload []byte
			}{"model/request", payload})
		}},
		{"invalid-provider-body", func() []evidence.RawRecord {
			return mockRecords(t, "mock-provider", struct {
				typ     string
				payload []byte
			}{"model/request", mockModelInput(t, llmnormalizer.KindRequest, `{"bogus":true}`)})
		}},
		{"nil-usage", func() []evidence.RawRecord {
			body := `{"id":"r","object":"chat.completion","model":"mock-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`
			return mockRecords(t, "mock-provider", struct {
				typ     string
				payload []byte
			}{"model/usage", mockModelInput(t, llmnormalizer.KindResponse, body)})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NormalizeMock(tc.records()); err == nil {
				t.Fatal("NormalizeMock succeeded")
			}
		})
	}
}

func TestNormalizeMockRejectsMismatchedRunAndBrokenModelInput(t *testing.T) {
	a := mockRecord(t, "mock-system", 1, "", "process/exec", []byte(`{"processId":"p"}`))
	b := mockRecord(t, "mock-system", 1, "", "file/write", []byte(`{"fileId":"f"}`))
	b.RunID = "other"
	rehashRecord(t, &b)
	if _, err := NormalizeMock([]evidence.RawRecord{a, b}); err == nil || !strings.Contains(err.Error(), "run ID") {
		t.Fatalf("err=%v", err)
	}
}

func rehashRecord(t *testing.T, r *evidence.RawRecord) {
	t.Helper()
	h, err := r.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	r.RecordSHA256 = h
}
