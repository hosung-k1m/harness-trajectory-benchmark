package plaintext

import (
	"errors"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
	"testing"
)

type resolver struct{ data []byte }

func (r resolver) ReadArtifact(id string, offset, length uint64) ([]byte, error) {
	if id != "artifact" || offset != 0 || length != uint64(len(r.data)) {
		return nil, errors.New("unexpected artifact slice")
	}
	return r.data, nil
}

func chunk(seq, offset uint64, text string, eof bool) events.NetworkPlaintext {
	return events.NetworkPlaintext{Boundary: "sandbox", CapturePoint: "tap", ConnectionID: "c", StreamID: "s", Transport: "tcp", Direction: "egress", Sequence: seq, Offset: &offset, EndOfStream: eof, Protocol: events.ProtocolIdentity{Name: "raw"}, Payload: events.CapturedBytes{Encoding: "utf8", Inline: text, Length: uint64(len(text)), SHA256: backend.SHA256Hex([]byte(text))}, Capture: events.PlaintextCapture{Method: "native-plaintext", Backend: "test"}}
}
func TestAssemblerReconstructsAndReconciles(t *testing.T) {
	a := NewAssembler()
	if err := a.Add(chunk(1, 0, "hel", false)); err != nil {
		t.Fatal(err)
	}
	if err := a.Add(chunk(2, 3, "lo", true)); err != nil {
		t.Fatal(err)
	}
	got, err := a.Bytes("c", "s", "egress")
	if err != nil || string(got) != "hello" {
		t.Fatalf("got %q: %v", got, err)
	}
	if err := a.ReconcileFlows([]FlowAccounting{{ConnectionID: "c", StreamID: "s", Direction: "egress", Bytes: 5, SHA256: backend.SHA256Hex([]byte("hello"))}}); err != nil {
		t.Fatal(err)
	}
}
func TestAssemblerResolvesArtifactPayload(t *testing.T) {
	b := []byte("artifact bytes")
	p := chunk(1, 0, "", true)
	p.Payload.Artifact = &events.ArtifactSlice{ArtifactID: "artifact", Length: uint64(len(b))}
	p.Payload.Length, p.Payload.SHA256 = uint64(len(b)), backend.SHA256Hex(b)
	a := NewAssemblerWithResolver(resolver{data: b})
	if err := a.Add(p); err != nil {
		t.Fatal(err)
	}
}
func TestAssemblerRejectsGapHashAndUnclosedFlow(t *testing.T) {
	a := NewAssembler()
	if err := a.Add(chunk(2, 0, "x", false)); err == nil {
		t.Fatal("sequence gap accepted")
	}
	a = NewAssembler()
	p := chunk(1, 0, "x", false)
	p.Payload.SHA256 = backend.SHA256Hex([]byte("y"))
	if err := a.Add(p); err == nil {
		t.Fatal("bad hash accepted")
	}
	a = NewAssembler()
	if err := a.Add(chunk(1, 0, "x", false)); err != nil {
		t.Fatal(err)
	}
	if err := a.ReconcileFlows([]FlowAccounting{{ConnectionID: "c", StreamID: "s", Direction: "egress", Bytes: 1, SHA256: backend.SHA256Hex([]byte("x"))}}); err == nil {
		t.Fatal("unclosed stream accepted")
	}
}
func TestAssemblerAllowsEmptyEOF(t *testing.T) {
	a := NewAssembler()
	if err := a.Add(chunk(1, 0, "", true)); err != nil {
		t.Fatal(err)
	}
}

func TestFlowReconciliationKeepsIdentityFieldsSeparate(t *testing.T) {
	a := NewAssembler()
	one := chunk(1, 0, "one", true)
	one.ConnectionID, one.StreamID = "a\x00b", "c"
	two := chunk(1, 0, "two", true)
	two.ConnectionID, two.StreamID = "a", "b\x00c"
	if err := a.Add(one); err != nil {
		t.Fatal(err)
	}
	if err := a.Add(two); err != nil {
		t.Fatal(err)
	}
	flows := []FlowAccounting{
		{ConnectionID: one.ConnectionID, StreamID: one.StreamID, Direction: one.Direction, Bytes: 3, SHA256: backend.SHA256Hex([]byte("one"))},
		{ConnectionID: two.ConnectionID, StreamID: two.StreamID, Direction: two.Direction, Bytes: 3, SHA256: backend.SHA256Hex([]byte("two"))},
	}
	if err := a.ReconcileFlows(flows); err != nil {
		t.Fatalf("distinct flows collided: %v", err)
	}
}
