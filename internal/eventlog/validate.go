// Package eventlog validates immutable JSONL trajectories.
package eventlog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

// Validate checks gap-free sequence numbering, earlier-only lineage, payload
// discriminators, and append-only correction/late-record conventions.
func Validate(log []events.TrackedEvent) error {
	for i, e := range log {
		expected := uint64(i + 1)
		if e.Seq != expected {
			return fmt.Errorf("event %d: seq=%d, want %d", i, e.Seq, expected)
		}
		if err := events.ValidateEvent(e); err != nil {
			return fmt.Errorf("event %d (%s): %w", e.Seq, e.Type, err)
		}
		seen := make(map[uint64]struct{}, len(e.SourceEventSeqs))
		for _, source := range e.SourceEventSeqs {
			if source == 0 || source >= e.Seq {
				return fmt.Errorf("event %d: lineage reference %d is not earlier", e.Seq, source)
			}
			if _, ok := seen[source]; ok {
				return fmt.Errorf("event %d: duplicate lineage reference %d", e.Seq, source)
			}
			seen[source] = struct{}{}
		}
		if e.Type == "correction/event" || e.Type == "event/correction" {
			if err := validateCorrection(e); err != nil {
				return fmt.Errorf("event %d: %w", e.Seq, err)
			}
		}
	}
	return nil
}

// Late records are legal by design: their tail position is their durable
// order. Corrections must identify an earlier immutable record and may never
// claim to rewrite it.
func validateCorrection(e events.TrackedEvent) error {
	var d events.CorrectionData
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return err
	}
	if d.SupersedesSeq == 0 || d.SupersedesSeq >= e.Seq || d.Reason == "" {
		return fmt.Errorf("correction/event requires earlier supersedesSeq and reason")
	}
	found := false
	for _, s := range e.SourceEventSeqs {
		if s == d.SupersedesSeq {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("correction/event must include supersedesSeq in sourceEventSeqs")
	}
	return nil
}

func DecodeJSONL(r io.Reader) ([]events.TrackedEvent, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var out []events.TrackedEvent
	line := 0
	for s.Scan() {
		line++
		b := bytes.TrimSpace(s.Bytes())
		if len(b) == 0 {
			continue
		}
		var e events.TrackedEvent
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, e)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if err := Validate(out); err != nil {
		return nil, err
	}
	return out, nil
}
