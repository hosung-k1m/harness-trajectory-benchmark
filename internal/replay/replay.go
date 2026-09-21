// Package replay reconstructs the conversation surface without changing the
// immutable trajectory log.
package replay

import (
	"encoding/json"
	"fmt"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

// Replayer applies only explicit surface operations. This permits observed
// events to coexist in the same log without entering model context.
type Replayer struct{ surface []events.TrackedEvent }

func (r *Replayer) Apply(e events.TrackedEvent) error {
	if err := events.ValidateSurfaceOp(e.SurfaceOp); err != nil {
		return err
	}
	if len(e.SurfaceOp) == 0 {
		return nil
	}
	var op string
	if err := json.Unmarshal(e.SurfaceOp, &op); err == nil {
		if op != "append" {
			return fmt.Errorf("unsupported surface operation %q", op)
		}
		r.surface = append(r.surface, e)
		return nil
	}
	var replace events.ReplaceSurfaceOp
	if err := json.Unmarshal(e.SurfaceOp, &replace); err != nil {
		return err
	}
	kept := r.surface[:0]
	for _, prior := range r.surface {
		if prior.Seq < replace.Start || prior.Seq > replace.End {
			kept = append(kept, prior)
		}
	}
	r.surface = append(kept, e)
	return nil
}

func (r *Replayer) Surface() []events.TrackedEvent {
	return append([]events.TrackedEvent(nil), r.surface...)
}

func Replay(log []events.TrackedEvent) ([]events.TrackedEvent, error) {
	var r Replayer
	for _, e := range log {
		if err := r.Apply(e); err != nil {
			return nil, err
		}
	}
	return r.Surface(), nil
}
