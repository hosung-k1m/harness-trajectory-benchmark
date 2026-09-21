// Package plaintext validates and reconstructs the canonical network plaintext stream.
package plaintext

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/backend"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

// ArtifactResolver returns immutable plaintext bytes for an artifact slice.
type ArtifactResolver interface {
	ReadArtifact(id string, offset, length uint64) ([]byte, error)
}

type streamKey struct{ boundary, connection, stream, direction string }
type streamState struct {
	nextSequence, nextOffset uint64
	closed                   bool
	bytes                    []byte
}

// Assembler accepts records in source sequence order and rejects loss, overlap,
// bad byte hashes and any bytes after EOF. It owns no transport decryption.
type Assembler struct {
	resolver ArtifactResolver
	streams  map[streamKey]*streamState
}

func NewAssembler() *Assembler {
	return &Assembler{streams: make(map[streamKey]*streamState)}
}

func NewAssemblerWithResolver(resolver ArtifactResolver) *Assembler {
	return &Assembler{resolver: resolver, streams: make(map[streamKey]*streamState)}
}

func (a *Assembler) Add(p events.NetworkPlaintext) error {
	if err := backend.ValidateNetworkPlaintext(p); err != nil {
		return err
	}
	k := streamKey{p.Boundary, p.ConnectionID, p.StreamID, p.Direction}
	s := a.streams[k]
	if s == nil {
		s = &streamState{nextSequence: 1}
		a.streams[k] = s
	}
	if s.closed {
		return errors.New("plaintext chunk follows end of stream")
	}
	if p.Sequence != s.nextSequence {
		return fmt.Errorf("plaintext sequence gap: got %d, want %d", p.Sequence, s.nextSequence)
	}
	b, err := a.bytes(p.Payload)
	if err != nil {
		return err
	}
	if uint64(len(b)) != p.Payload.Length {
		return errors.New("plaintext length mismatch")
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != p.Payload.SHA256 {
		return errors.New("plaintext hash mismatch")
	}
	if p.Offset != nil {
		if *p.Offset != s.nextOffset {
			return fmt.Errorf("plaintext offset gap: got %d, want %d", *p.Offset, s.nextOffset)
		}
		s.nextOffset += uint64(len(b))
	}
	s.bytes = append(s.bytes, b...)
	s.nextSequence++
	if p.EndOfStream {
		s.closed = true
	}
	return nil
}
func (a *Assembler) bytes(p events.CapturedBytes) ([]byte, error) {
	if p.Artifact == nil {
		return backend.InlinePayloadBytes(p)
	}
	if a.resolver == nil {
		return nil, errors.New("artifact payload requires resolver")
	}
	b, err := a.resolver.ReadArtifact(p.Artifact.ArtifactID, p.Artifact.Offset, p.Artifact.Length)
	if err != nil {
		return nil, err
	}
	return b, nil
}
func (a *Assembler) Bytes(connectionID, streamID, direction string) ([]byte, error) {
	k := streamKey{"sandbox", connectionID, streamID, direction}
	s := a.streams[k]
	if s == nil {
		return nil, errors.New("unknown plaintext stream")
	}
	return append([]byte(nil), s.bytes...), nil
}
func (a *Assembler) Closed(connectionID, streamID, direction string) bool {
	s := a.streams[streamKey{"sandbox", connectionID, streamID, direction}]
	return s != nil && s.closed
}

// FlowAccounting is the independently observed boundary-flow total.
type FlowAccounting struct {
	ConnectionID string `json:"connectionId"`
	StreamID     string `json:"streamId"`
	Direction    string `json:"direction"`
	Bytes        uint64 `json:"bytes"`
	SHA256       string `json:"sha256"`
	Denied       bool   `json:"denied"`
}

// ReconcileFlows requires every successful boundary direction to be an EOF-closed,
// byte-for-byte matching plaintext stream. Denied attempts must have no stream.
func (a *Assembler) ReconcileFlows(flows []FlowAccounting) error {
	seen := map[streamKey]bool{}
	for _, f := range flows {
		if f.ConnectionID == "" || f.StreamID == "" || (f.Direction != "ingress" && f.Direction != "egress") {
			return errors.New("invalid flow accounting")
		}
		k := streamKey{"sandbox", f.ConnectionID, f.StreamID, f.Direction}
		if seen[k] {
			return errors.New("duplicate flow accounting")
		}
		seen[k] = true
		s := a.streams[k]
		if f.Denied {
			if s != nil {
				return fmt.Errorf("denied flow %q/%q/%q has plaintext", f.ConnectionID, f.StreamID, f.Direction)
			}
			continue
		}
		if s == nil || !s.closed {
			return fmt.Errorf("successful flow %q/%q/%q lacks complete plaintext", f.ConnectionID, f.StreamID, f.Direction)
		}
		sum := sha256.Sum256(s.bytes)
		if uint64(len(s.bytes)) != f.Bytes || hex.EncodeToString(sum[:]) != f.SHA256 {
			return fmt.Errorf("flow %q/%q/%q does not reconcile", f.ConnectionID, f.StreamID, f.Direction)
		}
	}
	for k := range a.streams {
		if !seen[k] {
			return fmt.Errorf("plaintext stream %q/%q/%q lacks boundary flow", k.connection, k.stream, k.direction)
		}
	}
	return nil
}

// StreamKeys returns stable identifiers, useful for deterministic reports.
func (a *Assembler) StreamKeys() []string {
	out := make([]string, 0, len(a.streams))
	for k := range a.streams {
		out = append(out, k.connection+"/"+k.stream+"/"+k.direction)
	}
	sort.Strings(out)
	return out
}
