// Package appender owns the durable, globally ordered TrackedEvent log for a run.
package appender

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/events"
)

var (
	// ErrSealed means the log was sealed and can no longer accept events.
	ErrSealed = errors.New("tracked event log is sealed")
	// ErrClosed means the appender has been closed.
	ErrClosed = errors.New("tracked event appender is closed")
)

// Appender is a process-local single writer for one durable JSONL event log.
// It serializes callers, assigns the only global sequence numbers, and does
// not acknowledge a record until its exact frame has been synced to storage.
type Appender struct {
	mu       sync.Mutex
	path     string
	sealPath string
	file     *os.File
	events   []events.TrackedEvent
	head     [sha256.Size]byte
	nextSeq  uint64
	sealed   bool
	closed   bool
	now      func() time.Time
}

// Open recovers an existing log, or creates an empty log at path. Existing
// bytes are validated as exact newline-terminated JSONL frames before the log
// is made appendable. A malformed or partial tail is never repaired silently.
func Open(path string) (*Appender, error) {
	if path == "" {
		return nil, errors.New("log path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open tracked event log: %w", err)
	}
	a := &Appender{
		path:     path,
		sealPath: path + ".sealed",
		file:     f,
		nextSeq:  1,
		now:      time.Now,
	}
	if err := a.recover(); err != nil {
		_ = f.Close()
		return nil, err
	}
	if marker, err := os.ReadFile(a.sealPath); err == nil {
		if string(marker) != a.hashHead()+"\n" {
			_ = f.Close()
			return nil, errors.New("seal marker does not match tracked event hash head")
		}
		a.sealed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = f.Close()
		return nil, fmt.Errorf("inspect seal marker: %w", err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("seek tracked event log: %w", err)
	}
	return a, nil
}

// New is an alias for Open.
func New(path string) (*Appender, error) { return Open(path) }

func (a *Appender) recover() error {
	b, err := io.ReadAll(a.file)
	if err != nil {
		return fmt.Errorf("read tracked event log: %w", err)
	}
	recovered, head, err := ValidateFrames(b)
	if err != nil {
		return err
	}
	decoded, _ := hex.DecodeString(head)
	copy(a.head[:], decoded)
	a.events = recovered
	a.nextSeq = uint64(len(recovered)) + 1
	return nil
}

// ValidateFrames validates exact newline-terminated JSONL frames and returns
// the recovered events with their SHA-256 chain head, without opening or
// mutating any file.
func ValidateFrames(b []byte) ([]events.TrackedEvent, string, error) {
	var head [sha256.Size]byte
	var recovered []events.TrackedEvent
	if len(b) == 0 {
		return recovered, hex.EncodeToString(head[:]), nil
	}
	if b[len(b)-1] != '\n' {
		return nil, "", errors.New("tracked event log has a partial final frame")
	}
	for offset, frameNumber := 0, 1; offset < len(b); frameNumber++ {
		end := bytes.IndexByte(b[offset:], '\n')
		if end < 0 { // guarded above; keep recovery fail-closed if changed.
			return nil, "", fmt.Errorf("frame %d is unterminated", frameNumber)
		}
		end += offset + 1
		frame := b[offset:end]
		payload := frame[:len(frame)-1]
		if len(payload) == 0 {
			return nil, "", fmt.Errorf("frame %d is empty", frameNumber)
		}
		var event events.TrackedEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, "", fmt.Errorf("frame %d is invalid JSON: %w", frameNumber, err)
		}
		if event.Seq != uint64(frameNumber) {
			return nil, "", fmt.Errorf("frame %d has seq %d, want %d", frameNumber, event.Seq, frameNumber)
		}
		if err := events.ValidateEvent(event); err != nil {
			return nil, "", fmt.Errorf("frame %d: %w", frameNumber, err)
		}
		if err := validateLineage(event); err != nil {
			return nil, "", fmt.Errorf("frame %d: %w", frameNumber, err)
		}
		head = chain(head, frame)
		recovered = append(recovered, event)
		offset = end
	}
	return recovered, hex.EncodeToString(head[:]), nil
}

// Append assigns Seq and Time to event, validates the resulting envelope, and
// durably appends one deterministic JSONL frame. Callers must not preassign
// either field: accepting them would create a second sequence/time authority.
func (a *Appender) Append(event events.TrackedEvent) (events.TrackedEvent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return events.TrackedEvent{}, ErrClosed
	}
	if a.sealed {
		return events.TrackedEvent{}, ErrSealed
	}
	if event.Seq != 0 {
		return events.TrackedEvent{}, errors.New("caller must not assign seq")
	}
	if event.Time != 0 {
		return events.TrackedEvent{}, errors.New("caller must not assign time")
	}
	event.Seq = a.nextSeq
	event.Time = a.now().UnixMilli()
	if err := events.ValidateEvent(event); err != nil {
		return events.TrackedEvent{}, fmt.Errorf("validate event: %w", err)
	}
	if err := validateLineage(event); err != nil {
		return events.TrackedEvent{}, err
	}
	frame, err := json.Marshal(event)
	if err != nil {
		return events.TrackedEvent{}, fmt.Errorf("encode event: %w", err)
	}
	frame = append(frame, '\n')
	if err := writeAll(a.file, frame); err != nil {
		return events.TrackedEvent{}, fmt.Errorf("write event frame: %w", err)
	}
	if err := a.file.Sync(); err != nil {
		return events.TrackedEvent{}, fmt.Errorf("sync event frame: %w", err)
	}
	a.head = chain(a.head, frame)
	a.events = append(a.events, cloneEvent(event))
	a.nextSeq++
	return cloneEvent(event), nil
}

// Snapshot returns a copy of the events currently acknowledged by the
// appender. It is safe to call while appends are in progress.
func (a *Appender) Snapshot() []events.TrackedEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]events.TrackedEvent, len(a.events))
	for i, event := range a.events {
		out[i] = cloneEvent(event)
	}
	return out
}

// Export returns the exact acknowledged JSONL bytes, without re-encoding the
// events. This preserves the frame bytes bound by HashHead.
func (a *Appender) Export() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return os.ReadFile(a.path)
}

// Since returns acknowledged events with a sequence number greater than seq.
// It is suitable for a polling/following reader without exposing mutable state.
func (a *Appender) Since(seq uint64) []events.TrackedEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	if seq >= uint64(len(a.events)) {
		return []events.TrackedEvent{}
	}
	start := int(seq)
	out := make([]events.TrackedEvent, len(a.events)-start)
	for i, event := range a.events[start:] {
		out[i] = cloneEvent(event)
	}
	return out
}

// NextSeq returns the next global sequence number that would be assigned.
func (a *Appender) NextSeq() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nextSeq
}

// HashHead returns the SHA-256 hash-chain head over exact persisted frames.
// The empty log head is 32 zero bytes, encoded as lower-case hexadecimal.
func (a *Appender) HashHead() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return hex.EncodeToString(a.head[:])
}

// Seal durably records that no further event may be appended, including after
// a restart. It first syncs the log and then syncs its seal marker.
func (a *Appender) Seal() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	if a.sealed {
		return nil
	}
	if err := a.file.Sync(); err != nil {
		return fmt.Errorf("sync before seal: %w", err)
	}
	marker, err := os.OpenFile(a.sealPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create seal marker: %w", err)
		}
		existing, readErr := os.ReadFile(a.sealPath)
		if readErr != nil {
			return fmt.Errorf("read existing seal marker: %w", readErr)
		}
		if string(existing) != a.hashHead()+"\n" {
			return errors.New("existing seal marker does not match tracked event hash head")
		}
	} else {
		if _, err := marker.WriteString(a.hashHead() + "\n"); err != nil {
			_ = marker.Close()
			return fmt.Errorf("write seal marker: %w", err)
		}
		if err := marker.Sync(); err != nil {
			_ = marker.Close()
			return fmt.Errorf("sync seal marker: %w", err)
		}
		if err := marker.Close(); err != nil {
			return fmt.Errorf("close seal marker: %w", err)
		}
	}
	dir, err := os.Open(filepath.Dir(a.sealPath))
	if err != nil {
		return fmt.Errorf("open seal marker directory: %w", err)
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return fmt.Errorf("sync seal marker directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close seal marker directory: %w", err)
	}
	a.sealed = true
	return nil
}

func (a *Appender) Sealed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sealed
}

// hashHead is for callers already holding a.mu.
func (a *Appender) hashHead() string { return hex.EncodeToString(a.head[:]) }

// Close syncs and closes the log. It prevents further appends on this object;
// use Seal when that prohibition must survive reopening the same log.
func (a *Appender) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	if err := a.file.Sync(); err != nil {
		return fmt.Errorf("sync before close: %w", err)
	}
	if err := a.file.Close(); err != nil {
		return fmt.Errorf("close tracked event log: %w", err)
	}
	a.closed = true
	return nil
}

func validateLineage(event events.TrackedEvent) error {
	seen := make(map[uint64]struct{}, len(event.SourceEventSeqs))
	for _, source := range event.SourceEventSeqs {
		if source == 0 || source >= event.Seq {
			return fmt.Errorf("lineage reference %d is not earlier than seq %d", source, event.Seq)
		}
		if _, ok := seen[source]; ok {
			return fmt.Errorf("duplicate lineage reference %d", source)
		}
		seen[source] = struct{}{}
	}
	return nil
}

func chain(previous [sha256.Size]byte, frame []byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write(previous[:])
	_, _ = h.Write(frame)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func cloneEvent(event events.TrackedEvent) events.TrackedEvent {
	clone := event
	clone.Data = append(json.RawMessage(nil), event.Data...)
	clone.SourceEventSeqs = append([]uint64(nil), event.SourceEventSeqs...)
	clone.SurfaceOp = append(json.RawMessage(nil), event.SurfaceOp...)
	return clone
}
