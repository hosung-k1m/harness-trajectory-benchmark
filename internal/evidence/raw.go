// Package evidence implements byte-exact raw evidence and sealing contracts.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"path"
	"sort"
	"strings"
	"time"
)

const rawFrameMagic = "HTBRAW1\x00"

// RawRecord is stored as a binary frame; JSON is only a transport projection.
// RecordSHA256 is deliberately excluded from Frame to avoid self-reference.
type RawRecord struct {
	RunID                string     `json:"runId"`
	SensorID             string     `json:"sensorId"`
	BootID               string     `json:"bootId"`
	SourceSeq            uint64     `json:"sourceSeq"`
	ObservedMonotonicNS  *uint64    `json:"observedMonotonicNs"`
	ObservedWallTime     *time.Time `json:"observedWallTime"`
	RecordType           string     `json:"recordType"`
	Encoding             string     `json:"encoding"`
	Payload              []byte     `json:"payload"`
	PreviousRecordSHA256 string     `json:"previousRecordSha256"`
	RecordSHA256         string     `json:"recordSha256"`
}

// Frame is deterministic: magic, then length-prefixed UTF-8 fields, integer fields
// in big endian, and explicit presence tags for optional time fields.
func (r RawRecord) Frame() ([]byte, error) {
	if r.RunID == "" || r.SensorID == "" || r.BootID == "" || r.RecordType == "" || r.Encoding == "" {
		return nil, errors.New("raw record has missing identity or type")
	}
	if r.PreviousRecordSHA256 != "" && !validHash(r.PreviousRecordSHA256) {
		return nil, errors.New("invalid previous record hash")
	}
	b := bytes.NewBuffer(make([]byte, 0, len(r.Payload)+128))
	b.WriteString(rawFrameMagic)
	for _, v := range []string{r.RunID, r.SensorID, r.BootID} {
		if err := writeString(b, v); err != nil {
			return nil, err
		}
	}
	writeU64(b, r.SourceSeq)
	if r.ObservedMonotonicNS == nil {
		b.WriteByte(0)
	} else {
		b.WriteByte(1)
		writeU64(b, *r.ObservedMonotonicNS)
	}
	if r.ObservedWallTime == nil {
		b.WriteByte(0)
	} else {
		b.WriteByte(1)
		writeI64(b, r.ObservedWallTime.UTC().UnixNano())
	}
	for _, v := range []string{r.RecordType, r.Encoding, r.PreviousRecordSHA256} {
		if err := writeString(b, v); err != nil {
			return nil, err
		}
	}
	if err := writeBytes(b, r.Payload); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func (r RawRecord) ComputedHash() (string, error) {
	f, err := r.Frame()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(f)
	return hex.EncodeToString(h[:]), nil
}
func (r RawRecord) Validate() error {
	if r.SourceSeq == 0 {
		return errors.New("raw record source sequence must be positive")
	}
	h, err := r.ComputedHash()
	if err != nil {
		return err
	}
	if !validHash(r.RecordSHA256) || r.RecordSHA256 != h {
		return errors.New("raw record hash does not match exact frame")
	}
	return nil
}

// ChainSeed binds a new sensor chain to the run inputs and sensor identity.
func ChainSeed(runSpecDigest, planDigest, sensorID, bootID string) (string, error) {
	if !validHash(runSpecDigest) || !validHash(planDigest) || sensorID == "" || bootID == "" {
		return "", errors.New("invalid chain seed inputs")
	}
	h := sha256.New()
	h.Write([]byte("HTB/chain-seed/v1\x00"))
	for _, v := range []string{runSpecDigest, planDigest, sensorID, bootID} {
		if err := writeHashField(h, v); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ChainedHash is Hn = SHA-256(Hn-1 bytes || exact raw frame).
func ChainedHash(previousChainHash string, frame []byte) (string, error) {
	if !validHash(previousChainHash) {
		return "", errors.New("invalid previous chain hash")
	}
	prev, _ := hex.DecodeString(previousChainHash)
	h := sha256.New()
	h.Write(prev)
	h.Write(frame)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ValidateChain checks source identity, strict source sequence, record integrity and the external chain head.
func ValidateChain(records []RawRecord, seed string) (string, error) {
	if !validHash(seed) {
		return "", errors.New("invalid chain seed")
	}
	if len(records) == 0 {
		return seed, nil
	}
	previous := seed
	var priorSeq uint64
	var sensor, boot, run string
	for i, r := range records {
		if err := r.Validate(); err != nil {
			return "", fmt.Errorf("record %d: %w", i, err)
		}
		if i == 0 {
			if r.SourceSeq != 1 || r.PreviousRecordSHA256 != "" {
				return "", errors.New("first record must have source sequence 1 and no previous record hash")
			}
			sensor, boot, run = r.SensorID, r.BootID, r.RunID
		} else if r.SensorID != sensor || r.BootID != boot || r.RunID != run || priorSeq == math.MaxUint64 || r.SourceSeq != priorSeq+1 {
			return "", fmt.Errorf("record %d breaks source identity or sequence", i)
		}
		if i > 0 && r.PreviousRecordSHA256 != records[i-1].RecordSHA256 {
			return "", fmt.Errorf("record %d previous record hash mismatch", i)
		}
		frame, err := r.Frame()
		if err != nil {
			return "", fmt.Errorf("record %d frame: %w", i, err)
		}
		previous, err = ChainedHash(previous, frame)
		if err != nil {
			return "", err
		}
		priorSeq = r.SourceSeq
	}
	return previous, nil
}

type RawRange struct {
	SensorID string `json:"sensorId"`
	BootID   string `json:"bootId"`
	Start    uint64 `json:"start"`
	End      uint64 `json:"end"`
}

// RawSource identifies one sensor process without delimiter-based key encoding.
type RawSource struct {
	SensorID string
	BootID   string
}

type NormalizedCoverage struct {
	Raw     RawRange `json:"raw"`
	EventID string   `json:"eventId,omitempty"`
	BatchID string   `json:"batchId,omitempty"`
}

// ValidateRawCoverage proves every supplied raw record belongs to exactly one normalized event or explicit batch.
func ValidateRawCoverage(records []RawRecord, coverage []NormalizedCoverage) error {
	type interval struct{ start, end uint64 }
	ranges := map[RawSource][]interval{}
	for _, c := range coverage {
		if c.Raw.SensorID == "" || c.Raw.BootID == "" || c.Raw.Start == 0 || c.Raw.End < c.Raw.Start || (c.EventID == "") == (c.BatchID == "") {
			return errors.New("invalid normalized coverage")
		}
		key := RawSource{SensorID: c.Raw.SensorID, BootID: c.Raw.BootID}
		ranges[key] = append(ranges[key], interval{c.Raw.Start, c.Raw.End})
	}
	sequences := map[RawSource][]uint64{}
	for _, r := range records {
		if r.SensorID == "" || r.BootID == "" || r.SourceSeq == 0 {
			return errors.New("malformed raw record coverage identity")
		}
		key := RawSource{SensorID: r.SensorID, BootID: r.BootID}
		sequences[key] = append(sequences[key], r.SourceSeq)
	}
	for source, sourceRanges := range ranges {
		seqs := sequences[source]
		if len(seqs) == 0 {
			return fmt.Errorf("coverage references unknown raw source %q/%q", source.SensorID, source.BootID)
		}
		sort.Slice(sourceRanges, func(i, j int) bool { return sourceRanges[i].start < sourceRanges[j].start })
		for i := 1; i < len(sourceRanges); i++ {
			if sourceRanges[i].start <= sourceRanges[i-1].end {
				return errors.New("overlapping normalized coverage")
			}
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		for i := 1; i < len(seqs); i++ {
			if seqs[i] == seqs[i-1] {
				return errors.New("duplicate raw record")
			}
		}
		pos := 0
		for _, r := range sourceRanges {
			if pos >= len(seqs) || seqs[pos] != r.start {
				return errors.New("coverage references missing raw record")
			}
			width := r.end - r.start + 1 // start is non-zero, so this cannot wrap.
			if width > uint64(len(seqs)-pos) {
				return errors.New("coverage references missing raw record")
			}
			for i := uint64(0); i < width; i++ {
				if seqs[pos+int(i)] != r.start+i {
					return errors.New("coverage references missing raw record")
				}
			}
			pos += int(width)
		}
		if pos != len(seqs) {
			return errors.New("raw record lacks normalized coverage")
		}
	}
	for source := range sequences {
		if _, ok := ranges[source]; !ok {
			return fmt.Errorf("raw records for %q/%q lack normalized coverage", source.SensorID, source.BootID)
		}
	}
	return nil
}

type ArtifactDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
}
type RunEvidenceManifest struct {
	SchemaVersion            string            `json:"schemaVersion"`
	RunID                    string            `json:"runId"`
	RunSpecDigest            string            `json:"runSpecDigest"`
	ObservationPlanDigest    string            `json:"observationPlanDigest"`
	CapabilityManifestDigest string            `json:"capabilityManifestDigest"`
	SensorHealthDigest       string            `json:"sensorHealthDigest"`
	TrackedEventChainHead    string            `json:"trackedEventChainHead"`
	RawChainHeads            map[string]string `json:"rawChainHeads"`
	Artifacts                []ArtifactDigest  `json:"artifacts"`
	MerkleRoot               string            `json:"merkleRoot"`
	Signature                string            `json:"signature,omitempty"`
	SignatureFormat          string            `json:"signatureFormat,omitempty"`
	SealedAt                 time.Time         `json:"sealedAt"`
}

func (m RunEvidenceManifest) Validate() error {
	if m.SchemaVersion == "" || m.RunID == "" || !validHash(m.RunSpecDigest) || !validHash(m.ObservationPlanDigest) || !validHash(m.CapabilityManifestDigest) || !validHash(m.SensorHealthDigest) || !validHash(m.TrackedEventChainHead) || !validHash(m.MerkleRoot) || m.SealedAt.IsZero() {
		return errors.New("invalid evidence manifest identity or digest")
	}
	for k, v := range m.RawChainHeads {
		if k == "" || !validHash(v) {
			return errors.New("invalid raw chain head")
		}
	}
	seenArtifacts := make(map[string]struct{}, len(m.Artifacts))
	for _, a := range m.Artifacts {
		if !validArtifactPath(a.Path) || !validHash(a.SHA256) {
			return errors.New("invalid artifact digest")
		}
		if _, exists := seenArtifacts[a.Path]; exists {
			return errors.New("duplicate artifact path")
		}
		seenArtifacts[a.Path] = struct{}{}
	}
	return nil
}

func validArtifactPath(value string) bool {
	return value != "" && value != "." && !strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") && path.Clean(value) == value && !strings.HasPrefix(value, "../")
}

// ComputeMerkleRoot produces a deterministic binary Merkle root over leaf digests.
func ComputeMerkleRoot(digests []string) (string, error) {
	if len(digests) == 0 {
		return "", errors.New("merkle root needs leaves")
	}
	leaves := append([]string(nil), digests...)
	for _, d := range leaves {
		if !validHash(d) {
			return "", errors.New("invalid merkle leaf")
		}
	}
	sort.Strings(leaves)
	for len(leaves) > 1 {
		next := make([]string, 0, (len(leaves)+1)/2)
		for i := 0; i < len(leaves); i += 2 {
			right := leaves[i]
			if i+1 < len(leaves) {
				right = leaves[i+1]
			}
			l, _ := hex.DecodeString(leaves[i])
			r, _ := hex.DecodeString(right)
			h := sha256.New()
			h.Write(l)
			h.Write(r)
			next = append(next, hex.EncodeToString(h.Sum(nil)))
		}
		leaves = next
	}
	return leaves[0], nil
}

func writeU64(b *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	b.Write(x[:])
}
func writeI64(b *bytes.Buffer, v int64)           { writeU64(b, uint64(v)) }
func writeString(b *bytes.Buffer, s string) error { return writeBytes(b, []byte(s)) }
func writeBytes(b *bytes.Buffer, p []byte) error {
	if uint64(len(p)) > math.MaxUint32 {
		return errors.New("raw frame field exceeds uint32 length")
	}
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], uint32(len(p)))
	b.Write(x[:])
	b.Write(p)
	return nil
}
func writeHashField(h interface{ Write([]byte) (int, error) }, value string) error {
	if uint64(len(value)) > math.MaxUint32 {
		return errors.New("chain seed field exceeds uint32 length")
	}
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], uint32(len(value)))
	_, _ = h.Write(x[:])
	_, _ = h.Write([]byte(value))
	return nil
}
func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
