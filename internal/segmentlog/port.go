package segmentlog

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Digest is the SHA-256 of one line, its newline included: the digest an
// evidence export's cursor names a file's first line by.
type Digest = [sha256.Size]byte

// RecordLog keeps whole lines in segments. Append returns nil only once the
// lines are durable. Every method of a log that is closed, or that a seal or
// a prune left part way, refuses.
type RecordLog interface {
	// Append writes whole lines to the live segment, sealing it first when
	// they would take it past its byte bound, and refuses them with
	// ErrBudget when they would take the log past its own.
	Append(ctx context.Context, lines []byte) error
	// Seal seals the live segment; a live segment with no line stays.
	Seal() error
	// Prune prunes the sealed segments numbered through, and every one
	// before it: the tombstone is written before a file is unlinked.
	Prune(through int) error
	// Locate answers what the segment key names is now, key being
	// SegmentKey of its number and its first line. Its zero value is Unknown.
	Locate(key Digest) SegmentAnswer
	// Manifest is the log as its manifest and live segment hold it.
	Manifest() Manifest
	Close() error
}

// KindSegments is the default kind: segment files and a manifest in one
// directory.
const KindSegments = "segments"

// LiveFile is the live segment's file as the log's consumer opens it, which
// judges what the file may hold and cuts what a crash left of a last line.
type LiveFile interface {
	// AppendLines writes whole lines at the end of the file and returns nil
	// once they are synced; a failed append leaves the file as it was, or
	// its error matches ErrLiveChanged.
	AppendLines(ctx context.Context, lines []byte) error
	Close() error
}

// Config is what a log opens with.
type Config struct {
	// Kind is the log's kind; only KindSegments is known.
	Kind string
	// Dir is the log's directory, created mode 0700 when absent.
	Dir string
	// Tenant and Project bind the log: a new log records them, and an
	// existing one bound to another is refused.
	Tenant, Project string
	// SegmentBytes bounds a live segment before it is sealed, and MaxBytes
	// the bytes of every segment not pruned. Both zero refuses every append;
	// otherwise MaxBytes is at least twice SegmentBytes. A live segment
	// holding a line is sealed before an append would pass SegmentBytes,
	// whatever the bound then says, so a full log holds a sealed segment an
	// operator can prune unless one append alone is over MaxBytes.
	SegmentBytes, MaxBytes int64
	// MaxLineBytes bounds a line before its newline; a longer one in a
	// segment refuses the open.
	MaxLineBytes int
	// OpenLive opens the live segment by name in the directory root holds,
	// the one the log judged and locked, creating it when absent.
	OpenLive func(root *os.Root, name string) (LiveFile, error)
	// Visit, when set, is handed every whole line the log holds at open,
	// sealed segments first and in order; an error refuses the open.
	Visit func(line []byte) error
	// Now is the clock seals and prunes are dated by.
	Now func() time.Time
}

// Open opens the log cfg names, of the kind it names.
func Open(cfg Config) (RecordLog, error) {
	switch cfg.Kind {
	case KindSegments:
		l, err := openSegments(cfg)
		if err != nil {
			return nil, err
		}
		return l, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrKind, cfg.Kind)
	}
}

// State is what a segment is.
type State uint8

const (
	// StateUnknown is a segment the log does not name, or names more than
	// once. It is the zero value.
	StateUnknown State = iota
	// StateLive is the segment appends go to.
	StateLive
	// StateSealed is a segment no append changes.
	StateSealed
	// StatePruned is a sealed segment an operator removed; its tombstone
	// keeps what it held.
	StatePruned
)

// String names the state as the manifest spells it.
func (s State) String() string {
	switch s {
	case StateLive:
		return "live"
	case StateSealed:
		return "sealed"
	case StatePruned:
		return "pruned"
	default:
		return "unknown"
	}
}

// Segment is what the log knows of one segment.
type Segment struct {
	// Seq numbers the segment from 1, in the order it was sealed, and is
	// never given again.
	Seq   int
	State State
	// Lines and Bytes are its whole lines and their bytes; First and Last the
	// digests of its first and last line.
	Lines, Bytes int64
	First, Last  Digest
	// SealedAt and PrunedAt date the seal and the prune; the live segment
	// has neither.
	SealedAt, PrunedAt time.Time
	// File is the segment's file name in the log's directory, empty once
	// pruned.
	File string
}

// Manifest is the log at one moment.
type Manifest struct {
	Tenant, Project string
	// Dropped is how many of the first segments were pruned and their
	// tombstones dropped, to keep the manifest within MaxSegments entries;
	// Segments are the sealed and pruned segments after them, by Seq. Live
	// is the live segment, with no line when Live.Lines is 0.
	Dropped  int
	Segments []Segment
	Live     Segment
	// Retained is the bytes of every segment not pruned, the live one's whole
	// lines included.
	Retained int64
}

// SegmentAnswer is what Locate found. Its zero value is Unknown.
type SegmentAnswer struct {
	state State
	cause string
	seg   Segment
}

// State is the segment's state, StateUnknown when no segment the log names
// has the key.
func (a SegmentAnswer) State() State { return a.state }

// Cause says why the answer is Unknown.
func (a SegmentAnswer) Cause() string {
	if a.state == StateUnknown && a.cause == "" {
		return "nothing was located"
	}
	return a.cause
}

// Segment is what the log knows of the segment, for an answer that is not
// Unknown.
func (a SegmentAnswer) Segment() Segment {
	if a.state == StateUnknown {
		return Segment{}
	}
	return a.seg
}

// keyPrefix starts what a segment's key is the SHA-256 of.
const keyPrefix = ManifestFormat + "/"

// SegmentKey is what names segment seq whose first line has the digest first
// to a reader: the SHA-256 of ManifestFormat, "/", seq in decimal, "/" and
// the 32 bytes of first. A segment keeps its key when it is sealed,
// and no two segments of one log have one, as no number is given twice.
func SegmentKey(seq int, first Digest) Digest {
	b := append(strconv.AppendInt([]byte(keyPrefix), int64(seq), 10), '/')
	return sha256.Sum256(append(b, first[:]...))
}

// locate answers for key among segs and live.
func locate(segs []Segment, live Segment, key Digest) SegmentAnswer {
	for _, s := range segs {
		if SegmentKey(s.Seq, s.First) == key {
			return SegmentAnswer{state: s.State, seg: s}
		}
	}
	if live.Lines > 0 && SegmentKey(live.Seq, live.First) == key {
		return SegmentAnswer{state: StateLive, seg: live}
	}
	return SegmentAnswer{cause: "no segment this log names has that key"}
}
