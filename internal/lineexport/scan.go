package lineexport

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
)

// seenKey is a line's type and id; each type keeps its own ids.
type seenKey struct{ typ, id string }

// seenAt is the content of the lines this export read with one type and id,
// and where the first of them it wrote is, if it wrote one. One is kept per
// distinct key among the lines scanned: the byte bound limits them when the
// query gives one, and otherwise only the file's length does, since a line
// passed by counts against no record limit.
type seenAt struct {
	offset  int64
	content Digest
	written bool
}

type exporter struct {
	f          Format
	q          Query
	judge      Judge
	in         file
	first      Digest
	identified bool
	identity   string
	out        *bufio.Writer
	seen       map[seenKey]seenAt
	tr         Trailer
}

func (x *exporter) records() int {
	n := 0
	for _, c := range x.tr.Counts {
		n += c
	}
	return n
}

// scan reads the whole lines in [start, end). A line is consumed, and the
// next cursor moves past it, only once its record is written or it is passed
// by; the limit and the byte bound stop before a line, never in it, and a
// line that would cross the bound is read no further than the bound.
func (x *exporter) scan(start, end int64) error {
	lines := bufio.NewReaderSize(io.NewSectionReader(x.in.r, start, end-start), x.f.MaxLineBytes+1)
	for offset := start; offset < end; {
		room := int64(math.MaxInt64)
		if x.q.MaxBytes > 0 {
			room = x.q.MaxBytes - x.tr.ScannedBytes
		}
		line, length, sum, err := x.readLine(lines, room)
		if err != nil {
			return err
		}
		if length > room {
			if x.tr.ScannedBytes == 0 {
				return fmt.Errorf("%w: the line at offset %d is longer than the bound %d", x.f.Refusals.ByteBound, offset, x.q.MaxBytes)
			}
			return nil
		}
		l := Line{Offset: offset, Bytes: line, Sum: sum}
		v, first, err := x.decide(l)
		if err != nil {
			return err
		}
		if !v.Pass && x.records() == x.q.Limit {
			return nil
		}
		next := cursor{First: x.first, Offset: offset + length, Line: sum}.String()
		if err := x.record(v, next, l, first); err != nil {
			return err
		}
		x.tr.ScannedBytes += length
		x.tr.NextCursor = next
		offset += length
	}
	x.tr.EndReached = true
	return nil
}

// decide is the record a line gets and, for a duplicate, the offset of the
// line it repeats. A line nil is one too long to hold. The content is checked
// before Pass is, so a conflict is a gap whatever the filters pass; a line
// whose earlier ones were all passed by is written, not a duplicate.
func (x *exporter) decide(l Line) (Verdict, int64, error) {
	if l.Bytes == nil {
		return Verdict{Type: Gap, Reason: GapTooLong}, 0, nil
	}
	v := x.judge(l)
	switch {
	case v.Refuse != nil:
		return Verdict{}, 0, fmt.Errorf("the line at offset %d: %w", l.Offset, v.Refuse)
	case v.Type == Gap && v.Reason != "":
		return Verdict{Type: Gap, Reason: v.Reason}, 0, nil
	case v.noRecord():
		return v, 0, nil
	case !x.f.carries(v.Type):
		return Verdict{}, 0, fmt.Errorf("%w: the line at offset %d was judged %q with reason %q", ErrInvalid, l.Offset, v.Type, v.Reason)
	}
	first, seen := x.seen[seenKey{v.Type, v.ID}]
	switch {
	case seen && first.content != v.Content:
		return Verdict{Type: Gap, Reason: x.f.Conflict}, 0, nil
	case v.Pass:
		return v, 0, nil
	case seen && first.written:
		return Verdict{Type: Duplicate, ID: v.ID}, first.offset, nil
	}
	return v, 0, nil
}

// record writes the record decide chose for l, none for a line passed by,
// and keeps the content of a line's id and where it was first written.
func (x *exporter) record(v Verdict, next string, l Line, first int64) error {
	k := seenKey{v.Type, v.ID}
	if at, ok := x.seen[k]; v.ID != "" && x.f.carries(v.Type) && (!ok || !at.written) {
		x.seen[k] = seenAt{offset: l.Offset, content: v.Content, written: !v.Pass}
	}
	switch {
	case v.Pass:
		return nil
	case v.Type == Gap:
		return x.gap(l.Offset, next, v.Reason)
	case v.Type == Duplicate:
		return x.duplicate(l.Offset, v.ID, first)
	}
	return x.line(v.Type, l.Offset, next, l.Body())
}

// tail reports the bytes after the end as a gap, once every whole
// line is read, when no writer holds the file. The gap takes a record, and an
// export with no room left for it has not reached the end.
func (x *exporter) tail(end int64) error {
	switch {
	case !x.tr.EndReached || x.tr.TailBytes == 0 || x.tr.WriterHeld:
		return nil
	case x.records() == x.q.Limit:
		x.tr.EndReached = false
		return nil
	}
	return x.gap(end, "", GapPartialTail)
}

// readLine reads one line and its newline, and its digest. A line longer than
// the format's bound is read through to its newline and returned nil. Once
// more than room bytes are read the line is abandoned, and only its length so
// far, past room, is returned.
func (x *exporter) readLine(r *bufio.Reader, room int64) ([]byte, int64, Digest, error) {
	h := sha256.New()
	var length int64
	for {
		chunk, err := r.ReadSlice('\n')
		h.Write(chunk)
		length += int64(len(chunk))
		switch {
		case err != nil && !errors.Is(err, bufio.ErrBufferFull):
			return nil, 0, Digest{}, fmt.Errorf("%w: no newline where the last one was: %w", x.f.Refusals.ShortRead, err)
		case length > room:
			return nil, length, Digest{}, nil
		case err != nil:
			continue
		}
		var sum Digest
		h.Sum(sum[:0])
		if length > int64(len(chunk)) {
			return nil, length, sum, nil
		}
		return chunk, length, sum, nil
	}
}
