// Package lineexport writes a JSON Lines file that a writer appends to as an
// export: a header, one record per whole line up to the last newline, or to
// the last write the writer committed, and a trailer, resumable after any
// line by a cursor that holds only in the file it was taken from. A format
// names its records, supplies its refusals and judges each line; the
// reading, the bounds, the cursor and the duplicates are this package's.
package lineexport

import (
	"bytes"
	"io"
)

// Source is the file an export reads.
type Source struct {
	// Name is the file as named, which the header repeats.
	Name string
	R    io.ReaderAt
	// Size is the file's length when it was opened; nothing past it is read.
	Size int64
	// Held asks whether a writer holds the file. It is asked only when bytes
	// follow the end the export reads to; nil answers no.
	Held func() (bool, error)
	// Committed, for a file its writer appends to in writes that each end
	// at a commit, says where the last committed write ends: at a line's
	// end, at or before the last newline. The lines after it belong to a
	// write still open, are never read, and count with the bytes after the
	// last newline as the tail. Nil ends at the last newline.
	Committed func() (int64, error)
	// Identity says what the file's first line, which names it to a cursor,
	// holds; the trailer repeats it. Empty writes no such member.
	Identity string
	// Key, when set, makes what names the file to a cursor and in the
	// header's source from the digest of its first line, for a file that is
	// one of many whose first lines may be the same. Nil names it by that
	// digest.
	Key func(first Digest) Digest
	// More is a file that other lines follow, in a file after it: the
	// trailer never says the end was reached, so a reader following
	// next_cursor goes on to them.
	More bool
	// PrunedBefore is how many files before this one in a log are gone and
	// cannot be read; the header says it when the format names it.
	PrunedBefore int
}

// Query is where an export starts and how much it writes.
type Query struct {
	// After is a cursor an earlier export returned; empty starts at the
	// file's first byte.
	After string
	// Limit bounds the records written, every type counted.
	Limit int
	// MaxBytes bounds the bytes of whole lines read; 0 is no bound.
	MaxBytes int64
	// Echo is the query as the header repeats it; nil is refused, as the
	// header would read null.
	Echo any
}

// Line is one whole line a Judge is asked about.
type Line struct {
	Offset int64
	// Bytes is the line with its newline.
	Bytes []byte
	Sum   Digest
}

// Body is the line as a record carries it: without its newline and one
// carriage return before it, both whitespace and no part of the value.
func (l Line) Body() []byte {
	return bytes.TrimSuffix(l.Bytes[:len(l.Bytes)-1], []byte{'\r'})
}

// Verdict is what a Judge says a line is.
type Verdict struct {
	// Type is one of the format's Lines, or Gap with a Reason.
	Type, Reason string
	// Pass is a line of a Lines type the format's filters pass by: it writes
	// no record and takes none of the limit, and its id still counts. With no
	// Type and no ID it is a line the format writes no record for at all.
	Pass bool
	// ID is the line's id, empty for none. Two lines of one type with one id
	// are the same when their Content is, and a conflict otherwise.
	ID      string
	Content Digest
	// Refuse is a line no writer of the file leaves and no record may carry:
	// the export stops before it with this error, and writes no trailer.
	Refuse error
}

// noRecord is a line passed by that no format type names.
func (v Verdict) noRecord() bool { return v.Pass && v.Type == "" && v.ID == "" }

// Judge says what one line is.
type Judge func(Line) Verdict

// Trailer is what an export's trailer says.
type Trailer struct {
	// NextCursor is where the next export starts, empty when the file has no
	// whole line.
	NextCursor string
	// EndReached is every line to the end the export reads to read, and the
	// bytes after it reported.
	EndReached bool
	// TailBytes is the bytes after that end: after the last newline, or
	// after the last committed write. WriterHeld is whether a writer held the
	// file when it was asked.
	TailBytes  int64
	WriterHeld bool
	// Counts are the records written by type, a key for every type.
	Counts       map[string]int
	ScannedBytes int64
}

// Export writes the whole lines of src after q.After as format f, each line
// the record judge says it is, framed by a header and a trailer, and returns
// what the trailer said. A line longer than f.MaxLineBytes is a gap without
// asking judge; one whose type and id a line this export read carries with
// other content is a gap; one whose type and id a record this export wrote
// carries with the same content is a duplicate. The bytes after the last
// newline, or after src.Committed, are a gap only when Held says no writer
// holds the file.
//
// A refused format, query or cursor writes nothing. An error after the header
// leaves the output without its trailer, which is how a reader knows it was
// cut.
func Export(f Format, src Source, q Query, judge Judge, w io.Writer) (Trailer, error) {
	x, start, end, err := open(f, src, q, judge, w)
	if err != nil {
		return Trailer{}, err
	}
	if err := x.header(src.Name, src.PrunedBefore); err != nil {
		return Trailer{}, err
	}
	if err := x.scan(start, end); err != nil {
		return Trailer{}, err
	}
	if err := x.tail(end); err != nil {
		return Trailer{}, err
	}
	if src.More {
		x.tr.EndReached = false
	}
	if err := x.trailer(); err != nil {
		return Trailer{}, err
	}
	return x.tr, nil
}
