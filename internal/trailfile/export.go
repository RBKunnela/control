package trailfile

import (
	"bytes"
	"fmt"
	"io"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/lineexport"
)

const (
	// ExportFormat names the format Export writes.
	ExportFormat = brand.OTelNamespace + ".evidence-export"
	// ExportVersion is the format's version, read by the MAJOR.MINOR rules
	// of the wire contracts.
	ExportVersion = "1.1"

	// DefaultExportLimit is the records an export writes when not told.
	DefaultExportLimit = 1000
	// MaxExportLimit is the most records one export writes.
	MaxExportLimit = 100_000
)

const (
	// ErrQuery is a query the export refuses: a limit outside 1 to
	// MaxExportLimit, a negative byte bound, an empty filter value or a kind
	// the contract does not name.
	ErrQuery Error = "trailfile: the export's query is refused"
	// ErrByteBound is a next line longer than the byte bound, which no export
	// under that bound can pass.
	ErrByteBound Error = "trailfile: the next line is longer than the byte bound"
	// ErrShortRead is a file that no longer holds what it held when the
	// export opened it.
	ErrShortRead Error = "trailfile: the file no longer holds what it held when the export opened it"
)

// Query is what an export reads and how much of it.
type Query struct {
	// After is a cursor an earlier export returned; the export starts after
	// the line it names. Empty starts at the file's first byte.
	After string
	// Limit bounds the records written, every type counted.
	Limit int
	// MaxBytes bounds the bytes of whole lines read; 0 is no bound.
	MaxBytes int64
	// An event is written when it matches one value of every filter given.
	Requests, Runs, Tenants, Projects, Kinds []string
}

// Source is the file an export reads.
type Source struct {
	// Name is the file as named, which the header repeats.
	Name string
	R    io.ReaderAt
	// Size is the file's length when it was opened; nothing past it is read.
	Size int64
	// Held asks whether a writer holds the file. It is asked only when bytes
	// follow the last newline; nil answers no.
	Held func() (bool, error)
	// Key and More are lineexport.Source's: what names a segment of a log to
	// a cursor, and whether later segments hold lines.
	Key  func(lineexport.Digest) lineexport.Digest
	More bool
	// PrunedBefore is how many segments of the log before this one are gone,
	// pruned or their tombstones dropped; a single file has none.
	PrunedBefore int
}

// Trailer is what an export's trailer says.
type Trailer struct {
	// NextCursor is where the next export starts, empty when the file has no
	// whole line.
	NextCursor string
	// EndReached is every line to the last newline read, and the bytes after
	// it reported.
	EndReached bool
	// TailBytes is the bytes after the last newline, and WriterHeld whether a
	// writer held the file when it was asked.
	TailBytes  int64
	WriterHeld bool
	// The records written by type, and the bytes of the whole lines read.
	Events, Gaps, Duplicates int
	ScannedBytes             int64
}

// Gap reasons, as the gap record spells them.
const (
	gapMalformed   = "malformed"
	gapVersion     = "unsupported_version"
	gapConflict    = "conflicting_event_id"
	gapCR          = "carriage_return"
	gapPartialTail = lineexport.GapPartialTail
)

// Export writes the whole lines of src after q.After as the evidence export,
// JSON Lines framed by a header and a trailer, and returns what the trailer
// said. docs/contracts.md, "The evidence export", is the format.
//
// Each line is one record: an event, carrying the line's bytes as they stand
// but for its line ending; a gap, for a line that is not one event of a major
// this build reads, holds a carriage return before its line ending, or
// carries an event id a line this export read carries with other content; or
// a duplicate, for a line repeating one this export wrote. Duplicates and
// conflicts are found among the lines this export reads only, whatever the
// filters. The bytes after the last newline are a gap only when Held says no
// writer holds the file.
//
// A refused query or cursor writes nothing. An error after the header leaves
// the output without its trailer, which is how a reader knows it was cut.
func Export(src Source, q Query, w io.Writer) (Trailer, error) {
	return export(src, q, q.After, w)
}

// export is Export starting after the cursor after, which may not be the
// query's: a log's export past the end of one segment starts the next one at
// its first line, and the header still repeats the query asked.
func export(src Source, q Query, after string, w io.Writer) (Trailer, error) {
	f, err := q.filter()
	if err != nil {
		return Trailer{}, err
	}
	if src.Size < 0 {
		return Trailer{}, fmt.Errorf("%w: size %d", ErrLimit, src.Size)
	}
	tr, err := lineexport.Export(exportFormat(), lineexport.Source{Name: src.Name, R: src.R, Size: src.Size, Held: src.Held,
		Key: src.Key, More: src.More, PrunedBefore: src.PrunedBefore},
		lineexport.Query{After: after, Limit: q.Limit, MaxBytes: q.MaxBytes, Echo: q.echo()}, f.judge, w)
	if err != nil {
		return Trailer{}, err
	}
	return Trailer{NextCursor: tr.NextCursor, EndReached: tr.EndReached, TailBytes: tr.TailBytes, WriterHeld: tr.WriterHeld,
		Events: tr.Counts["event"], Gaps: tr.Counts[lineexport.Gap], Duplicates: tr.Counts[lineexport.Duplicate],
		ScannedBytes: tr.ScannedBytes}, nil
}

// exportFormat is the evidence export as the line export writes it.
func exportFormat() lineexport.Format {
	return lineexport.Format{Name: ExportFormat, Version: ExportVersion, Lines: []string{"event"}, IDMember: "event_id",
		Conflict: gapConflict, MaxLineBytes: evidence.MaxLineBytes, PrunedBefore: true, Refusals: lineexport.Refusals{
			CursorMalformed: ErrCursorMalformed, CursorOtherFile: ErrCursorOtherFile, CursorPastEnd: ErrCursorPastEnd,
			CursorOffLine: ErrCursorOffLine, CursorChanged: ErrCursorChanged, ShortRead: ErrShortRead, ByteBound: ErrByteBound,
		}}
}

// ExportFile exports the file at path as Export does, reading the length it
// has when opened and holding no lock, so it reads a file a collector is
// writing. Anything that is not a regular file is refused, without waiting on
// a named pipe, and so is a file in a log's directory, through a link or not,
// as ErrSegmentFile.
func ExportFile(path string, q Query, w io.Writer) (Trailer, error) {
	f, info, err := openTrail(path, "trail export")
	if err != nil {
		return Trailer{}, err
	}
	defer func() { _ = f.Close() }()
	return Export(Source{Name: path, R: f, Size: info.Size(), Held: func() (bool, error) { return heldByWriter(f) }}, q, w)
}

// judge says what record a line is: an event, a gap and why, or an event the
// filters pass by. The line export finds conflicts and duplicates by the
// event id, two lines the same only when every byte is.
func (f filter) judge(l lineexport.Line) lineexport.Verdict {
	events, err := evidence.DecodeJSONL(bytes.NewReader(l.Bytes), 1)
	if err != nil {
		return lineexport.Verdict{Type: lineexport.Gap, Reason: gapMalformed}
	}
	ev := events[0]
	if evidence.CheckEventVersion(ev) != nil {
		return lineexport.Verdict{Type: lineexport.Gap, Reason: gapVersion}
	}
	if bytes.IndexByte(l.Body(), '\r') >= 0 {
		return lineexport.Verdict{Type: lineexport.Gap, Reason: gapCR}
	}
	// A line repeating one exactly matches the filters as that one did, so a
	// duplicate is written only of an event this export wrote.
	return lineexport.Verdict{Type: "event", Pass: !f.match(ev), ID: ev.GetEventId(), Content: l.Sum}
}
