package observelog

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/lineexport"
	"github.com/guardana/control/internal/observe"
)

const (
	// ExportFormat names the format Export writes.
	ExportFormat = brand.OTelNamespace + ".observation-export"
	// ExportVersion is the format's version, read by the MAJOR.MINOR rules
	// of the wire contracts.
	ExportVersion = "0.1"

	// DefaultExportLimit is the records an export writes when not told.
	DefaultExportLimit = 1000
	// MaxExportLimit is the most records one export writes.
	MaxExportLimit = 100_000
)

// Record types and gap reasons, as the export spells them.
const (
	typeObservation  = "observation"
	typeImportReport = "import_report"
	gapMalformed     = "malformed"
	gapVersion       = "unsupported_version"
	gapConflict      = "conflicting_observation_id"
	gapCR            = "carriage_return"
)

// Query is where an export starts and how much it writes.
type Query struct {
	// After is a cursor an earlier export returned; the export starts after
	// the line it names. Empty starts at the file's first byte.
	After string
	// Limit bounds the records written, every type counted.
	Limit int
	// MaxBytes bounds the bytes of whole lines read; 0 is no bound.
	MaxBytes int64
}

// queryRecord is the query as the export's header repeats it.
type queryRecord struct {
	After    string `json:"after,omitempty"`
	Limit    int    `json:"limit"`
	MaxBytes int64  `json:"max_bytes,omitempty"`
}

// Export writes the whole lines of src after q.After as the observation
// export, JSON Lines framed by a header and a trailer, and returns what the
// trailer said.
//
// Each line is one record: an observation or an import report, carrying the
// line's bytes as they stand but for its newline; a gap, for a line that is
// not one record of a version this build reads in the form the codec writes
// it, holds a carriage return anywhere, the one before its newline included,
// or carries an observation id a line this export read carries with other
// content; or a duplicate, for a line repeating a record this export wrote.
// An observation repeats another when its id and content digest do, an
// import report only when every byte does. The bytes after the last newline
// are a gap only when src.Held says no writer holds the file.
//
// A refused query or cursor writes nothing. An error after the header leaves
// the output without its trailer, which is how a reader knows it was cut.
func Export(src lineexport.Source, q Query, w io.Writer) (lineexport.Trailer, error) {
	switch {
	case q.Limit < 1 || q.Limit > MaxExportLimit:
		return lineexport.Trailer{}, fmt.Errorf("%w: limit %d, want 1 to %d", ErrQuery, q.Limit, MaxExportLimit)
	case q.MaxBytes < 0:
		return lineexport.Trailer{}, fmt.Errorf("%w: byte bound %d", ErrQuery, q.MaxBytes)
	}
	return lineexport.Export(exportFormat(), src,
		lineexport.Query{After: q.After, Limit: q.Limit, MaxBytes: q.MaxBytes,
			Echo: queryRecord(q)}, judge, w)
}

// exportFormat is the observation export as the line export writes it. A
// duplicate's id member is "id", since it names an observation id or an
// import report's line digest.
func exportFormat() lineexport.Format {
	return lineexport.Format{Name: ExportFormat, Version: ExportVersion, Lines: []string{typeObservation, typeImportReport},
		IDMember: "id", Conflict: gapConflict, MaxLineBytes: observe.MaxLineBytes, Refusals: lineexport.Refusals{
			CursorMalformed: ErrCursorMalformed, CursorOtherFile: ErrCursorOtherFile, CursorPastEnd: ErrCursorPastEnd,
			CursorOffLine: ErrCursorOffLine, CursorChanged: ErrCursorChanged, ShortRead: ErrShortRead, ByteBound: ErrByteBound,
		}}
}

// ExportFile exports the file at path as Export does, reading the length it
// has when opened and holding no lock, so it reads a log a writer holds. The
// file must pass the judgement ReadFile makes, a link at path refused as
// ErrNotRegular, without waiting on a named pipe.
//
// A log is exported to its last import report, as ReadFile reads it: the
// lines after it are a write still open, or one a crash left that the next
// Open cuts, and count with the bytes after the last newline as the tail. A
// log over MaxLogBytes, or one whose lines after that report no writer leaves,
// is never cut, so it is exported to its last newline.
func ExportFile(path string, q Query, w io.Writer) (lineexport.Trailer, error) {
	f, info, err := openJudged(path)
	if err != nil {
		return lineexport.Trailer{}, err
	}
	defer func() { _ = f.Close() }()
	return exportLog(path, f, info.Size(), func() (bool, error) { return heldByWriter(f) }, q, w)
}

// exportLog exports the first size bytes of the log r, named name, to its
// last import report when a writer's Open would cut what follows.
func exportLog(name string, r io.ReaderAt, size int64, held func() (bool, error), q Query, w io.Writer) (lineexport.Trailer, error) {
	src := lineexport.Source{Name: name, R: r, Size: size, Held: held}
	committed, cuttable, err := committedEnd(r, size)
	if err != nil {
		return lineexport.Trailer{}, err
	}
	if cuttable {
		src.Committed = func() (int64, error) { return committed, nil }
	}
	return Export(src, q, w)
}

// committedEnd is where the last write an import report closes ends in the
// first size bytes of r, and whether a writer's Open would cut what follows.
// It walks back from the last newline over the observations of a write still
// open to the report before them, so it reads the size of one write, not the
// log. A log over MaxLogBytes, a tail no writer leaves or a line of that
// write Open would refuse is never cut; damage before the last report is the
// export's to report, line by line.
func committedEnd(r io.ReaderAt, size int64) (int64, bool, error) {
	if size > MaxLogBytes {
		return 0, false, nil
	}
	end, err := lastLineEnd(r, size)
	if errors.Is(err, ErrDamaged) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	for end > 0 {
		start, line, err := lineEndingAt(r, end)
		if err != nil || line == nil {
			return 0, false, err
		}
		rec := written(line)
		switch {
		case rec == nil:
			return 0, false, nil
		case rec.GetObservation() == nil:
			return end, true, nil
		}
		end = start
	}
	return 0, true, nil
}

// written is the record line holds in the form the codec writes it, or nil
// for a line no writer of this package leaves.
func written(line []byte) *observev1.Record {
	if observe.CheckLineForm(line) != nil {
		return nil
	}
	rec, err := observe.UnmarshalLine(line)
	if err != nil {
		return nil
	}
	return rec
}

// lineEndingAt reads the whole line whose newline is the byte before end and
// returns where it starts. A line longer than a writer writes is nil.
func lineEndingAt(r io.ReaderAt, end int64) (int64, []byte, error) {
	var buf [4 << 10]byte
	start := int64(0)
	for at := end - 1; at > 0; {
		n := min(at, int64(len(buf)))
		chunk := buf[:n]
		if _, err := r.ReadAt(chunk, at-n); err != nil {
			return 0, nil, err
		}
		if i := bytes.LastIndexByte(chunk, '\n'); i >= 0 {
			start = at - n + int64(i) + 1
			break
		}
		at -= n
		if end-1-at > observe.MaxLineBytes {
			return 0, nil, nil
		}
	}
	if end-1-start > observe.MaxLineBytes {
		return 0, nil, nil
	}
	line := make([]byte, end-start)
	if _, err := r.ReadAt(line, start); err != nil {
		return 0, nil, err
	}
	return start, line, nil
}

// judge says what record a line is. An observation's id is its observation
// id and its content the digest observe.ContentDigest defines, so a line read
// again at a later receive time is a duplicate; an import report's id and
// content are its line's digest.
func judge(l lineexport.Line) lineexport.Verdict {
	r, err := observe.UnmarshalLine(l.Bytes)
	switch {
	case err != nil && (errors.Is(err, observe.ErrVersion) || unreadVersion(l.Body())):
		return lineexport.Verdict{Type: lineexport.Gap, Reason: gapVersion}
	case err != nil:
		return lineexport.Verdict{Type: lineexport.Gap, Reason: gapMalformed}
	case bytes.IndexByte(l.Bytes, '\r') >= 0:
		return lineexport.Verdict{Type: lineexport.Gap, Reason: gapCR}
	case observe.CheckLineForm(l.Bytes) != nil:
		return lineexport.Verdict{Type: lineexport.Gap, Reason: gapMalformed}
	}
	o := r.GetObservation()
	if o == nil {
		return lineexport.Verdict{Type: typeImportReport, ID: hex.EncodeToString(l.Sum[:]), Content: l.Sum}
	}
	var content lineexport.Digest
	if n, err := hex.Decode(content[:], []byte(observe.ContentDigest(o))); err != nil || n != len(content) {
		return lineexport.Verdict{Type: lineexport.Gap, Reason: gapMalformed}
	}
	return lineexport.Verdict{Type: typeObservation, ID: o.GetObservationId(), Content: content}
}

// unreadVersion reports a line the strict codec refused that names, as its
// one record's schema_version, a version outside the table. A later minor may
// add a member this build cannot name, and its line is then a version this
// build does not read rather than a malformed one.
func unreadVersion(body []byte) bool {
	var outer map[string]map[string]json.RawMessage
	if json.Unmarshal(body, &outer) != nil || len(outer) != 1 {
		return false
	}
	for kind, inner := range outer {
		if kind != "observation" && kind != "importReport" && kind != "import_report" {
			return false
		}
		for _, name := range []string{"schemaVersion", "schema_version"} {
			var v string
			if raw, ok := inner[name]; ok && json.Unmarshal(raw, &v) == nil {
				return observe.CheckVersion(v) != nil
			}
		}
	}
	return false
}
