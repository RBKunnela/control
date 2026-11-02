package coverage

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/pkg/contract"
)

const (
	exportFormat = brand.OTelNamespace + ".evidence-export"
	exportMajor  = "1"
	// maxExportLineBytes bounds one record before its newline: the trail's
	// own line bound and room for the members the export wraps it in.
	maxExportLineBytes = 3*contract.MaxEnvelopeBytes + 4096
)

// Export is one evidence export (ADR-0035) as the join reads it.
type Export struct {
	// File is the trail file the header names.
	File string
	// Whole is true when the export holds every line of its file: a trailer
	// that reached the end, no gap, no segment of its log pruned before it,
	// no cursor to start after and no filter.
	Whole bool
	// NotWhole says why Whole is false.
	NotWhole string
	// Events counts the event records.
	Events int

	// proposals are the ACTION_PROPOSED events by their envelope's trace
	// and span id; one with either id empty joins nothing and is not kept.
	// refused holds, by the same ids, those whose envelope the contract
	// refuses for more than a missing effect class: they join nothing and
	// leave the observation of the call they name not checked.
	proposals        map[proposalKey][]*controlv1.Event
	refused          map[proposalKey][]*controlv1.Event
	earliest, latest time.Time
	window           bool
}

type proposalKey struct{ trace, span string }

// ReadExport reads an evidence export as the gateway's trail export writes
// it. An export cut short, stopped early, gapped, resumed or filtered reads,
// and says it is not whole; a line that is not a record of the format, an
// unknown record type, another format or major, or an event that does not
// decode is refused with ErrExport.
func ReadExport(r io.Reader) (*Export, error) {
	x, _, err := readExport(r, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExport, err)
	}
	return x, nil
}

// ReadExportEvents reads an export as ReadExport does, and returns its events
// in order as that read decoded them.
func ReadExportEvents(r io.Reader) (*Export, []*controlv1.Event, error) {
	x, events, err := readExport(r, true)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrExport, err)
	}
	return x, events, nil
}

// exportReader is one read in progress: what the records said so far.
type exportReader struct {
	x          *Export
	header     bool
	trailer    bool
	endReached bool
	after      bool
	filtered   bool
	// source is the header naming one: the file holds a whole line.
	source bool
	// tail is a partial tail gap read, after which only the trailer comes.
	tail bool
	// prunedBefore is the segments of the log before the exported one that
	// are gone; a 1.0 header, which never names it, has none.
	prunedBefore uint64
	counts       map[string]int
	// keep says to keep the events read, in events.
	keep   bool
	events []*controlv1.Event
}

func readExport(r io.Reader, keep bool) (*Export, []*controlv1.Event, error) {
	// Behind an interface, so a caller's large bufio.Reader is not taken as
	// the buffer and the line bound stays this package's.
	in := bufio.NewReaderSize(struct{ io.Reader }{r}, maxExportLineBytes+1)
	er := &exportReader{x: &Export{proposals: map[proposalKey][]*controlv1.Event{}, refused: map[proposalKey][]*controlv1.Event{}}, counts: map[string]int{}, keep: keep}
	for number := 1; ; number++ {
		line, err := in.ReadSlice('\n')
		done, err := er.line(line, err)
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: %w", number, err)
		}
		if done {
			break
		}
	}
	if !er.header {
		return nil, nil, errors.New("no header")
	}
	er.x.NotWhole = er.notWhole()
	er.x.Whole = er.x.NotWhole == ""
	return er.x, er.events, nil
}

// line takes one ReadSlice result and reports whether the input ended.
func (er *exportReader) line(line []byte, err error) (bool, error) {
	atEOF := err == io.EOF //nolint:errorlint // a reader's error wrapping io.EOF is a failure, not the end
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return true, fmt.Errorf("over %d bytes", maxExportLineBytes)
	case err != nil && !atEOF:
		return true, err
	case atEOF && len(line) > 0 && er.trailer:
		return true, errors.New("bytes after the trailer")
	case atEOF:
		// Bytes no newline ends before any trailer: the export was cut
		// short, and the missing trailer says so.
		return true, nil
	}
	return false, er.record(line[:len(line)-1])
}

func (er *exportReader) notWhole() string {
	switch {
	case !er.trailer:
		return "it has no trailer: it was cut short"
	case !er.endReached:
		return "its trailer says the end of the file was not reached"
	case er.counts[recordGap] > 0:
		return "it holds a gap"
	case er.prunedBefore > 0:
		return fmt.Sprintf("%d segment(s) of its log before the one it exports were pruned", er.prunedBefore)
	case er.after:
		return "it starts after a cursor"
	case er.filtered:
		return "it is filtered"
	}
	return ""
}

const (
	recordHeader    = "header"
	recordEvent     = "event"
	recordGap       = "gap"
	recordDuplicate = "duplicate"
	recordTrailer   = "trailer"
)

func (er *exportReader) record(line []byte) error {
	if err := strictJSON(line); err != nil {
		return err
	}
	probe, err := object(line, recordMembers...)
	if err != nil {
		return err
	}
	kind, err := probe.str("type")
	if err != nil {
		return err
	}
	switch {
	case er.trailer:
		return errors.New("a record after the trailer")
	case er.tail && kind != recordTrailer:
		return errors.New("a record after the bytes after the last newline")
	case !er.header && kind != recordHeader:
		return errors.New("the first record is not the header")
	case er.header && kind == recordHeader:
		return errors.New("a second header")
	}
	read, ok := map[string]func([]byte) error{
		recordHeader: er.readHeader, recordEvent: er.readEvent, recordGap: er.readGap,
		recordDuplicate: er.readDuplicate, recordTrailer: er.readTrailer,
	}[kind]
	if !ok {
		return fmt.Errorf("record type %s is not one this reader knows", strconv.QuoteToASCII(clip(kind)))
	}
	return read(line)
}

// recordMembers is every member any record type has; each type's reader
// narrows it.
var recordMembers = []string{"type", "format", "version", "file", "source", "pruned_before", "query", "offset", "cursor",
	"event", "reason", "event_id", "first_offset", "next_cursor", "end_reached", "tail_bytes", "writer_held",
	"counts", "scanned_bytes", "dedup_scope"}
