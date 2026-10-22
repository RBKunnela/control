package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// maxRecordBytes bounds one record: the exporter's longest event line and
// the few hundred bytes that frame it, with room to spare.
const maxRecordBytes = 4 << 20

// maxExportRecords is the most records an export writes, at its highest
// --limit; only its trailer follows them.
const maxExportRecords = 100_000

// maxExportBytes bounds what one read takes in after the header, newlines
// counted, since the events it keeps are held until the export ends.
const maxExportBytes = 64 << 20

// exportMajor is the major of the export format this reader reads.
const exportMajor = 1

// contractPackage is the wire contract's Protobuf package, whose last
// segment is its major, v1.
var contractPackage = string((&controlv1.Event{}).ProtoReflect().Descriptor().ParentFile().Package())

// exportFormat is the format this reader reads: the contract names it in the
// namespace of the wire contract's package, without its major segment, and
// TestDemoExportFormat holds it to what the exporter wrote.
var exportFormat = contractPackage[:strings.LastIndex(contractPackage, ".")] + ".evidence-export"

// eventMajor is the event schema major the generated package was built from.
var eventMajor = strings.TrimPrefix(contractPackage[strings.LastIndex(contractPackage, ".")+1:], "v")

// export is what a read of an export found: its events in the file's order,
// what it could not use, and the trailer when one was read and accepted.
type export struct {
	events   []*event
	byKey    map[eventKey]*event
	atOffset map[int64]*event
	trailer  *trailerState
	header   header
	// gapRecords are the gap records in the file's order.
	gapRecords []gapRecord

	gaps, duplicates, conflicting, refused int
	problems                               []string
	// firstRefusal says where and why the first record was refused.
	firstRefusal string

	// The records read by type, which the trailer's counts have to match.
	seenEvents, seenGaps, seenDuplicates int
	line                                 int
	lastOffset                           int64
	ended                                bool
}

type event struct {
	ev          *controlv1.Event
	raw         []byte
	offset      int64
	cursor      string
	conflicting bool
}

type gapRecord struct {
	offset         int64
	cursor, reason string
}

// eventKey is how a consumer tells events apart across a tenant's projects.
type eventKey struct{ tenant, project, id string }

type trailerState struct {
	nextCursor string
	endReached bool
	tailBytes  int64
	writerHeld bool
}

// readExport reads an export to its end. The error is a refusal of the whole
// export: no header, another format, or a major this reader does not read.
// Everything wrong past the header is counted and said, and the read goes on.
func readExport(r io.Reader) (*export, error) {
	br := bufio.NewReader(r)
	first, err := nextLine(br, maxRecordBytes+1)
	switch {
	case errors.Is(err, io.EOF):
		return nil, errors.New("no header: the input is empty")
	case err != nil:
		return nil, fmt.Errorf("the header could not be read: %w", err)
	}
	h, err := checkHeader(first)
	if err != nil {
		return nil, err
	}
	x := &export{byKey: map[eventKey]*event{}, atOffset: map[int64]*event{}, header: h, line: 1, lastOffset: -1}
	x.readRecords(br)
	return x, nil
}

// readRecords reads the records after the header. Input that cannot be read,
// or that goes on past what an export writes or this reader holds, is refused
// where it stops, and without a trailer read the export is cut.
func (x *export) readRecords(br *bufio.Reader) {
	read := 0
	for {
		l, err := nextLine(br, maxExportBytes-read)
		if errors.Is(err, io.EOF) {
			return
		}
		x.line++
		if err != nil {
			x.refuse("the input could not be read: " + err.Error())
			return
		}
		read += l.size
		if why := x.pastBound(read); why != "" {
			x.refuse(why)
			return
		}
		x.record(l)
	}
}

// pastBound names the bound that the records read so far, read bytes in all,
// go past.
func (x *export) pastBound(read int) string {
	switch {
	case x.line-1 > maxExportRecords+1:
		return fmt.Sprintf("the export goes on past %d records and its trailer, more than an export writes", maxExportRecords)
	case read > maxExportBytes:
		return fmt.Sprintf("the export goes on past %d bytes after its header, more than this reader holds: "+
			"export again with a smaller --limit or --max-bytes", maxExportBytes)
	}
	return ""
}

type rawLine struct {
	b []byte
	// size is the bytes the record took in the input, its newline included.
	size                  int
	tooLong, unterminated bool
}

// nextLine returns the next record without its newline, or io.EOF when no
// byte is left. A record longer than maxRecordBytes is read through and its
// bytes dropped, but a record no newline has ended is read no further than
// once past limit bytes: the input may never end it.
func nextLine(r *bufio.Reader, limit int) (rawLine, error) {
	var l rawLine
	n := 0
	for {
		chunk, err := r.ReadSlice('\n')
		n += len(chunk)
		if n <= maxRecordBytes+1 {
			l.b = append(l.b, chunk...)
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull) && n > limit:
			l.unterminated = true
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && n == 0:
			return l, io.EOF
		case errors.Is(err, io.EOF):
			l.unterminated = true
		case err != nil:
			return l, err
		}
		l.b = bytes.TrimSuffix(l.b, []byte("\n"))
		l.size = n
		l.tooLong = n-len("\n") > maxRecordBytes
		return l, nil
	}
}

func (x *export) refuse(why string) {
	x.refused++
	p := fmt.Sprintf("line %d: %s", x.line, why)
	if x.firstRefusal == "" {
		x.firstRefusal = p
	}
	x.problems = append(x.problems, p)
}

func (x *export) record(l rawLine) {
	switch {
	case x.ended:
		x.refuse("a record after the trailer")
		return
	case l.tooLong:
		x.refuse(fmt.Sprintf("a record longer than %d bytes", maxRecordBytes))
		return
	case l.unterminated:
		x.refuse("a record the input ends inside, before its newline: the export was cut")
		return
	}
	ms, err := object(l.b)
	if err != nil {
		x.refuse("a record that is not one well-formed JSON object: " + err.Error())
		return
	}
	typ, err := recordType(ms)
	if err != nil {
		x.refuse(err.Error())
		return
	}
	if !x.held(typ) {
		return
	}
	if err := only(ms, recordMembers[typ]); err != nil {
		x.refuse(fmt.Sprintf("a %s record the contract does not give: %s", typ, err))
		return
	}
	switch typ {
	case "event":
		x.event(l.b)
	case "gap":
		x.gap(l.b)
	case "duplicate":
		x.duplicate(l.b)
	default:
		x.readTrailer(l.b, ms)
	}
}

// held counts a record by the type it names, which the trailer's counts have
// to match, and refuses a type no record after the header has.
func (x *export) held(typ string) bool {
	switch typ {
	case "event":
		x.seenEvents++
	case "gap":
		x.seenGaps++
	case "duplicate":
		x.seenDuplicates++
	case "trailer":
		x.ended = true
	case "header":
		x.refuse("a second header")
		return false
	default:
		x.refuse("a record of a type this reader does not know")
		return false
	}
	return true
}

// recordType is the type a record names in its member spelled "type".
func recordType(ms []member) (string, error) {
	raw, ok := valueOf(ms, "type")
	var typ string
	if ok && json.Unmarshal(raw, &typ) == nil {
		return typ, nil
	}
	for _, m := range ms {
		if strings.EqualFold(m.name, "type") && m.name != "type" {
			return "", fmt.Errorf("a record whose member differs from %q only in case", "type")
		}
	}
	return "", errors.New("a record that is not a JSON object naming its type")
}

// inOrder holds the records to the file's order, in which every offset is
// past the one before.
func (x *export) inOrder(offset int64) bool {
	if offset <= x.lastOffset {
		x.refuse(fmt.Sprintf("offset %d does not follow offset %d: the records are not in the file's order", offset, x.lastOffset))
		return false
	}
	x.lastOffset = offset
	return true
}
