package observelog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
)

// readIndex reads r as whole log lines and returns the index of the
// observations every import report closes, with the length up to the end of
// the last report. The observations after it are a write a crash cut before
// its report, so they are read and judged but not indexed. A line that is not
// one record this build reads in the form the codec writes it, a carriage
// return, and an observation id carried with two contents are ErrDamaged: a
// writer of this package leaves none of them.
func readIndex(r io.Reader) (index, int64, error) {
	ids, committed, err := scanLog(r, nil)
	var fault *lineFault
	switch {
	case errors.As(err, &fault) && errors.Is(fault.cause, bufio.ErrBufferFull):
		return nil, 0, fmt.Errorf("%w: line %d is over %d bytes", ErrDamaged, fault.number, observe.MaxLineBytes)
	case errors.As(err, &fault):
		return nil, 0, fmt.Errorf("%w: line %d: %w", ErrDamaged, fault.number, fault.cause)
	case err != nil:
		return nil, 0, err
	}
	return ids, committed, nil
}

// lineFault is a line the log's reader refuses: over observe.MaxLineBytes, or
// judged and found damaged. Each caller words it, since only some may repeat
// the cause, which can quote the line.
type lineFault struct {
	number int
	offset int64
	cause  error
}

func (f *lineFault) Error() string {
	return fmt.Sprintf("line %d at byte %d: %v", f.number, f.offset, f.cause)
}

func (f *lineFault) Unwrap() error { return f.cause }

// scanLog judges r as readIndex describes and, when keep is not nil, hands it
// each write's records once the write's import report closes it.
func scanLog(r io.Reader, keep func([]*observev1.Record)) (index, int64, error) {
	reader := bufio.NewReaderSize(r, observe.MaxLineBytes+1)
	ids, pending := index{}, index{}
	var write []*observev1.Record
	var offset, committed int64
	for number := 1; ; number++ {
		line, err := reader.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			return nil, 0, &lineFault{number: number, offset: offset, cause: err}
		case errors.Is(err, io.EOF) && len(line) == 0:
			return ids, committed, nil
		case err != nil:
			return nil, 0, fmt.Errorf("reading line %d: %w", number, err)
		}
		record, closes, err := ids.read(pending, line)
		if err != nil {
			return nil, 0, &lineFault{number: number, offset: offset, cause: err}
		}
		offset += int64(len(line))
		if keep != nil {
			write = append(write, record)
		}
		if closes {
			ids.add(pending)
			clear(pending)
			committed = offset
			if keep != nil {
				keep(write)
				write = nil
			}
		}
	}
}

// read judges one whole line and adds an observation to pending. It returns
// the line's record and whether it is an import report, which closes its
// write.
func (ids index) read(pending index, line []byte) (*observev1.Record, bool, error) {
	// The form refuses a carriage return anywhere, a string's or not.
	if err := observe.CheckLineForm(line); err != nil {
		return nil, false, err
	}
	r, err := observe.UnmarshalLine(line)
	if err != nil {
		return nil, false, err
	}
	o := r.GetObservation()
	if o == nil {
		return r, true, nil
	}
	h, id := heldOf(o), o.GetObservationId()
	kept, ok := ids[id]
	if !ok {
		kept, ok = pending[id]
	}
	if h.sum == "" || (ok && kept.sum != h.sum) {
		return nil, false, errors.New("an observation id an earlier line carries with other content")
	}
	pending[id] = h
	return r, false, nil
}

// lastLineEnd returns the length of the file up to and including its last
// newline. Only the last observe.MaxLineBytes+1 bytes are read: a writer
// leaves at most observe.MaxLineBytes after the last newline, so a newline
// that is not among them is ErrDamaged. So is a tail that cannot be the start
// of a line the codec writes, which is no write a crash cut.
func lastLineEnd(f io.ReaderAt, size int64) (int64, error) {
	if size == 0 {
		return 0, nil
	}
	window := min(size, int64(observe.MaxLineBytes)+1)
	tail := make([]byte, window)
	if _, err := f.ReadAt(tail, size-window); err != nil {
		return 0, err
	}
	start := bytes.LastIndexByte(tail, '\n') + 1
	switch {
	case start == 0 && size > observe.MaxLineBytes:
		return 0, fmt.Errorf("%w: more than %d bytes follow the last newline", ErrDamaged, observe.MaxLineBytes)
	case start < len(tail) && !torn(tail[start:]):
		return 0, fmt.Errorf("%w: the bytes after the last newline are not the start of a log line", ErrDamaged)
	}
	return size - window + int64(start), nil
}

// openings are the ways a line the codec writes can begin: an object whose
// one member is a record's kind, in its JSON name and with no space, which is
// how protojson compacted spells it.
var openings = func() [][]byte {
	fields := (&observev1.Record{}).ProtoReflect().Descriptor().Fields()
	out := make([][]byte, 0, fields.Len())
	for i := range fields.Len() {
		out = append(out, []byte(`{"`+fields.Get(i).JSONName()+`":`))
	}
	return out
}()

// torn reports whether tail can be what a crash left of a line the codec
// wrote. A whole JSON value can, only when it reads as one record in the
// codec's form: the write was cut between the object and its newline.
// Anything shorter can only when it agrees with one opening as far as either
// goes and is a proper prefix of one JSON value.
func torn(tail []byte) bool {
	if json.Valid(tail) {
		_, err := observe.UnmarshalLine(tail)
		return err == nil && observe.CheckLineForm(tail) == nil
	}
	for _, opening := range openings {
		n := min(len(tail), len(opening))
		if bytes.Equal(tail[:n], opening[:n]) {
			return prefixOfOneValue(tail)
		}
	}
	return false
}

// prefixOfOneValue reports whether b is a proper prefix of one JSON value: a
// walk of its tokens meets no syntax error, and ends only because the bytes
// ran out inside that value. A value that closes with bytes after it is not.
func prefixOfOneValue(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	depth := 0
	for {
		tok, err := dec.Token()
		switch {
		case errors.Is(err, io.ErrUnexpectedEOF):
			return true
		case errors.Is(err, io.EOF):
			return depth > 0
		case err != nil:
			return false
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			return false
		}
	}
}
