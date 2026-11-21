package trailfile

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/guardana/control/adapters/otel"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
)

type digest = [sha256.Size]byte

// index maps the digest of each event id a file holds to the line that
// carries it. Digests keep an entry the same size however long the id is. An
// event with no id is not in it.
type index map[digest]place

// place is a line an index holds: its digest, and where it stands in what
// was indexed, the offset of its first byte and its length.
type place struct {
	line     digest
	at, size int64
}

type entry struct {
	id digest
	place
}

// readIndex reads r as whole evidence lines and indexes them at their offsets
// in r. A line that is not one event, and an event id on two different
// lines, are ErrDamaged: a writer of this package leaves neither.
func readIndex(r io.Reader) (index, error) {
	reader := bufio.NewReaderSize(r, evidence.MaxLineBytes+1)
	ids := index{}
	var at int64
	for number := 1; ; number++ {
		line, err := reader.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			return nil, fmt.Errorf("%w: line %d is over %d bytes", ErrDamaged, number, evidence.MaxLineBytes)
		case errors.Is(err, io.EOF) && len(line) == 0:
			return ids, nil
		case err != nil:
			return nil, fmt.Errorf("reading line %d: %w", number, err)
		}
		if _, err := ids.addLine(number, at, line); err != nil {
			return nil, err
		}
		at += int64(len(line))
	}
}

// addLine indexes one whole line, at the offset at, and returns its event. A
// line that is not one event, and an event id the index holds with another
// line, are ErrDamaged.
func (ids index) addLine(number int, at int64, line []byte) (*controlv1.Event, error) {
	events, err := evidence.DecodeJSONL(bytes.NewReader(line), 1)
	if err != nil {
		return nil, fmt.Errorf("%w: line %d is not one evidence event: %w", ErrDamaged, number, err)
	}
	id := events[0].GetEventId()
	if id == "" {
		return events[0], nil
	}
	key, sum := sha256.Sum256([]byte(id)), sha256.Sum256(line)
	if held, ok := ids[key]; ok && held.line != sum {
		return nil, fmt.Errorf("%w: line %d carries the event id of an earlier line with other content", ErrDamaged, number)
	}
	ids[key] = place{line: sum, at: at, size: int64(len(line))}
	return events[0], nil
}

// fresh returns the lines of events that neither the index nor an earlier
// event of the same append holds, to be written at the offset end, with
// their entries, and the places of the lines the index holds. An event id
// held with another line refuses the whole append.
func (ids index) fresh(events []*controlv1.Event, lines [][]byte, end int64) ([]byte, []entry, []place, error) {
	var buf []byte
	var added []entry
	var held []place
	pending := map[digest]digest{}
	for i, line := range lines {
		id := events[i].GetEventId()
		if id == "" {
			buf = append(buf, line...)
			continue
		}
		key, sum := sha256.Sum256([]byte(id)), sha256.Sum256(line)
		p, indexed := ids[key]
		first, ok := pending[key]
		switch {
		case indexed && p.line == sum:
			held = append(held, p)
			continue
		case !indexed && ok && first == sum:
			continue
		case indexed || ok:
			return nil, nil, nil, fmt.Errorf("%w: %w: event %d of the append", ErrConflict, otel.ErrSinkRefused, i)
		}
		pending[key] = sum
		added = append(added, entry{id: key, place: place{line: sum, at: end + int64(len(buf)), size: int64(len(line))}})
		buf = append(buf, line...)
	}
	return buf, added, held, nil
}

func (ids index) add(entries []entry) {
	for _, e := range entries {
		ids[e.id] = e.place
	}
}
