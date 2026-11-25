package coverage

import (
	"encoding/json"
	"errors"
	"fmt"
)

// maxExportLimit is the most records the contract lets one export write.
const maxExportLimit = 100_000

// gapPartialTail is the gap of the bytes after the file's last newline, the
// one record the contract gives no cursor.
const gapPartialTail = "partial_tail"

// count reads member name, which the record requires, as a non-negative
// integer.
func (m members) count(name string) (uint64, error) {
	raw, ok := m[name]
	if !ok {
		return 0, fmt.Errorf("%s: required", name)
	}
	var n uint64
	if json.Unmarshal(raw, &n) != nil {
		return 0, fmt.Errorf("%s: not a count", name)
	}
	return n, nil
}

// flag reads member name, which the record requires, as a boolean.
func (m members) flag(name string) (bool, error) {
	switch string(m[name]) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("%s: want true or false", name)
}

// nonEmpty refuses member name unless it is a non-empty string; the record
// requires it.
func (m members) nonEmpty(name string) error {
	s, err := m.str(name)
	if err == nil && s == "" {
		err = fmt.Errorf("%s: required", name)
	}
	return err
}

// readSource takes the header's source, which the contract leaves out only
// while the file holds no whole line.
func (er *exportReader) readSource(header members) error {
	if _, ok := header["source"]; !ok {
		return nil
	}
	s, err := header.str("source")
	if err != nil || !lowerHexDigest(s) {
		return errors.New("source: not a SHA-256 in lowercase hex")
	}
	er.source = true
	return nil
}

func lowerHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// readBounds checks the query's limit, which it always has, its byte bound,
// absent when there is none, and its cursor, which only a file with a whole
// line has.
func (er *exportReader) readBounds(q members) error {
	limit, err := q.count("limit")
	if err != nil {
		return err
	}
	if limit < 1 || limit > maxExportLimit {
		return fmt.Errorf("limit: %d, want 1 to %d", limit, maxExportLimit)
	}
	if _, ok := q["max_bytes"]; ok {
		if n, err := q.count("max_bytes"); err != nil || n == 0 {
			return errors.New("max_bytes: want a bound of at least 1, absent when there is none")
		}
	}
	if _, er.after = q["after"]; !er.after {
		return nil
	}
	if err := q.nonEmpty("after"); err != nil {
		return err
	}
	if !er.source {
		return errors.New("after: a cursor into a file the header says holds no whole line")
	}
	return nil
}

// wholeLine refuses a record of a whole line in an export whose header says
// the file holds none.
func (er *exportReader) wholeLine() error {
	if !er.source {
		return errors.New("a line of a file the header says holds no whole line")
	}
	return nil
}

// readGapCursor takes the gap's cursor, which only the bytes after the last
// newline lack.
func (er *exportReader) readGapCursor(gap members, reason string) error {
	_, cursored := gap["cursor"]
	switch {
	case reason == gapPartialTail && cursored:
		return errors.New("cursor: the bytes after the last newline have none")
	case reason == gapPartialTail:
		er.tail = true
		return nil
	case !cursored:
		return errors.New("cursor: required on a whole line")
	}
	if err := gap.nonEmpty("cursor"); err != nil {
		return err
	}
	return er.wholeLine()
}

// readTrailerMembers checks what the trailer says besides its end and its
// counts: a next cursor exactly when the header names a source, and the bytes
// after the last newline, which a partial tail gap says no writer holds and
// an export that reached the end reports as that gap.
func (er *exportReader) readTrailerMembers(tr members) error {
	if _, next := tr["next_cursor"]; next != er.source {
		return errors.New("next_cursor: present exactly when the header names a source")
	} else if next {
		if err := tr.nonEmpty("next_cursor"); err != nil {
			return err
		}
	}
	if _, err := tr.count("scanned_bytes"); err != nil {
		return err
	}
	if scope, err := tr.str("dedup_scope"); err != nil || scope != "export" {
		return errors.New(`dedup_scope: want "export"`)
	}
	tail, err := tr.count("tail_bytes")
	if err != nil {
		return err
	}
	held, err := tr.flag("writer_held")
	if err != nil {
		return err
	}
	return er.checkTail(tail, held)
}

// checkTail holds the trailer's tail_bytes and writer_held to the partial
// tail gap the export did or did not carry.
func (er *exportReader) checkTail(tail uint64, held bool) error {
	switch {
	case er.tail && (tail == 0 || held):
		return errors.New("tail_bytes, writer_held: a partial tail gap needs bytes after the last newline no writer holds")
	case !er.tail && tail > 0 && !held && er.endReached:
		return errors.New("tail_bytes, writer_held: bytes after the last newline no writer holds need a partial tail gap before the end")
	}
	return nil
}
