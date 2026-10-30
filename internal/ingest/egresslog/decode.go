package egresslog

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"
)

// The reasons a line is refused for, the keys of refused_by.
const (
	reasonTooLong     = "line_too_long"
	reasonNotAnObject = "not_an_object"
	reasonDuplicate   = "duplicate_member"
	reasonTime        = "time"
	reasonDestination = "destination"
	reasonPort        = "port"
)

// values is what one line holds for each field.
type values [fieldCount]value

// decodeLine reads one line's top-level members and decodes the values of
// the mapped ones; every other value is stepped over unread. It returns the
// reason the line is refused for, or "". A member named twice is refused
// whichever it is, since a reader that keeps one copy can be steered by
// whoever writes the other.
func decodeLine(line []byte, mapped map[string]field) (values, string) {
	var vals values
	if !utf8.Valid(line) || !json.Valid(line) {
		return vals, reasonNotAnObject
	}
	w := walker{b: line}
	w.space()
	if w.b[w.i] != '{' {
		return vals, reasonNotAnObject
	}
	w.i++
	seen := map[string]bool{}
	for {
		w.space()
		switch w.b[w.i] {
		case '}':
			return vals, ""
		case ',':
			w.i++
			w.space()
		}
		name := w.name()
		if seen[name] {
			return vals, reasonDuplicate
		}
		seen[name] = true
		w.space()
		w.i++
		w.space()
		start := w.i
		w.skip()
		if f, ok := mapped[name]; ok {
			vals[f] = decodeValue(w.b[start:w.i])
		}
	}
}

// decodeValue reads one value json.Valid has passed: a string decoded, a
// number as written, and null and every other kind named only.
func decodeValue(raw []byte) value {
	switch c := raw[0]; {
	case c == '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return value{kind: kindOther}
		}
		return value{kind: kindString, text: s}
	case c == 'n':
		return value{kind: kindNull}
	case c == '-' || (c >= '0' && c <= '9'):
		return value{kind: kindNumber, text: string(raw)}
	}
	return value{kind: kindOther}
}

// walker steps through a line json.Valid has passed, so it never meets an
// end or a byte it does not expect.
type walker struct {
	b []byte
	i int
}

func (w *walker) space() {
	for w.i < len(w.b) && space(w.b[w.i]) {
		w.i++
	}
}

func space(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// name decodes the member name at w.i and moves past it. A name without an
// escape is taken as written; one with an escape is decoded, so two
// spellings of one name are one name.
func (w *walker) name() string {
	start := w.i
	inner := w.str()
	if bytes.IndexByte(inner, '\\') < 0 {
		return string(inner)
	}
	var s string
	if err := json.Unmarshal(w.b[start:w.i], &s); err != nil {
		return string(w.b[start:w.i])
	}
	return s
}

// skip moves w.i past the value it is at.
func (w *walker) skip() {
	switch w.b[w.i] {
	case '"':
		w.str()
	case '{', '[':
		w.container()
	default:
		for w.i < len(w.b) && !boundary(w.b[w.i]) {
			w.i++
		}
	}
}

func boundary(c byte) bool { return c == ',' || c == '}' || c == ']' || space(c) }

// container moves w.i past the object or array it is at.
func (w *walker) container() {
	depth := 0
	for {
		switch w.b[w.i] {
		case '"':
			w.str()
			continue
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		}
		w.i++
		if depth == 0 {
			return
		}
	}
}

// str returns the string at w.i as written, escapes included and quotes
// excluded, and moves w.i past its closing quote.
func (w *walker) str() []byte {
	w.i++
	start := w.i
	for w.b[w.i] != '"' {
		if w.b[w.i] == '\\' {
			w.i++
		}
		w.i++
	}
	w.i++
	return w.b[start : w.i-1]
}
