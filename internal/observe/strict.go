package observe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// maxCauseBytes bounds how much of the codec's message a refusal carries:
// protojson quotes the token it refused word for word.
const maxCauseBytes = 120

// quoted cuts s to at most limit bytes and quotes it in ASCII, so a refusal
// carries no control byte and no unbounded run of a producer's bytes.
func quoted(s string, limit int) string {
	if len(s) > limit {
		return strconv.QuoteToASCII(s[:limit]) + " (truncated)"
	}
	return strconv.QuoteToASCII(s)
}

func cause(err error) string { return quoted(err.Error(), maxCauseBytes) }

// errNull reports a JSON null. protojson reads a null member as an absent
// one, so {"observation":null,"importReport":{...}} would decode as one
// member and a null required member as a default.
var errNull = errors.New("null is not a value here")

// unmarshalStrict decodes b into m, refusing an unknown or duplicate member in
// either spelling, a trailing value, and a null anywhere.
func unmarshalStrict(b []byte, m proto.Message) error {
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(b, m); err != nil {
		return errors.New(cause(err))
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errors.New(cause(err))
		}
		if tok == nil {
			return fmt.Errorf("%w (offset %d)", errNull, dec.InputOffset())
		}
	}
}

// checkSpelledSet refuses a member b spells, in either spelling, that m,
// decoded from it, does not hold: one at its default, which MarshalLine never
// spells, and which would let a record carry a member of a later minor while
// it reads as one that lacks it. A map's entries are written whatever their
// value, and a member spelled as a string, such as a timestamp, holds no
// members.
func checkSpelledSet(b []byte, m protoreflect.Message) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(b, &members); err != nil {
		return errors.New(cause(err))
	}
	fields := m.Descriptor().Fields()
	for name, raw := range members {
		fd := fields.ByJSONName(name)
		if fd == nil {
			fd = fields.ByTextName(name)
		}
		if fd != nil {
			if err := checkSpelledMember(raw, m, fd); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkSpelledMember holds raw, the spelling of m's member fd, to
// checkSpelledSet's rule, and the singular messages it holds with it, the
// only ones the contract holds (see hasUnknownFields).
func checkSpelledMember(raw json.RawMessage, m protoreflect.Message, fd protoreflect.FieldDescriptor) error {
	switch {
	case !m.Has(fd):
		return fmt.Errorf("%s: spelled at its default, which the writer leaves out", fd.JSONName())
	case fd.Message() != nil && !fd.IsMap() && bytes.HasPrefix(raw, []byte("{")):
		return checkSpelledSet(raw, m.Get(fd).Message())
	}
	return nil
}

// hasUnknownFields reports whether any message in the tree carries a field
// this build cannot name; protojson would drop it without a word. It descends
// only through singular messages: the contract holds no list or map of
// messages, which a test pins.
func hasUnknownFields(m protoreflect.Message) bool {
	if len(m.GetUnknown()) > 0 {
		return true
	}
	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Message() != nil && fd.Cardinality() != protoreflect.Repeated {
			found = hasUnknownFields(v.Message())
		}
		return !found
	})
	return found
}

// escapeLine appends line to dst with every rune a reader could take for
// something other than text written as a JSON \u escape, as the evidence
// writer does: DEL and the C1 controls (NEL breaks a line, CSI drives a
// terminal), U+2028 and U+2029, and the bidirectional controls. Outside a
// string a JSON line is ASCII, so each sits inside a string, where the escape
// decodes to the same value.
func escapeLine(dst *bytes.Buffer, line []byte) {
	start := 0
	for i := 0; i < len(line); {
		if b := line[i]; b < utf8.RuneSelf && b != 0x7f {
			i++
			continue
		}
		r, size := utf8.DecodeRune(line[i:])
		if needsEscape(r) {
			dst.Write(line[start:i])
			fmt.Fprintf(dst, `\u%04x`, r)
			start = i + size
		}
		i += size
	}
	dst.Write(line[start:])
}

func needsEscape(r rune) bool {
	return (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 || unicode.Is(unicode.Bidi_Control, r)
}
