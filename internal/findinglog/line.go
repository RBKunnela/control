package findinglog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// MaxLineBytes bounds one log line, its newline excluded, in both directions.
const MaxLineBytes = 64 << 10

var (
	errLineTooLong = errors.New("findinglog: line too long")
	errNull        = errors.New("null is not a value here")
)

// marshalLine writes one record as one log line: protojson compacted, the
// runes a reader could take for something other than text escaped, and a
// newline. It refuses a record unmarshalLine would refuse, and one carrying a
// field this build cannot name, which protojson would drop without a word.
func marshalLine(r *findingv1alpha1.Record) ([]byte, error) {
	if err := checkRecord(r); err != nil {
		return nil, err
	}
	if hasUnknownFields(r.ProtoReflect()) {
		return nil, errors.New("a field this build cannot name would be dropped")
	}
	raw, err := protojson.Marshal(r)
	if err != nil {
		return nil, err
	}
	var compact, line bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, err
	}
	escapeLine(&line, compact.Bytes())
	if line.Len() > MaxLineBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", errLineTooLong, line.Len(), MaxLineBytes)
	}
	line.WriteByte('\n')
	return line.Bytes(), nil
}

// Line is the line the writer writes for r, its newline left out. It
// refuses a record the writer refuses.
func Line(r *findingv1alpha1.Record) ([]byte, error) {
	b, err := marshalLine(r)
	if err != nil {
		return nil, err
	}
	return b[:len(b)-1], nil
}

// unmarshalLine reads one log line, with or without its newline, held to the
// writer's form. Its errors can quote the line, so a caller that may not
// repeat a line's bytes does not repeat them.
func unmarshalLine(line []byte) (*findingv1alpha1.Record, error) {
	if n := len(bytes.TrimSuffix(line, []byte("\n"))); n > MaxLineBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", errLineTooLong, n, MaxLineBytes)
	}
	if err := checkLineForm(line); err != nil {
		return nil, err
	}
	r := &findingv1alpha1.Record{}
	if err := unmarshalStrict(line, r); err != nil {
		return nil, err
	}
	if err := checkSpelledSet(line, r.ProtoReflect()); err != nil {
		return nil, err
	}
	if err := checkRecord(r); err != nil {
		return nil, err
	}
	return r, nil
}

// unmarshalStrict decodes b into m, refusing an unknown or duplicate member,
// a trailing value, and a null anywhere: protojson reads a null member as an
// absent one.
func unmarshalStrict(b []byte, m proto.Message) error {
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(b, m); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return err
		case tok == nil:
			return fmt.Errorf("%w (offset %d)", errNull, dec.InputOffset())
		}
	}
}

// checkSpelledSet refuses a member b spells that m, decoded from it, does
// not hold: one at its default, which the writer never spells, and which
// would let a record carry a member of a later schema while it reads as one
// that lacks it. A map's entries are written whatever their value, and a
// member spelled as a string, such as a timestamp, holds no members.
func checkSpelledSet(b []byte, m protoreflect.Message) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(b, &members); err != nil {
		return err
	}
	fields := m.Descriptor().Fields()
	for name, raw := range members {
		if fd := fields.ByJSONName(name); fd != nil {
			if err := checkSpelledMember(raw, m, fd); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkSpelledMember holds raw, the spelling of m's member fd, to
// checkSpelledSet's rule, and the messages it holds with it.
func checkSpelledMember(raw json.RawMessage, m protoreflect.Message, fd protoreflect.FieldDescriptor) error {
	switch {
	case !m.Has(fd):
		return fieldError(fd.JSONName() + ": spelled at its default, which the writer leaves out")
	case fd.IsList() && fd.Message() != nil:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		list := m.Get(fd).List()
		for i := 0; i < len(items) && i < list.Len(); i++ {
			if err := checkSpelledSet(items[i], list.Get(i).Message()); err != nil {
				return err
			}
		}
	case fd.Message() != nil && !fd.IsMap() && bytes.HasPrefix(raw, []byte("{")):
		return checkSpelledSet(raw, m.Get(fd).Message())
	}
	return nil
}

// hasUnknownFields reports whether any message in the tree carries a field
// this build cannot name, through singular fields, lists and map values.
func hasUnknownFields(m protoreflect.Message) bool {
	if len(m.GetUnknown()) > 0 {
		return true
	}
	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList() && fd.Message() != nil:
			for i := 0; i < v.List().Len() && !found; i++ {
				found = hasUnknownFields(v.List().Get(i).Message())
			}
		case fd.IsMap() && fd.MapValue().Message() != nil:
			v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
				found = hasUnknownFields(mv.Message())
				return !found
			})
		case fd.Message() != nil && !fd.IsList() && !fd.IsMap():
			found = hasUnknownFields(v.Message())
		}
		return !found
	})
	return found
}

// escapeLine appends line to dst with every rune a reader could take for
// something other than text written as a JSON \u escape: DEL and the C1
// controls (NEL breaks a line, CSI drives a terminal), U+2028 and U+2029, and
// the bidirectional controls. Outside a string a JSON line is ASCII, so each
// sits inside a string, where the escape decodes to the same value.
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
