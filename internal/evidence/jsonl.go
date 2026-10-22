package evidence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
)

// MaxLineBytes is the longest line either direction of the codec will handle:
// three times contract.MaxEnvelopeBytes. The largest thing an event carries is
// one envelope, and a line spells it in JSON, escaped, which is larger than the
// Protobuf bytes the contract bounds.
//
// The factor is sized for the worst case of what contract.Validate accepts.
// Under the string rule ADR-0011 gives Validate, a string an envelope holds at
// most doubles in JSON, a quote or a backslash being two bytes there, so the
// envelope alone can reach twice the limit. The rest of the line is small
// beside that and not nothing: field and enum names, timestamps, the event's
// own fields, and the two free-text fields, where the Arabic letter mark is two
// bytes raw and six escaped. TestTheLargestProposalTheContractAcceptsFitsOnALine
// builds that case; its line is more than twice the limit, and it fits.
//
// A line past the bound is refused in both directions: EncodeJSONL refuses to
// write a record DecodeJSONL would refuse to read, loudly, where a caller can
// still do something about it. The decoder's buffer is this size on every
// call, which is what a larger factor costs.
const MaxLineBytes = 3 * contract.MaxEnvelopeBytes

var (
	// ErrLineTooLong reports a line over MaxLineBytes, in either direction.
	ErrLineTooLong = errors.New("evidence: line too long")

	// ErrTooManyEvents reports input holding more events than the caller's
	// limit allows.
	ErrTooManyEvents = errors.New("evidence: too many events")

	// ErrInvalidLimit reports a negative limit. It is not read as "unlimited":
	// a bound that disappears when a caller passes a value it did not check is
	// the failure this project calls a false green.
	ErrInvalidLimit = errors.New("evidence: invalid limit")

	// ErrMalformedLine reports a line that is not one JSON object of one Event.
	// It carries the codec's own message, bounded and escaped rather than
	// wrapped, so that a refusal written into a log holds no unbounded run of a
	// producer's bytes and no control byte at all. That message is not part of
	// this package's contract; match on this sentinel, not on the text.
	ErrMalformedLine = errors.New("evidence: malformed line")

	// ErrUnknownField reports an event handed to EncodeJSONL that carries a
	// field this build cannot name, anywhere in its tree. protojson drops such
	// a field without a word, and a trail that silently lost what a producer
	// thought mattered is the loss DecodeJSONL refuses in the other direction.
	// A caller holding one has a message from a later minor version and needs
	// an encoding that keeps it, which is the binary one.
	ErrUnknownField = errors.New("evidence: unknown field")

	// ErrNilEvent reports a nil element in the slice handed to EncodeJSONL. A
	// nil message encodes as "{}", which would put a record saying nothing into
	// a trail, and a gap has to look like a gap.
	ErrNilEvent = errors.New("evidence: nil event")
)

// EncodeJSONL writes one event per line as one JSON object, in the order given.
//
// The bytes are stable: protojson is free to vary insignificant whitespace
// between runs, so each line is compacted before it is written and two runs
// over the same events produce the same file.
//
// One event is one line for every reader. JSON escapes the C0 controls inside a
// string, so no line holds a newline or a carriage return of its own, and the
// encoder escapes the rest of what a reader may split a line on, act on or
// reorder: DEL and the C1 controls, U+2028 and U+2029, and the bidirectional
// controls, each as a \u escape. The escaped line is the one measured against
// MaxLineBytes, because it is the one DecodeJSONL reads.
//
// It writes nothing for an empty slice and refuses a nil element. A partial
// write leaves whatever the writer accepted: this package has no file to
// truncate and no transaction to roll back, and the reader's own refusal of a
// truncated last line is what catches it.
//
// It also refuses an event carrying a field this build cannot name, with
// ErrUnknownField, rather than writing the lossy record protojson would
// produce. The reader refuses an unknown field instead of dropping it and the
// writer holds the same line.
func EncodeJSONL(w io.Writer, events []*controlv1.Event) error {
	var compact, line bytes.Buffer
	for i, event := range events {
		if event == nil {
			return fmt.Errorf("event %d: %w", i, ErrNilEvent)
		}
		if hasUnknownFields(event.ProtoReflect()) {
			return fmt.Errorf("event %d: %w: writing it would drop the field", i, ErrUnknownField)
		}
		raw, err := protojson.Marshal(event)
		if err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
		compact.Reset()
		if err := json.Compact(&compact, raw); err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
		line.Reset()
		escapeLine(&line, compact.Bytes())
		if line.Len() > MaxLineBytes {
			return fmt.Errorf("event %d: %w: %d bytes, limit %d",
				i, ErrLineTooLong, line.Len(), MaxLineBytes)
		}
		line.WriteByte('\n')
		if _, err := w.Write(line.Bytes()); err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
	}
	return nil
}

// DecodeJSONL reads at most limit events, one per line, and refuses anything
// else it finds.
//
// It parses bytes it did not write, so it trusts none of them:
//
//   - A line longer than MaxLineBytes is refused with ErrLineTooLong without
//     being held in memory. The reader underneath is one bufio.Reader sized
//     MaxLineBytes+1, which is the longest line plus its newline, and it
//     reports a full buffer rather than growing, so the memory this function
//     uses does not depend on the length of the line it is refusing. It is
//     this function's own even when r is a *bufio.Reader, so a buffer the
//     caller chose never sets the bound.
//   - An unknown JSON field is refused, never dropped. A receiver that ignored
//     what it did not understand would silently discard the field a producer
//     thought mattered.
//   - A blank or whitespace-only line is refused rather than skipped, for the
//     same reason. The end of the file is not a blank line: a trailing newline
//     after the last event ends the input, and a last line with no newline at
//     all is read as a line, which is how a write cut short inside an object is
//     refused as malformed rather than accepted as short. A write cut short
//     between the closing brace and its newline is a different matter: those
//     are two bytes of one Write, and a last line missing only the terminator
//     is not distinguishable from a complete one. It is accepted.
//   - A file written with CRLF endings reads, because JSON counts a carriage
//     return as whitespace and the one before the newline is trailing
//     whitespace after the object. Nothing here strips it: a carriage return
//     used alone as a terminator is not a line ending either, so such a file
//     arrives as one long line and is refused rather than read as several.
//
// limit is a count of events and it is never a suggestion. A limit of 0 admits
// no events: empty input returns an empty slice, and one event is
// ErrTooManyEvents. A negative limit is ErrInvalidLimit. The event past the
// limit is refused before it is parsed, so a caller cannot be made to build
// what it said it would not hold.
//
// It counts events and not bytes, and an event admitted at the line bound
// retains most of MaxLineBytes: limit bounds the events a successful read
// returns, and limit * MaxLineBytes bounds what it retains. A caller naming a
// limit is naming both.
//
// An event decodes here whenever the line is one well formed Event. Whether the
// events are a trail is a separate question and ValidateChain is what answers
// it: "{}" is a valid Event and never a valid chain.
func DecodeJSONL(r io.Reader, limit int) ([]*controlv1.Event, error) {
	if limit < 0 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidLimit, limit)
	}
	// Sized so that the longest allowed line and its newline fit exactly.
	// ReadSlice reports a full buffer instead of growing, which is what bounds
	// the read: a line that never ends costs this buffer and nothing more.
	//
	// The caller's reader goes in behind an interface. NewReaderSize hands
	// back a *bufio.Reader it is given whose buffer is already this large, and
	// the bound would then be whatever buffer the caller chose.
	reader := bufio.NewReaderSize(struct{ io.Reader }{r}, MaxLineBytes+1)

	// Not limit: a caller naming a large bound must not turn it into an
	// allocation before a single event has been read.
	events := make([]*controlv1.Event, 0, min(limit, 64))

	for number := 1; ; number++ {
		line, err := reader.ReadSlice('\n')
		// Identity, not errors.Is, which unwraps: a reader that fails with an
		// error wrapping io.EOF has failed, and reading that as the end of the
		// input would return a truncated read as a complete one. bufio hands
		// back the underlying reader's error as it stands, so the end of the
		// input is io.EOF itself and everything else falls through to a refusal.
		atEOF := err == io.EOF //nolint:errorlint // identity: a wrapped io.EOF is a failure

		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			return nil, fmt.Errorf("line %d: %w: over %d bytes", number, ErrLineTooLong, MaxLineBytes)
		case err != nil && !atEOF:
			return nil, fmt.Errorf("line %d: %w", number, err)
		case atEOF && len(line) == 0:
			return events, nil
		}

		// Counted before the line is parsed, so the event past the limit costs
		// no allocation and no decode.
		if len(events) >= limit {
			return nil, fmt.Errorf("line %d: %w: limit %d", number, ErrTooManyEvents, limit)
		}
		event, err := decodeLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", number, err)
		}
		events = append(events, event)

		if atEOF {
			return events, nil
		}
	}
}

// decodeLine reads one line, which is borrowed from the reader's buffer and is
// not retained: protojson copies every value it decodes.
//
// The line still carries its terminator, and its carriage return if it had one.
// JSON counts both as whitespace around a value, so the parser takes the line
// as it stands. Trimming them first would be a normalization no test could tell
// from doing nothing, which is how a line ending nobody checked gets treated as
// handled; the CRLF and bare-newline cases in the tests are what hold this.
func decodeLine(line []byte) (*controlv1.Event, error) {
	if len(bytes.TrimSpace(line)) == 0 {
		return nil, fmt.Errorf("%w: blank", ErrMalformedLine)
	}
	event := &controlv1.Event{}
	// DiscardUnknown stays false: see the note on unknown fields above.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(line, event); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrMalformedLine, refusalAt(err))
	}
	return event, nil
}

// refusalAt says where protojson refused a line and nothing of what the line
// held: its message quotes the value or the member name it refused, and a
// sender can put a credential or a prompt in either.
func refusalAt(err error) string {
	msg := err.Error()
	i := strings.Index(msg, "(line ")
	if i < 0 {
		return "not an event this build reads"
	}
	j := strings.IndexByte(msg[i:], ')')
	if j < 0 {
		return "not an event this build reads"
	}
	at := msg[i+len("(line ") : i+j]
	if strings.Trim(at, "0123456789:") != "" {
		return "not an event this build reads"
	}
	return "not an event this build reads, from line:column " + at
}

// hasUnknownFields reports whether any message in the tree carries a field this
// build cannot name. The check is the whole tree because a later minor version
// is at least as likely to add a field to a payload as to the event around it,
// and protojson drops either one just as quietly.
func hasUnknownFields(m protoreflect.Message) bool {
	if len(m.GetUnknown()) > 0 {
		return true
	}
	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		found = fieldHasUnknownFields(fd, v)
		return !found
	})
	return found
}

// fieldHasUnknownFields descends into one populated field. The recursion is
// bounded by the frozen v1 contract, in which no message contains itself and
// nothing carries a google.protobuf.Struct or an Any; the depth is the schema's
// and not a caller's.
func fieldHasUnknownFields(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	switch {
	case fd.IsMap():
		if fd.MapValue().Message() == nil {
			return false
		}
		found := false
		v.Map().Range(func(_ protoreflect.MapKey, entry protoreflect.Value) bool {
			found = hasUnknownFields(entry.Message())
			return !found
		})
		return found
	case fd.IsList():
		if fd.Message() == nil {
			return false
		}
		for i := range v.List().Len() {
			if hasUnknownFields(v.List().Get(i).Message()) {
				return true
			}
		}
		return false
	case fd.Message() != nil:
		return hasUnknownFields(v.Message())
	default:
		return false
	}
}
