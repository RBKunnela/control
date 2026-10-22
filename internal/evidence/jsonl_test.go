// Codec tests. Everything DecodeJSONL reads here is a byte slice written by
// the test rather than by the encoder, because the point of the decoder is what
// it does with input the package did not produce.
package evidence_test

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"pgregory.net/rapid"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/evidence"
)

// A whole trail with payloads, which is what a real segment holds.
func trailWithPayloads(t *testing.T) []*controlv1.Event {
	t.Helper()
	b := trailBuilder(t, "req-1", "evt")
	return []*controlv1.Event{
		b.Proposed(&controlv1.ActionEnvelope{
			SchemaVersion: evidence.SchemaVersion,
			RequestId:     "req-1",
			Action:        &controlv1.Action{Kind: "tool", Name: "files.write"},
			Arguments:     &controlv1.Arguments{RedactedPreview: "path=/tmp/x", RedactionProfile: "default"},
		}),
		b.Decided(&controlv1.Decision{
			DecisionId:  "dec-1",
			Verdict:     controlv1.Verdict_VERDICT_REQUIRE_APPROVAL,
			ReasonCodes: []string{"APPROVAL_REQUIRED"},
		}),
		b.ApprovalRequested(&controlv1.Approval{ApprovalId: "app-1", Reason: "needs a human"}),
		b.ApprovalDecided(&controlv1.Approval{
			ApprovalId: "app-1",
			State:      controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
			ApproverId: "operator-1",
		}),
		b.Started("exec-1"),
		b.Completed(&controlv1.ActionResult{
			ExecutionId: "exec-1",
			Status:      controlv1.ResultStatus_RESULT_STATUS_SUCCESS,
		}),
	}
}

func encode(t *testing.T, events []*controlv1.Event) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := evidence.EncodeJSONL(&buf, events); err != nil {
		t.Fatalf("EncodeJSONL: %v", err)
	}
	return buf.Bytes()
}

func TestRoundTrip(t *testing.T) {
	events := trailWithPayloads(t)
	wire := encode(t, events)

	if lines := bytes.Count(wire, []byte("\n")); lines != len(events) {
		t.Errorf("%d newline(s) for %d events", lines, len(events))
	}

	decoded, err := evidence.DecodeJSONL(bytes.NewReader(wire), len(events))
	if err != nil {
		t.Fatalf("DecodeJSONL: %v", err)
	}
	if len(decoded) != len(events) {
		t.Fatalf("decoded %d events, want %d", len(decoded), len(events))
	}
	for i := range events {
		if !proto.Equal(events[i], decoded[i]) {
			t.Errorf("event %d changed:\nbefore %v\nafter  %v", i, events[i], decoded[i])
		}
	}
	// The trail has to survive as a trail, not only as events.
	if err := evidence.ValidateChain(decoded); err != nil {
		t.Errorf("ValidateChain after the round trip: %v", err)
	}
}

// protojson is free to vary insignificant whitespace between runs, so the
// encoder compacts. Two runs of the same events are the same bytes.
func TestEncodeIsByteStable(t *testing.T) {
	first := encode(t, trailWithPayloads(t))
	second := encode(t, trailWithPayloads(t))
	if !bytes.Equal(first, second) {
		t.Errorf("two runs differ:\n%s\n%s", first, second)
	}
	if bytes.Contains(first, []byte(", ")) || bytes.Contains(first, []byte(": ")) {
		t.Errorf("the output carries insignificant whitespace: %s", first)
	}

	// The whole line, spelled out: field order, camelCase names, the enum by
	// name and no whitespace anywhere. protojson picks its own spacing per
	// build, so without the compaction step this literal holds only on the
	// builds that happened to choose none.
	b := trailBuilder(t, "req-1", "evt")
	const want = `{"eventId":"evt-1","kind":"EVENT_KIND_ACTION_STARTED","requestId":"req-1",` +
		`"runId":"run-1","projectId":"proj-1","tenantId":"tenant-1",` +
		`"occurredAt":"2026-09-09T12:00:00Z","schemaVersion":"1.0",` +
		`"enforcementMode":"ENFORCEMENT_MODE_ENFORCE","executionId":"exec-1"}` + "\n"
	if got := string(encode(t, []*controlv1.Event{b.Started("exec-1")})); got != want {
		t.Errorf("one event encodes as\n%s\nwant\n%s", got, want)
	}
}

// One event is one line whatever a string field holds, for a reader that splits
// on the newline byte and for one that splits on every Unicode line break. JSON
// escapes the C0 controls inside a string, so a newline or a carriage return
// never reaches the file raw; the other line breaks a reader may split on are
// the encoder's to escape. A field whose line break reached the file raw would
// split one record into two for whoever reads it that way.
func TestEncodeKeepsOneEventOnOneLine(t *testing.T) {
	b := trailBuilder(t, "req-1", "evt")
	event := b.Proposed(&controlv1.ActionEnvelope{
		RequestId: "req\n1",
		// The separator is built from its number, so the source holds no
		// character its reader cannot see.
		Arguments: &controlv1.Arguments{
			RedactedPreview: "first\nsecond\r\nthird" + string(rune(0x2028)) + "fourth",
		},
	})

	wire := encode(t, []*controlv1.Event{event})
	if count := bytes.Count(wire, []byte("\n")); count != 1 {
		t.Fatalf("%d newlines for one event: %q", count, wire)
	}
	if count := unicodeLineBreaks(wire); count != 1 {
		t.Fatalf("%d Unicode line breaks for one event: %q", count, wire)
	}
	decoded, err := evidence.DecodeJSONL(bytes.NewReader(wire), 1)
	if err != nil {
		t.Fatalf("DecodeJSONL: %v", err)
	}
	if !proto.Equal(event, decoded[0]) {
		t.Errorf("event changed:\nbefore %v\nafter  %v", event, decoded[0])
	}
}

// mustEscape is every rune the encoder writes as a \u escape, spelled out here
// rather than read from the encoder, so that a rune dropped from its table
// fails a test instead of agreeing with it: DEL and the C1 controls, NEL and
// CSI among them, the line and paragraph separators, and the twelve
// bidirectional controls.
func mustEscape() []rune {
	runes := []rune{
		0x2028, 0x2029,
		0x061c, 0x200e, 0x200f,
		0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
		0x2066, 0x2067, 0x2068, 0x2069,
	}
	for r := rune(0x7f); r <= 0x9f; r++ {
		runes = append(runes, r)
	}
	return runes
}

// unicodeLineBreaks counts the line breaks a reader with Unicode line semantics
// finds, the set Python's str.splitlines splits on: LF, CR, a CRLF pair once,
// VT, FF, the separators FS, GS and RS, NEL, and the line and paragraph
// separators.
func unicodeLineBreaks(b []byte) int {
	s := string(b)
	breaks := 0
	for i, r := range s {
		switch r {
		case '\n':
			if i == 0 || s[i-1] != '\r' {
				breaks++
			}
		case '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			breaks++
		}
	}
	return breaks
}

// writtenLinesProblem says what is wrong with the lines EncodeJSONL wrote for
// a number of events, or "" when nothing is: each event is one line for every
// reader, and no rune the encoder escapes is left raw. The property and the
// fuzz target both ask it, one of them from a *rapid.T.
func writtenLinesProblem(wire []byte, events int) string {
	if got := unicodeLineBreaks(wire); got != events {
		return fmt.Sprintf("%d line breaks for %d events: %q", got, events, wire)
	}
	for _, r := range mustEscape() {
		if bytes.ContainsRune(wire, r) {
			return fmt.Sprintf("the written lines hold %U raw: %q", r, wire)
		}
	}
	return ""
}

// One line for every reader, and nothing on it that a reader takes for a
// command. protojson escapes the C0 controls, the quote and the backslash, and
// writes the rest raw, so without the encoder's own escaping a record reached a
// Unicode line splitter as several invalid ones, cat delivered a raw CSI to a
// terminal, and a bidirectional override reordered what a reviewer saw. Each
// rune goes in three places, a map key inside a payload, a payload field and a
// top-level field, because the escape has to hold wherever a string sits.
func TestEncodeEscapesWhatAReaderCouldTakeForALineBreakOrACommand(t *testing.T) {
	for _, r := range mustEscape() {
		t.Run(fmt.Sprintf("%U", r), func(t *testing.T) {
			text := "x" + string(r) + "y"
			b := trailBuilder(t, "req-1", "evt")
			events := []*controlv1.Event{
				b.Proposed(&controlv1.ActionEnvelope{
					RequestId: "req-1",
					Principal: &controlv1.Principal{Id: "user-1", Attributes: map[string]string{text: "v"}},
				}),
				b.ApprovalRequested(&controlv1.Approval{ApprovalId: "app-1", Reason: text}),
				b.Started(text),
			}
			wire := encode(t, events)

			if bytes.ContainsRune(wire, r) {
				t.Errorf("the written lines hold %U raw: %q", r, wire)
			}
			escape := fmt.Sprintf(`\u%04x`, r)
			if got := bytes.Count(wire, []byte(escape)); got != len(events) {
				t.Errorf("the written lines hold %s %d times, want %d, once per place the rune sits: %q",
					escape, got, len(events), wire)
			}
			if got := unicodeLineBreaks(wire); got != len(events) {
				t.Errorf("a reader that splits on Unicode line breaks finds %d lines, want %d", got, len(events))
			}

			decoded, err := evidence.DecodeJSONL(bytes.NewReader(wire), len(events))
			if err != nil {
				t.Fatalf("DecodeJSONL: %v", err)
			}
			for i := range events {
				if !proto.Equal(events[i], decoded[i]) {
					t.Errorf("event %d changed:\nbefore %v\nafter  %v", i, events[i], decoded[i])
				}
			}
		})
	}
}

// The other side of the same rule: the encoder escapes the runes above and
// nothing else. The neighbours of each range, and ordinary text beyond ASCII,
// reach the line as the producer wrote them, so a line is no longer than it has
// to be.
func TestEncodeLeavesOtherTextAsItIs(t *testing.T) {
	for _, r := range []rune{
		'~', 0xa0, // either side of DEL and the C1 controls
		0x061b, 0x061d, // either side of the Arabic letter mark
		0x200d, 0x2010, // either side of the two directional marks
		0x2027, 0x202f, // either side of the separators and the embeddings
		0x2065, 0x206a, // either side of the isolates
		0xe9, 0x20ac, 0x1f600,
	} {
		t.Run(fmt.Sprintf("%U", r), func(t *testing.T) {
			event := trailBuilder(t, "req-1", "evt").Started("x" + string(r) + "y")
			if wire := encode(t, []*controlv1.Event{event}); !bytes.ContainsRune(wire, r) {
				t.Errorf("%U did not reach the line as written: %q", r, wire)
			}
		})
	}
}

func TestEncodeRefusals(t *testing.T) {
	b := trailBuilder(t, "req-1", "evt")

	t.Run("nil event", func(t *testing.T) {
		var buf bytes.Buffer
		err := evidence.EncodeJSONL(&buf, []*controlv1.Event{b.Started("exec-1"), nil})
		if !errors.Is(err, evidence.ErrNilEvent) {
			t.Errorf("EncodeJSONL: got %v, want ErrNilEvent", err)
		}
	})

	t.Run("a line over the limit", func(t *testing.T) {
		big := b.Proposed(&controlv1.ActionEnvelope{
			Arguments: &controlv1.Arguments{RedactedPreview: strings.Repeat("a", evidence.MaxLineBytes)},
		})
		err := evidence.EncodeJSONL(io.Discard, []*controlv1.Event{big})
		if !errors.Is(err, evidence.ErrLineTooLong) {
			t.Errorf("EncodeJSONL: got %v, want ErrLineTooLong", err)
		}
	})

	// A string field holds bytes, not runes, so a caller can put a broken
	// sequence in one. JSON cannot carry it, and the encoder says so rather
	// than writing a line no reader will accept.
	t.Run("a string that is not utf-8", func(t *testing.T) {
		event := b.Started("exec-\xff\xfe")
		err := evidence.EncodeJSONL(io.Discard, []*controlv1.Event{event})
		if err == nil {
			t.Fatal("EncodeJSONL accepted a string that is not valid UTF-8")
		}
	})

	t.Run("the writer fails", func(t *testing.T) {
		want := errors.New("disk is gone")
		err := evidence.EncodeJSONL(failingWriter{want}, []*controlv1.Event{b.Started("exec-1")})
		if !errors.Is(err, want) {
			t.Errorf("EncodeJSONL: got %v, want the writer's own error", err)
		}
	})

	t.Run("no events writes nothing", func(t *testing.T) {
		var buf bytes.Buffer
		if err := evidence.EncodeJSONL(&buf, nil); err != nil {
			t.Fatalf("EncodeJSONL: %v", err)
		}
		if buf.Len() != 0 {
			t.Errorf("wrote %q for no events", buf.String())
		}
	})
}

// The reader refuses an unknown JSON field rather than dropping it, and the
// writer has to hold the same line. protojson drops what it cannot name without
// a word, so a relay that read a later minor version's event over binary
// protobuf and wrote it here would write a record missing the field a producer
// thought mattered, and that record would then validate.
func TestEncodeRefusesAnEventCarryingAFieldThisBuildCannotName(t *testing.T) {
	unknown := protowire.AppendTag(nil, 999, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 1)

	// What a relay holds: bytes from a producer this build does not share a
	// schema with, parsed by this build, which keeps what it could not name.
	fromALaterVersion := func(t *testing.T, m proto.Message, into proto.Message) {
		t.Helper()
		raw, err := proto.Marshal(m)
		if err != nil {
			t.Fatalf("proto.Marshal: %v", err)
		}
		if err := proto.Unmarshal(append(raw, unknown...), into); err != nil {
			t.Fatalf("proto.Unmarshal: %v", err)
		}
		if len(into.ProtoReflect().GetUnknown()) == 0 {
			t.Fatal("the parsed message kept no unknown field, so this test proves nothing")
		}
	}

	t.Run("on the event", func(t *testing.T) {
		b := trailBuilder(t, "req-1", "evt")
		event := &controlv1.Event{}
		fromALaterVersion(t, b.Started("exec-1"), event)

		if err := evidence.EncodeJSONL(io.Discard, []*controlv1.Event{event}); !errors.Is(err, evidence.ErrUnknownField) {
			t.Errorf("EncodeJSONL: got %v, want ErrUnknownField", err)
		}
	})

	// A later minor is at least as likely to add a field to a payload as to the
	// envelope around it, and protojson drops it just as quietly.
	t.Run("on a payload", func(t *testing.T) {
		b := trailBuilder(t, "req-1", "evt")
		decision := &controlv1.Decision{}
		fromALaterVersion(t, &controlv1.Decision{DecisionId: "dec-1"}, decision)

		if err := evidence.EncodeJSONL(io.Discard, []*controlv1.Event{b.Decided(decision)}); !errors.Is(err, evidence.ErrUnknownField) {
			t.Errorf("EncodeJSONL: got %v, want ErrUnknownField", err)
		}
	})

	// A repeated message is a place the walk has to step into element by
	// element, and a delegation chain is where a later version would most
	// plausibly add one.
	t.Run("inside one element of a repeated message", func(t *testing.T) {
		b := trailBuilder(t, "req-1", "evt")
		hop := &controlv1.Delegation{}
		fromALaterVersion(t, &controlv1.Delegation{From: "a", To: "b"}, hop)
		env := &controlv1.ActionEnvelope{
			RequestId:  "req-1",
			Delegation: []*controlv1.Delegation{{From: "root", To: "a"}, hop},
		}

		if err := evidence.EncodeJSONL(io.Discard, []*controlv1.Event{b.Proposed(env)}); !errors.Is(err, evidence.ErrUnknownField) {
			t.Errorf("EncodeJSONL: got %v, want ErrUnknownField", err)
		}
	})

	// The controls. Without them the checks above pass just as well when the
	// walk refuses every event with a payload, and a walk that took a map field
	// for a message field would read a map entry as one and stop being a walk.
	t.Run("a full payload this build can name still encodes", func(t *testing.T) {
		if err := evidence.EncodeJSONL(io.Discard, trailWithPayloads(t)); err != nil {
			t.Errorf("EncodeJSONL: %v", err)
		}
	})

	t.Run("a map field and a repeated message still encode", func(t *testing.T) {
		b := trailBuilder(t, "req-1", "evt")
		env := &controlv1.ActionEnvelope{
			RequestId:  "req-1",
			Principal:  &controlv1.Principal{Id: "user-1", Attributes: map[string]string{"team": "core"}},
			Resource:   &controlv1.Resource{Labels: map[string]string{"tier": "gold"}},
			Delegation: []*controlv1.Delegation{{From: "root", To: "a"}},
		}
		if err := evidence.EncodeJSONL(io.Discard, []*controlv1.Event{b.Proposed(env)}); err != nil {
			t.Errorf("EncodeJSONL: %v", err)
		}
	})
}

// The walk over an event's tree has no depth bound, because the v1 contract has
// no message that can contain itself. That is a property of the schema rather
// than of this package, so it is asserted rather than assumed: a later version
// that adds a recursive message, or a google.protobuf.Struct, needs a bound
// before it lands, and this is where that shows up.
func TestTheEventSchemaHasNoMessageThatCanContainItself(t *testing.T) {
	onStack := map[protoreflect.FullName]bool{}

	var walk func(md protoreflect.MessageDescriptor, path string)
	walk = func(md protoreflect.MessageDescriptor, path string) {
		if onStack[md.FullName()] {
			t.Errorf("%s can contain itself, reached by %s", md.FullName(), path)
			return
		}
		onStack[md.FullName()] = true
		defer delete(onStack, md.FullName())

		fields := md.Fields()
		for i := range fields.Len() {
			fd := fields.Get(i)
			switch {
			case fd.IsMap():
				if value := fd.MapValue().Message(); value != nil {
					walk(value, path+"."+string(fd.Name())+"[]")
				}
			case fd.Message() != nil:
				walk(fd.Message(), path+"."+string(fd.Name()))
			}
		}
	}

	walk((&controlv1.Event{}).ProtoReflect().Descriptor(), "Event")
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

// The hostile table. Every entry is a byte sequence a file could hold after a
// crash, an edit nobody recorded, or a producer from somewhere else.
func TestDecodeRefusesMalformedLines(t *testing.T) {
	const valid = `{"eventId":"evt-1","kind":"EVENT_KIND_ACTION_PROPOSED","requestId":"req-1"}`

	for _, tc := range []struct {
		name  string
		input string
	}{
		{"an empty line", "\n"},
		{"a line of spaces", "   \n"},
		{"a line of tabs", "\t\t\n"},
		{"a blank line between events", valid + "\n\n" + valid + "\n"},
		{"null", "null\n"},
		{"an empty array", "[]\n"},
		{"an array of events", "[" + valid + "]\n"},
		{"a bare string", `"an event"` + "\n"},
		{"a number", "123\n"},
		{"true", "true\n"},
		{"an unknown field", `{"eventId":"a","bogusSecurityField":true}` + "\n"},
		{"a field of the wrong type", `{"eventId":123}` + "\n"},
		{"an unknown enum name", `{"kind":"EVENT_KIND_FROM_THE_FUTURE"}` + "\n"},
		{"a duplicated key", `{"eventId":"a","eventId":"b"}` + "\n"},
		{"two objects on one line", valid + " " + valid + "\n"},
		{"trailing bytes after the object", valid + "trailing\n"},
		{"a truncated final line", valid + "\n" + `{"eventId":"evt-2","kin`},
		{"a truncated first line", `{"eventId":"evt-1",` + "\n" + valid + "\n"},
		{"carriage return as the only terminator", valid + "\r" + valid + "\r"},
		{"not json at all", "hello\n"},
		{"a nul byte", "\x00\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events, err := evidence.DecodeJSONL(strings.NewReader(tc.input), 16)
			if !errors.Is(err, evidence.ErrMalformedLine) {
				t.Errorf("DecodeJSONL: got %v, want ErrMalformedLine", err)
			}
			if events != nil {
				t.Errorf("DecodeJSONL returned %d events alongside the refusal", len(events))
			}
		})
	}
}

func TestDecodeAccepts(t *testing.T) {
	const valid = `{"eventId":"evt-1","kind":"EVENT_KIND_ACTION_PROPOSED","requestId":"req-1"}`

	for _, tc := range []struct {
		name  string
		input string
		want  int
	}{
		{"nothing at all", "", 0},
		{"one line", valid + "\n", 1},
		{"a last line with no newline", valid, 1},
		{"two lines", valid + "\n" + valid + "\n", 2},
		{"crlf endings", valid + "\r\n" + valid + "\r\n", 2},
		{"proto field names", `{"event_id":"evt-1","request_id":"req-1"}` + "\n", 1},
		// An empty object is a well formed Event and never a well formed
		// trail. Which of the two a caller needs is ValidateChain's question.
		{"an empty object", "{}\n", 1},
		// An undeclared enum number is what a trail from a later minor version
		// carries. event.proto makes it INDETERMINATE to a reader rather than
		// an error, so the decoder keeps it and ValidateChain reports it.
		{"an undeclared enum number", `{"eventId":"evt-1","kind":99}` + "\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events, err := evidence.DecodeJSONL(strings.NewReader(tc.input), 16)
			if err != nil {
				t.Fatalf("DecodeJSONL: %v", err)
			}
			if len(events) != tc.want {
				t.Errorf("decoded %d events, want %d", len(events), tc.want)
			}
		})
	}
}

// The seam between the two halves of this file, stated as a test: decoding says
// the bytes are an Event, and only ValidateChain says the events are a trail.
func TestDecodedEmptyObjectIsNotATrail(t *testing.T) {
	events, err := evidence.DecodeJSONL(strings.NewReader("{}\n"), 1)
	if err != nil {
		t.Fatalf("DecodeJSONL: %v", err)
	}
	if err := evidence.ValidateChain(events); !errors.Is(err, evidence.ErrChainBroken) {
		t.Errorf("ValidateChain: got %v, want ErrChainBroken", err)
	}
}

func TestDecodeLimits(t *testing.T) {
	const valid = `{"eventId":"evt-1","kind":"EVENT_KIND_ACTION_PROPOSED","requestId":"req-1"}`
	three := strings.Repeat(valid+"\n", 3)

	t.Run("a negative limit is refused, never read as unlimited", func(t *testing.T) {
		events, err := evidence.DecodeJSONL(strings.NewReader(three), -1)
		if !errors.Is(err, evidence.ErrInvalidLimit) {
			t.Errorf("DecodeJSONL: got %v, want ErrInvalidLimit", err)
		}
		if events != nil {
			t.Errorf("DecodeJSONL returned %d events for a negative limit", len(events))
		}
	})

	t.Run("a limit of zero admits nothing", func(t *testing.T) {
		if _, err := evidence.DecodeJSONL(strings.NewReader(three), 0); !errors.Is(err, evidence.ErrTooManyEvents) {
			t.Errorf("DecodeJSONL: got %v, want ErrTooManyEvents", err)
		}
	})

	t.Run("a limit of zero over empty input returns nothing", func(t *testing.T) {
		events, err := evidence.DecodeJSONL(strings.NewReader(""), 0)
		if err != nil {
			t.Fatalf("DecodeJSONL: %v", err)
		}
		if len(events) != 0 {
			t.Errorf("decoded %d events, want none", len(events))
		}
	})

	t.Run("exactly the limit is accepted", func(t *testing.T) {
		events, err := evidence.DecodeJSONL(strings.NewReader(three), 3)
		if err != nil {
			t.Fatalf("DecodeJSONL: %v", err)
		}
		if len(events) != 3 {
			t.Errorf("decoded %d events, want 3", len(events))
		}
	})

	// A limit is a promise about what a caller will hold, not a request to
	// reserve it. Sizing the first allocation from it turns a caller's
	// unchecked int into a slice this package cannot make, and make refuses a
	// capacity that large by panicking, in the package that runs when
	// something has already gone wrong.
	t.Run("an enormous limit is not an enormous allocation", func(t *testing.T) {
		events, err := evidence.DecodeJSONL(strings.NewReader(valid+"\n"), math.MaxInt)
		if err != nil {
			t.Fatalf("DecodeJSONL: %v", err)
		}
		if len(events) != 1 {
			t.Errorf("decoded %d events, want 1", len(events))
		}
	})

	// The line past the limit is deliberately unparseable. A decoder that
	// parsed first and counted afterwards would report the parse failure, so
	// ErrTooManyEvents here is what shows the count is checked first and the
	// event past the limit is never built.
	t.Run("one past the limit is refused before it is parsed", func(t *testing.T) {
		input := strings.Repeat(valid+"\n", 3) + "{not json at all\n"
		_, err := evidence.DecodeJSONL(strings.NewReader(input), 3)
		if !errors.Is(err, evidence.ErrTooManyEvents) {
			t.Fatalf("DecodeJSONL: got %v, want ErrTooManyEvents", err)
		}
		if errors.Is(err, evidence.ErrMalformedLine) {
			t.Errorf("DecodeJSONL: got %v, so the line past the limit was parsed", err)
		}
	})
}

// The line bound, at the byte. A line of exactly MaxLineBytes is the longest
// one that can be read, and one byte more is refused.
func TestDecodeLineLengthBoundary(t *testing.T) {
	// {"eventId":"<pad>"} is the shortest Event with one variable-length field.
	const overhead = len(`{"eventId":""}`)

	line := func(total int) string {
		return `{"eventId":"` + strings.Repeat("a", total-overhead) + `"}` + "\n"
	}

	t.Run("exactly the limit", func(t *testing.T) {
		events, err := evidence.DecodeJSONL(strings.NewReader(line(evidence.MaxLineBytes)), 1)
		if err != nil {
			t.Fatalf("DecodeJSONL: %v", err)
		}
		if got := len(events[0].GetEventId()); got != evidence.MaxLineBytes-overhead {
			t.Errorf("event_id is %d bytes, want %d", got, evidence.MaxLineBytes-overhead)
		}
	})

	t.Run("one byte over the limit", func(t *testing.T) {
		_, err := evidence.DecodeJSONL(strings.NewReader(line(evidence.MaxLineBytes+1)), 1)
		if !errors.Is(err, evidence.ErrLineTooLong) {
			t.Errorf("DecodeJSONL: got %v, want ErrLineTooLong", err)
		}
	})

	// A last line with no newline is bounded the same way: the buffer fills
	// before the decoder can decide the line has ended.
	t.Run("over the limit with no newline at all", func(t *testing.T) {
		over := strings.TrimSuffix(line(evidence.MaxLineBytes+1), "\n")
		if _, err := evidence.DecodeJSONL(strings.NewReader(over), 1); !errors.Is(err, evidence.ErrLineTooLong) {
			t.Errorf("DecodeJSONL: got %v, want ErrLineTooLong", err)
		}
	})
}

// The line bound holds whatever reader a caller passes. bufio.NewReaderSize
// hands back a *bufio.Reader it is given when that reader's buffer is already
// large enough, so without care the bound is whatever buffer the caller chose,
// and a line the encoder refuses to write reads.
func TestDecodeLineBoundHoldsForACallersBufferedReader(t *testing.T) {
	const overhead = len(`{"eventId":""}`)
	line := func(total int) string {
		return `{"eventId":"` + strings.Repeat("a", total-overhead) + `"}` + "\n"
	}

	for _, tc := range []struct {
		name string
		size int
	}{
		{"a reader four times the bound", 1 << 20},
		// Exactly the decoder's own size, and bufio's default, as controls:
		// the first is handed back as it is, the second is too small to be.
		{"a reader of exactly the decoder's size", evidence.MaxLineBytes + 1},
		{"the default reader", 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			over := bufio.NewReaderSize(strings.NewReader(line(evidence.MaxLineBytes+1)), tc.size)
			if _, err := evidence.DecodeJSONL(over, 1); !errors.Is(err, evidence.ErrLineTooLong) {
				t.Errorf("one byte over the bound: got %v, want ErrLineTooLong", err)
			}

			// The same reader still reads a line at the bound, so the refusal
			// above is the bound and not a reader the decoder cannot use.
			at := bufio.NewReaderSize(strings.NewReader(line(evidence.MaxLineBytes)), tc.size)
			events, err := evidence.DecodeJSONL(at, 1)
			if err != nil {
				t.Fatalf("a line at the bound: %v", err)
			}
			if got := len(events[0].GetEventId()); got != evidence.MaxLineBytes-overhead {
				t.Errorf("event_id is %d bytes, want %d", got, evidence.MaxLineBytes-overhead)
			}
		})
	}
}

// The encoder's bound at the byte, measured on the line as written. A line of
// exactly MaxLineBytes is written and reads back, and one byte more is refused.
// The second pair ends in an escaped separator, three bytes raw and six
// written: a bound measured before escaping would write a line three bytes
// longer than the one it checked, past the one the decoder reads.
func TestEncodeLineLengthBoundary(t *testing.T) {
	const overhead = len(`{"eventId":""}`)
	const escaped = len("\\u") + 4
	separator := string(rune(0x2028))

	for _, tc := range []struct {
		name string
		id   func(total int) string // an event_id whose written line is total bytes long
	}{
		{"plain text", func(total int) string { return strings.Repeat("a", total-overhead) }},
		{"an escaped separator at the end", func(total int) string {
			return strings.Repeat("a", total-overhead-escaped) + separator
		}},
	} {
		t.Run(tc.name+", exactly the limit", func(t *testing.T) {
			event := &controlv1.Event{EventId: tc.id(evidence.MaxLineBytes)}
			var buf bytes.Buffer
			if err := evidence.EncodeJSONL(&buf, []*controlv1.Event{event}); err != nil {
				t.Fatalf("EncodeJSONL: %v", err)
			}
			// Checked rather than assumed: the case sits at the limit because
			// the written bytes say so, not because the arithmetic above does.
			if got := buf.Len(); got != evidence.MaxLineBytes+1 {
				t.Fatalf("wrote %d bytes, want the limit and a newline, %d", got, evidence.MaxLineBytes+1)
			}
			decoded, err := evidence.DecodeJSONL(&buf, 1)
			if err != nil {
				t.Fatalf("DecodeJSONL of a line the encoder wrote: %v", err)
			}
			if !proto.Equal(event, decoded[0]) {
				t.Error("the event changed on its way through the file")
			}
		})
		t.Run(tc.name+", one byte over", func(t *testing.T) {
			event := &controlv1.Event{EventId: tc.id(evidence.MaxLineBytes + 1)}
			if err := evidence.EncodeJSONL(io.Discard, []*controlv1.Event{event}); !errors.Is(err, evidence.ErrLineTooLong) {
				t.Errorf("EncodeJSONL: got %v, want ErrLineTooLong", err)
			}
		})
	}
}

// The codec's one asymmetry, held still rather than left to be met by
// surprise. The two bounds are over different bytes: the decoder's is over the
// line it reads, the encoder's over the line it writes, and the same event can
// be inside one and outside the other. A line grows on the way back in two
// ways. A declared enum arrives as a number and leaves as a name, twenty-seven
// bytes longer for the kind below, and a rune the encoder escapes arrives raw
// and leaves as six bytes.
//
// Both directions refuse loudly, so nothing is written that cannot be read and
// nothing is read that is silently truncated. FuzzDecodeJSONL names this case
// for the same reason.
func TestReEncodingCanCrossTheLineBound(t *testing.T) {
	t.Run("an enum given as a number", func(t *testing.T) {
		const overhead = len(`{"kind":1,"eventId":""}`)
		line := `{"kind":1,"eventId":"` + strings.Repeat("a", evidence.MaxLineBytes-overhead) + `"}` + "\n"

		events, err := evidence.DecodeJSONL(strings.NewReader(line), 1)
		if err != nil {
			t.Fatalf("DecodeJSONL of a line at the bound: %v", err)
		}
		if got := events[0].GetKind(); got != controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED {
			t.Fatalf("kind is %s, so the numeric enum is not what makes the line grow", got)
		}
		if err := evidence.EncodeJSONL(io.Discard, events); !errors.Is(err, evidence.ErrLineTooLong) {
			t.Errorf("EncodeJSONL: got %v, want ErrLineTooLong", err)
		}
	})

	t.Run("a separator given raw", func(t *testing.T) {
		const overhead = len(`{"eventId":""}`)
		separator := string(rune(0x2028))
		line := `{"eventId":"` + strings.Repeat("a", evidence.MaxLineBytes-overhead-len(separator)) +
			separator + `"}` + "\n"

		events, err := evidence.DecodeJSONL(strings.NewReader(line), 1)
		if err != nil {
			t.Fatalf("DecodeJSONL of a line at the bound: %v", err)
		}
		if err := evidence.EncodeJSONL(io.Discard, events); !errors.Is(err, evidence.ErrLineTooLong) {
			t.Errorf("EncodeJSONL: got %v, want ErrLineTooLong", err)
		}
	})
}

// floodReader supplies bytes that never contain a newline and refuses to serve
// more than its cap. A decoder that buffered a line before bounding it would
// read to the cap and report the flood's error; a bounded one stops after the
// buffer it declared.
type floodReader struct {
	served int
	cap    int
}

var errFlood = errors.New("flood reader: asked for more than the cap")

func (f *floodReader) Read(p []byte) (int, error) {
	if f.served >= f.cap {
		return 0, errFlood
	}
	n := min(len(p), f.cap-f.served)
	for i := range p[:n] {
		p[i] = 'a'
	}
	f.served += n
	return n, nil
}

// The bound that matters: an endless line costs the decoder one buffer, not the
// length of the line. Without it a 2 GB line is a 2 GB allocation and this test
// is the only thing standing between a reader and that.
func TestDecodeDoesNotBufferAnOversizedLine(t *testing.T) {
	flood := &floodReader{cap: 8 * evidence.MaxLineBytes}

	_, err := evidence.DecodeJSONL(flood, 16)
	if !errors.Is(err, evidence.ErrLineTooLong) {
		t.Fatalf("DecodeJSONL: got %v, want ErrLineTooLong", err)
	}
	if errors.Is(err, errFlood) {
		t.Fatal("the decoder read to the end of the flood, so it was bounding nothing")
	}
	// One byte more than the limit is enough to know the line is too long: the
	// buffer is the limit plus the newline that never arrived.
	if want := evidence.MaxLineBytes + 1; flood.served > want {
		t.Errorf("the decoder read %d bytes of an endless line, want at most %d", flood.served, want)
	}
	t.Logf("read %d bytes of an endless line before refusing it (cap %d)", flood.served, flood.cap)
}

// A reader that fails part way through is not a malformed line: the difference
// between "this file says something wrong" and "the file could not be read" is
// what a caller acts on.
func TestDecodeReportsAReadFailure(t *testing.T) {
	want := errors.New("device is gone")
	r := io.MultiReader(strings.NewReader(`{"eventId":"evt-1"}`+"\n"), failingReader{want})

	events, err := evidence.DecodeJSONL(r, 16)
	if !errors.Is(err, want) {
		t.Errorf("DecodeJSONL: got %v, want the reader's own error", err)
	}
	if errors.Is(err, evidence.ErrMalformedLine) {
		t.Errorf("DecodeJSONL: got %v, which blames the file for the reader's failure", err)
	}
	if events != nil {
		t.Errorf("DecodeJSONL returned %d events alongside a read failure", len(events))
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

// A refusal travels into a log and often into a record of its own. protojson
// quotes the token it refused verbatim, so without a bound one bad line is a
// quarter of a megabyte of operator log, and an invalid bare token puts a raw
// control byte in it. pkg/contract holds this line in both directions
// (effect.go, validate.go) and this is the package whose refusals are most
// likely to be written down.
func TestDecodeRefusalDoesNotCarryTheLineBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"a very long field name", `{"` + strings.Repeat("Z", 200000) + `":1}` + "\n"},
		{"a very long number", `{"kind":` + strings.Repeat("9", 200000) + "}\n"},
		{"a raw escape byte in a bare token", "{\"kind\":\x1b[31m}\n"},
		{"a nul byte in a bare token", "{\"kind\":\x00}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := evidence.DecodeJSONL(strings.NewReader(tc.input), 16)
			if !errors.Is(err, evidence.ErrMalformedLine) {
				t.Fatalf("DecodeJSONL: got %v, want ErrMalformedLine", err)
			}
			message := err.Error()
			if len(message) > 512 {
				t.Errorf("the refusal is %d bytes long: %.120q...", len(message), message)
			}
			for i := range len(message) {
				if c := message[i]; c < 0x20 || c == 0x7f {
					t.Errorf("byte %d of the refusal is the control byte %#x: %q", i, c, message)
					break
				}
			}
			if !utf8.ValidString(message) {
				t.Errorf("the refusal is not valid UTF-8: %q", message)
			}
		})
	}
}

// TestDecodeRefusalNamesNoSubmittedText: a refusal says where the line went
// wrong and never what it held, since a sender can put a credential or a
// prompt in a value or a member name, and the refusal is what gets logged.
func TestDecodeRefusalNamesNoSubmittedText(t *testing.T) {
	const marker = "SECRETMARKER"
	for _, input := range []string{
		`{"kind":"` + marker + `"}`,
		`{"` + marker + `":1}`,
		`{"eventId":"` + marker + `","kind":7.5}`,
		`{"eventId":` + marker + `}`,
		`{"eventId":"` + marker,
	} {
		_, err := evidence.DecodeJSONL(strings.NewReader(input+"\n"), 16)
		if !errors.Is(err, evidence.ErrMalformedLine) {
			t.Fatalf("%s: DecodeJSONL = %v, want ErrMalformedLine", input, err)
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: the refusal repeats submitted text: %v", input, err)
		}
	}
}

// errors.Is unwraps. A reader whose failure wraps io.EOF would be read as the
// end of the input, and a truncated read would be reported as a complete one
// with a nil error. bufio hands back the underlying reader's error as it
// stands, so the end of the input is io.EOF itself and nothing else.
func TestDecodeDoesNotReadAWrappedEOFAsTheEndOfInput(t *testing.T) {
	const line = `{"eventId":"evt-1","requestId":"req-1"}` + "\n"
	wrapped := fmt.Errorf("read from the segment failed: %w", io.EOF)

	t.Run("a failure that wraps io.EOF is a failure", func(t *testing.T) {
		r := io.MultiReader(strings.NewReader(line), failingReader{wrapped})
		events, err := evidence.DecodeJSONL(r, 16)
		if !errors.Is(err, wrapped) {
			t.Fatalf("DecodeJSONL: got %d event(s) and err %v, want the reader's own failure", len(events), err)
		}
		if events != nil {
			t.Errorf("DecodeJSONL returned %d events alongside a read failure", len(events))
		}
	})

	// The control: the same shape with a bare io.EOF is the end of the input,
	// so the case above cannot pass by refusing every reader that stops.
	t.Run("a bare io.EOF is the end of the input", func(t *testing.T) {
		r := io.MultiReader(strings.NewReader(line), failingReader{io.EOF})
		events, err := evidence.DecodeJSONL(r, 16)
		if err != nil {
			t.Fatalf("DecodeJSONL: %v", err)
		}
		if len(events) != 1 {
			t.Errorf("decoded %d events, want 1", len(events))
		}
	})
}

// Whatever a Builder produces survives the file. The generated part is the
// sequence of kinds, the payload strings and the request id, because the inputs
// that break a codec are the ones nobody writes into a table: an empty string,
// a quote, a brace, a rune that is four bytes long.
func TestRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		requestID := rapid.StringMatching(`[a-zA-Z0-9_.:-]{1,40}`).Draw(rt, "request_id")
		kinds := declaredKinds()
		choices := rapid.SliceOfN(rapid.IntRange(0, len(kinds)-1), 1, 12).Draw(rt, "kinds")
		// Arbitrary text with the runes the encoder escapes mixed in, which
		// rapid's own string generator reaches too rarely to rely on.
		text := rapid.StringOf(rapid.OneOf(rapid.Rune(), rapid.RuneFrom(mustEscape()))).Draw(rt, "payload_text")

		b, err := evidence.NewBuilder(
			evidence.IDs{RequestID: requestID, ProjectID: "proj-1", TenantID: "tenant-1"},
			controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
			func() time.Time { return time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC) },
			counter("evt"),
		)
		if err != nil {
			rt.Fatalf("NewBuilder: %v", err)
		}

		events := make([]*controlv1.Event, 0, len(choices))
		for i, choice := range choices {
			kind := kinds[choice]
			event := buildKind(b, kind)
			if event == nil {
				rt.Fatalf("no constructor produces kind %s", kind)
			}
			// One event per sequence carries the generated string, so the
			// escaping path is exercised without making every line long.
			if i == 0 {
				event.Payload = &controlv1.Event_Approval{Approval: &controlv1.Approval{Reason: text}}
			}
			events = append(events, event)
		}

		var buf bytes.Buffer
		if err := evidence.EncodeJSONL(&buf, events); err != nil {
			rt.Fatalf("EncodeJSONL: %v", err)
		}
		// One line per event for every reader, whatever the text held.
		if problem := writtenLinesProblem(buf.Bytes(), len(events)); problem != "" {
			rt.Fatalf("%s", problem)
		}
		decoded, err := evidence.DecodeJSONL(&buf, len(events))
		if err != nil {
			rt.Fatalf("DecodeJSONL: %v", err)
		}
		if len(decoded) != len(events) {
			rt.Fatalf("decoded %d events, want %d", len(decoded), len(events))
		}
		for i := range events {
			if !proto.Equal(events[i], decoded[i]) {
				rt.Fatalf("event %d changed:\nbefore %v\nafter  %v", i, events[i], decoded[i])
			}
		}
	})
}

// counter is the id generator the property test uses; it takes no *testing.T,
// which is what the property test can supply.
func counter(prefix string) func() string {
	n := 0
	return func() string {
		n++
		return fmt.Sprintf("%s-%d", prefix, n)
	}
}
