package hookbridge

import (
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/guardana/control/internal/policy/strictjson"
)

// Interrupt is what an event says of whether the tool was stopped while it
// ran.
type Interrupt int

const (
	// InterruptUnknown is a flag that is absent or not a boolean. It is the
	// zero value, so an event that says nothing is never read as "not
	// interrupted".
	InterruptUnknown Interrupt = iota
	// InterruptNo is a flag written false.
	InterruptNo
	// InterruptYes is a flag written true.
	InterruptYes
)

// Event is the part of one hook event the bridge acts on. Every other member
// of the event, a tool's response included, is dropped as it is read.
type Event struct {
	Name      string
	Phase     Phase
	Tool      string
	CallID    string
	SessionID string
	// Input is the tool input's raw text exactly as the event wrote it, never
	// re-serialised. It is nil only for an event of a complete phase that
	// carries none.
	Input     []byte
	Interrupt Interrupt
}

// ReadEvent reads one event from r, at most the profile's max_event_bytes,
// as one JSON object of valid UTF-8 with nothing after it, each member named
// once.
func ReadEvent(p *Profile, r io.Reader) (Event, error) {
	if p == nil {
		return Event{}, ErrNoProfile
	}
	raw, err := readBounded(r, p.MaxEventBytes, ErrEventTooLarge)
	if err != nil {
		return Event{}, err
	}
	if !utf8.Valid(raw) {
		return Event{}, ErrEventEncoding
	}
	o, err := strictjson.ReadObject(raw)
	if err != nil {
		return Event{}, fmt.Errorf("%w: %w", ErrEventMalformed, err)
	}
	ev, err := readNames(p, o)
	if err != nil {
		return Event{}, err
	}
	m := p.Members
	input, present := o[m.Input]
	switch {
	case !present && ev.Phase == PhaseAdmit:
		return Event{}, ErrNoInput
	case present && (len(input) == 0 || input[0] != '{'):
		return Event{}, ErrInputNotObject
	case present:
		ev.Input = input
	}
	ev.Interrupt = readInterrupt(o[m.Interrupt])
	return ev, nil
}

// readInterrupt reads a flag written true or false; anything else, absence
// included, is unknown.
func readInterrupt(raw []byte) Interrupt {
	switch string(raw) {
	case "true":
		return InterruptYes
	case "false":
		return InterruptNo
	}
	return InterruptUnknown
}

// readNames reads the event's name, its phase and the strings that name the
// call, none of which may be empty.
func readNames(p *Profile, o strictjson.Object) (Event, error) {
	m := p.Members
	var ev Event
	var ok bool
	if ev.Name, ok = strictjson.String(o[m.Event]); !ok {
		return Event{}, fmt.Errorf("%w: no event name", ErrEventMalformed)
	}
	if ev.Phase, ok = p.Events[ev.Name]; !ok {
		return Event{}, ErrUnknownEvent
	}
	if ev.Tool, ok = strictjson.String(o[m.Tool]); !ok || ev.Tool == "" {
		return Event{}, fmt.Errorf("%w: no tool name", ErrEventMalformed)
	}
	if ev.CallID, ok = strictjson.String(o[m.CallID]); !ok || ev.CallID == "" {
		return Event{}, ErrNoCallID
	}
	if ev.SessionID, ok = strictjson.String(o[m.SessionID]); !ok || ev.SessionID == "" {
		return Event{}, ErrNoSession
	}
	return ev, nil
}

// readBounded reads all of r up to limit bytes and refuses one more with
// tooLarge.
func readBounded(r io.Reader, limit int64, tooLarge error) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, tooLarge
	}
	return raw, nil
}
