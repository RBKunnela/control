package hookbridge_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/hookbridge"
)

type reader func(*hookbridge.Profile, []byte) (hookbridge.Event, error)

func readReference(p *hookbridge.Profile, raw []byte) (hookbridge.Event, error) {
	return hookbridge.ReadEvent(p, bytes.NewReader(raw))
}

// The event every refusal below changes in one place.
const plainAdmit = `{"event":"BeforeTool","session":"s-1","call":"c-1","tool":"refund","input":{"account":"acct-1", "amount":5}}`

type eventCase struct {
	name, raw string
	want      error
}

func eventRefusals() []eventCase {
	return []eventCase{
		{"a member named twice", `{"event":"BeforeTool","session":"s-1","call":"c-1","call":"c-2","tool":"refund","input":{}}`, hookbridge.ErrEventMalformed},
		{"a member named twice in another spelling", `{"event":"BeforeTool","session":"s-1","call":"c-1","tool":"refund","input":{},"input":{"a":1}}`, hookbridge.ErrEventMalformed},
		{"bytes after the object", plainAdmit + `{}`, hookbridge.ErrEventMalformed},
		{"text after the object", plainAdmit + ` x`, hookbridge.ErrEventMalformed},
		{"an array", `[` + plainAdmit + `]`, hookbridge.ErrEventMalformed},
		{"invalid UTF-8", strings.Replace(plainAdmit, "acct-1", "acct-\xff", 1), hookbridge.ErrEventEncoding},
		{"no event name", strings.Replace(plainAdmit, `"event":"BeforeTool",`, ``, 1), hookbridge.ErrEventMalformed},
		{"an event name the profile lacks", strings.Replace(plainAdmit, `BeforeTool`, `BeforeAnything`, 1), hookbridge.ErrUnknownEvent},
		{"no tool", strings.Replace(plainAdmit, `"tool":"refund",`, ``, 1), hookbridge.ErrEventMalformed},
		{"an empty tool", strings.Replace(plainAdmit, `"tool":"refund"`, `"tool":""`, 1), hookbridge.ErrEventMalformed},
		{"no call id", strings.Replace(plainAdmit, `"call":"c-1",`, ``, 1), hookbridge.ErrNoCallID},
		{"an empty call id", strings.Replace(plainAdmit, `"call":"c-1"`, `"call":""`, 1), hookbridge.ErrNoCallID},
		{"a call id that is a number", strings.Replace(plainAdmit, `"call":"c-1"`, `"call":7`, 1), hookbridge.ErrNoCallID},
		{"no session id", strings.Replace(plainAdmit, `"session":"s-1",`, ``, 1), hookbridge.ErrNoSession},
		{"no input on an admit", strings.Replace(plainAdmit, `,"input":{"account":"acct-1", "amount":5}`, ``, 1), hookbridge.ErrNoInput},
		{"a null input", strings.Replace(plainAdmit, `{"account":"acct-1", "amount":5}`, `null`, 1), hookbridge.ErrInputNotObject},
		{"a string input", strings.Replace(plainAdmit, `{"account":"acct-1", "amount":5}`, `"{\"account\":\"acct-1\"}"`, 1), hookbridge.ErrInputNotObject},
		{"an array input", strings.Replace(plainAdmit, `{"account":"acct-1", "amount":5}`, `[1]`, 1), hookbridge.ErrInputNotObject},
		{"a null input on a completion", `{"event":"AfterTool","session":"s-1","call":"c-1","tool":"refund","input":null}`, hookbridge.ErrInputNotObject},
	}
}

// refusalMisses returns every refusal read accepts or refuses for another
// reason.
func refusalMisses(p *hookbridge.Profile, read reader) []string {
	var miss []string
	for _, tc := range eventRefusals() {
		if _, err := read(p, []byte(tc.raw)); !errors.Is(err, tc.want) {
			miss = append(miss, tc.name+": "+errText(err)+", want "+tc.want.Error())
		}
	}
	return miss
}

func errText(err error) string {
	if err == nil {
		return "accepted"
	}
	return err.Error()
}

func TestEveryMalformedEventIsRefused(t *testing.T) {
	for _, m := range refusalMisses(neutral(t), readReference) {
		t.Error(m)
	}
}

// valueMisses returns every value read reads otherwise than the event wrote
// it.
func valueMisses(p *hookbridge.Profile, read reader) []string {
	var miss []string
	ev, err := read(p, []byte(plainAdmit))
	if err != nil {
		return []string{"the plain admit: " + err.Error()}
	}
	if ev.Name != "BeforeTool" || ev.Phase != hookbridge.PhaseAdmit || ev.Tool != "refund" || ev.CallID != "c-1" || ev.SessionID != "s-1" {
		miss = append(miss, "the plain admit read as "+ev.Name+" "+string(ev.Phase)+" "+ev.Tool+" "+ev.CallID+" "+ev.SessionID)
	}
	if string(ev.Input) != `{"account":"acct-1", "amount":5}` {
		miss = append(miss, "the input read as "+string(ev.Input))
	}
	ev, err = read(p, []byte(`{"event":"AfterTool","session":"s-1","call":"c-1","tool":"refund"}`))
	if err != nil || ev.Input != nil || ev.Phase != hookbridge.PhaseComplete {
		miss = append(miss, "a completion without input read as "+errText(err))
	}
	return append(miss, interruptMisses(p, read)...)
}

// interruptMisses returns every interrupt flag read reads otherwise than
// as true, false or unknown.
func interruptMisses(p *hookbridge.Profile, read reader) []string {
	var miss []string
	for _, tc := range []struct {
		flag string
		want hookbridge.Interrupt
	}{
		{``, hookbridge.InterruptUnknown},
		{`,"interrupted":"false"`, hookbridge.InterruptUnknown},
		{`,"interrupted":0`, hookbridge.InterruptUnknown},
		{`,"interrupted":null`, hookbridge.InterruptUnknown},
		{`,"interrupted":false`, hookbridge.InterruptNo},
		{`,"interrupted":true`, hookbridge.InterruptYes},
	} {
		raw := `{"event":"AfterToolFailed","session":"s-1","call":"c-1","tool":"refund","input":{"a":1}` + tc.flag + `}`
		ev, err := read(p, []byte(raw))
		if err != nil || ev.Interrupt != tc.want || ev.Phase != hookbridge.PhaseCompleteFailure {
			miss = append(miss, "interrupt flag "+tc.flag+" read as "+errText(err))
		}
	}
	return miss
}

func TestAnEventIsReadAsWritten(t *testing.T) {
	for _, m := range valueMisses(neutral(t), readReference) {
		t.Error(m)
	}
}

// A tool's response fills the event up to its bound and is read past, kept
// nowhere in what ReadEvent returns.
func TestAnEventIsBoundedAndItsResponseIsDropped(t *testing.T) {
	p := neutral(t)
	head := `{"event":"AfterTool","session":"s-1","call":"c-1","tool":"refund","input":{"a":1},"response":"`
	marker := strings.Repeat("R", int(p.MaxEventBytes)-len(head)-len(`"}`))
	at := head + marker + `"}`
	if len(at) != 4096 {
		t.Fatalf("the event is %d bytes, want 4096", len(at))
	}
	ev, err := hookbridge.ReadEvent(p, strings.NewReader(at))
	if err != nil {
		t.Fatalf("an event of exactly max_event_bytes: %v", err)
	}
	for _, field := range []string{ev.Name, ev.Tool, ev.CallID, ev.SessionID, string(ev.Input)} {
		if strings.Contains(field, "RRRR") {
			t.Fatalf("the response is kept in %q", field)
		}
	}
	over := strings.Replace(at, `"response":"`, `"response":"R`, 1)
	if _, err := hookbridge.ReadEvent(p, strings.NewReader(over)); !errors.Is(err, hookbridge.ErrEventTooLarge) {
		t.Fatalf("one byte more = %v", err)
	}
	if _, err := hookbridge.ReadEvent(nil, strings.NewReader(plainAdmit)); !errors.Is(err, hookbridge.ErrNoProfile) {
		t.Fatalf("no profile = %v", err)
	}
}

func TestNoRefusalQuotesTheEvent(t *testing.T) {
	p := neutral(t)
	for _, tc := range eventRefusals() {
		_, err := readReference(p, []byte(tc.raw))
		if err != nil && (strings.Contains(err.Error(), "acct-1") || strings.Contains(err.Error(), "refund")) {
			t.Errorf("%s: the refusal quotes the event: %v", tc.name, err)
		}
	}
}

func FuzzReadEvent(f *testing.F) {
	seedEvents(f)
	p := neutral(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		ev, err := hookbridge.ReadEvent(p, bytes.NewReader(raw))
		if err == nil {
			if problem := eventProblem(p, raw, ev); problem != "" {
				t.Fatal(problem)
			}
		}
	})
}

// eventProblem names what is wrong with an event ReadEvent accepted from raw.
func eventProblem(p *hookbridge.Profile, raw []byte, ev hookbridge.Event) string {
	switch {
	case ev.Tool == "" || ev.CallID == "" || ev.SessionID == "":
		return "accepted an event with an empty value"
	case p.Events[ev.Name] != ev.Phase:
		return "event " + ev.Name + " read as phase " + string(ev.Phase)
	case ev.Phase == hookbridge.PhaseAdmit && ev.Input == nil:
		return "an admit without input"
	case ev.Input != nil && (ev.Input[0] != '{' || !bytes.Contains(raw, ev.Input)):
		return "input " + string(ev.Input) + " is not an object the event wrote"
	}
	return ""
}

func seedEvents(f *testing.F) {
	names, err := filepath.Glob("testdata/neutral/fixtures/*.json")
	if err != nil || len(names) == 0 {
		f.Fatalf("no fixtures: %v", err)
	}
	for _, name := range names {
		raw, err := os.ReadFile(name) //nolint:gosec // G304: a fixture this package keeps
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	for _, tc := range eventRefusals() {
		f.Add([]byte(tc.raw))
	}
}
