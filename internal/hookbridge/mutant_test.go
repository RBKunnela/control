package hookbridge_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/enforceclient"
	"github.com/guardana/control/internal/hookbridge"
)

func readScenarios() []scenario {
	adapt := func(b impl) reader {
		return func(p *hookbridge.Profile, raw []byte) (hookbridge.Event, error) {
			return b.read(p, bytes.NewReader(raw))
		}
	}
	return []scenario{
		{"every malformed event is refused", func(t *testing.T, b impl) []string { return refusalMisses(neutral(t), adapt(b)) }},
		{"every value is read as written", func(t *testing.T, b impl) []string { return valueMisses(neutral(t), adapt(b)) }},
	}
}

func suite() []scenario {
	return append(append(readScenarios(), preScenarios()...), postScenarios()...)
}

func TestTheBridgePassesEveryScenario(t *testing.T) {
	for _, sc := range suite() {
		t.Run(sc.name, func(t *testing.T) {
			for _, m := range sc.run(t, reference()) {
				t.Error(m)
			}
		})
	}
}

// Each mutant breaks one rule and must fail the suite; the scenarios that
// caught it are logged.
func TestEveryMutantFailsTheSuite(t *testing.T) {
	for _, m := range []struct {
		name string
		make func() impl
	}{
		{"drops a deny", dropsDeny},
		{"passes the proposed input when a rewrite is wanted", passesProposed},
		{"reports the authorized bytes as sent", reportsAuthorized},
		{"aborts in post", abortsInPost},
		{"decodes the event leniently", decodesLeniently},
	} {
		t.Run(m.name, func(t *testing.T) {
			var caught []string
			for _, sc := range suite() {
				if misses := sc.run(t, m.make()); len(misses) > 0 {
					caught = append(caught, sc.name+": "+misses[0])
				}
			}
			if len(caught) == 0 {
				t.Fatal("the mutant passed every scenario")
			}
			for _, c := range caught {
				t.Log(c)
			}
		})
	}
}

func dropsDeny() impl {
	b := reference()
	b.pre = func(ctx context.Context, p *hookbridge.Profile, ev hookbridge.Event, c hookbridge.Client, s *hookbridge.Store, token string) hookbridge.PreOutcome {
		out := hookbridge.Pre(ctx, p, ev, c, s, token)
		return hookbridge.PreOutcome{Allow: true, Err: out.Err}
	}
	return b
}

// carriesAll is a client that takes whatever bytes the receiver authorized,
// as if the runtime could carry a changed input.
type carriesAll struct{ hookbridge.Client }

func (c carriesAll) Admit(ctx context.Context, tool string, args []byte, key string, _ enforceclient.Carry) (enforceclient.Answer, enforceclient.Admission, enforcev1alpha1.AbortCause, error) {
	return c.Client.Admit(ctx, tool, args, key, enforceclient.CarryAuthorized)
}

// passesProposed lets the call run with its own input when the receiver
// authorized another.
func passesProposed() impl {
	b := reference()
	b.pre = func(ctx context.Context, p *hookbridge.Profile, ev hookbridge.Event, c hookbridge.Client, s *hookbridge.Store, token string) hookbridge.PreOutcome {
		return hookbridge.Pre(ctx, p, ev, carriesAll{c}, s, token)
	}
	return b
}

// reportsAuthorized remembers each admitted input and reports it as sent,
// whatever the completion event says ran.
func reportsAuthorized() impl {
	var mu sync.Mutex
	admitted := map[string][]byte{}
	b := reference()
	b.pre = func(ctx context.Context, p *hookbridge.Profile, ev hookbridge.Event, c hookbridge.Client, s *hookbridge.Store, token string) hookbridge.PreOutcome {
		mu.Lock()
		admitted[ev.CallID] = ev.Input
		mu.Unlock()
		return hookbridge.Pre(ctx, p, ev, c, s, token)
	}
	b.post = func(ctx context.Context, p *hookbridge.Profile, ev hookbridge.Event, c hookbridge.Client, s *hookbridge.Store, token string) hookbridge.PostOutcome {
		mu.Lock()
		if in, ok := admitted[ev.CallID]; ok && ev.Input != nil {
			ev.Input = in
		}
		mu.Unlock()
		return hookbridge.Post(ctx, p, ev, c, s, token)
	}
	return b
}

func abortsInPost() impl {
	b := reference()
	b.post = func(ctx context.Context, _ *hookbridge.Profile, ev hookbridge.Event, c hookbridge.Client, s *hookbridge.Store, token string) hookbridge.PostOutcome {
		claimed, err := s.Claim(token, ev.SessionID, ev.CallID)
		if errors.Is(err, hookbridge.ErrNoEntry) {
			return hookbridge.PostOutcome{Result: hookbridge.PostUnmatched}
		}
		if err != nil {
			return hookbridge.PostOutcome{Err: err}
		}
		if ev.Input == nil {
			return hookbridge.PostOutcome{Result: hookbridge.PostNoInput, Err: s.Remove(claimed)}
		}
		ending, err := c.Abort(ctx, claimed.Handle, enforcev1alpha1.AbortCause_ABORT_CAUSE_NOT_SENT)
		return hookbridge.PostOutcome{Result: hookbridge.PostRecorded, Ending: ending, Err: errors.Join(err, s.Remove(claimed))}
	}
	return b
}

// decodesLeniently reads an event as encoding/json does: the last of two
// members wins, any shape of input passes, and a missing flag is false.
func decodesLeniently() impl {
	b := reference()
	b.read = func(p *hookbridge.Profile, r io.Reader) (hookbridge.Event, error) {
		var o map[string]json.RawMessage
		if err := json.NewDecoder(r).Decode(&o); err != nil {
			return hookbridge.Event{}, hookbridge.ErrEventMalformed
		}
		str := func(k string) string {
			var s string
			if json.Unmarshal(o[k], &s) != nil {
				return ""
			}
			return s
		}
		m := p.Members
		ev := hookbridge.Event{Name: str(m.Event), Tool: str(m.Tool), CallID: str(m.CallID), SessionID: str(m.SessionID), Interrupt: hookbridge.InterruptNo}
		ev.Phase = p.Events[ev.Name]
		if in, ok := o[m.Input]; ok {
			ev.Input = in
		}
		if string(o[m.Interrupt]) == "true" {
			ev.Interrupt = hookbridge.InterruptYes
		}
		return ev, nil
	}
	return b
}
