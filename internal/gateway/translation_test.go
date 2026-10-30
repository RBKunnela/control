package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/pkg/contract"
)

// refusalShape is one way an adapter can hand a translation in: whole, with
// nothing classifying it, or refused for something else, alone or beside
// the unclassified cause.
type refusalShape struct {
	name string
	// refused: the translation is refused for more than nothing classifying
	// it, so no mode may hand it out.
	refused bool
	admit   func() gateway.Admission
}

func unclassifiedEnvelope() *controlv1.ActionEnvelope {
	env := readEnvelope()
	env.Action.Effect = controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED
	return env
}

func refusing(env *controlv1.ActionEnvelope, refusal error) func() gateway.Admission {
	return func() gateway.Admission {
		a := admission(env, []byte(`{}`))
		a.Refusal = refusal
		return a
	}
}

// claiming is an envelope nothing classifies, edited by mut, handed in with
// a refusal that claims only that.
func claiming(mut func(*controlv1.ActionEnvelope)) func() gateway.Admission {
	env := unclassifiedEnvelope()
	mut(env)
	return refusing(env, fmt.Errorf("%w: no entry names the tool", gateway.ErrUnclassified))
}

// rawPreview is content a preview carries with no redaction profile.
const rawPreview = "raw-content-of-the-call"

// claimsOverRefusedEnvelopes are envelopes the contract refuses for more than
// their missing effect, or whose hash names other bytes, each handed in with
// a refusal that claims nothing classifies them, and the code the kernel
// gives the refusal they earn.
func claimsOverRefusedEnvelopes(t *testing.T) []struct {
	name, code string
	admit      func() gateway.Admission
} {
	t.Helper()
	other := argumentsHash(t, []byte(`{"other":1}`))
	empty := argumentsHash(t, []byte(`{}`))
	issued := time.Date(2026, time.September, 11, 11, 0, 0, 0, time.UTC)
	return []struct {
		name, code string
		admit      func() gateway.Admission
	}{
		{"another major", "UNSUPPORTED_SCHEMA", claiming(func(e *controlv1.ActionEnvelope) { e.SchemaVersion = "9.0" })},
		{"no principal id", codeRequiredFieldAbsent, claiming(func(e *controlv1.ActionEnvelope) { e.Principal.Id = "" })},
		{"an action name past its bound", "LIMIT_EXCEEDED", claiming(func(e *controlv1.ActionEnvelope) {
			e.Action.Name = strings.Repeat("n", contract.MaxStringBytes+1)
		})},
		{"a hop that does not start at the principal", codeInvalidFieldValue, claiming(func(e *controlv1.ActionEnvelope) {
			e.Delegation = []*controlv1.Delegation{{From: "stranger", To: "agent-1", IssuedAt: timestamppb.New(issued), ExpiresAt: timestamppb.New(issued.Add(2 * time.Hour))}}
		})},
		{"a hash of other bytes", codeInvalidFieldValue, claiming(func(e *controlv1.ActionEnvelope) {
			e.Arguments = &controlv1.Arguments{CanonicalHash: other}
		})},
		{"a preview with no profile", codeInvalidFieldValue, claiming(func(e *controlv1.ActionEnvelope) {
			e.Arguments = &controlv1.Arguments{CanonicalHash: empty, RedactedPreview: rawPreview}
		})},
		{"an envelope whose effect is set", codeInvalidFieldValue, refusing(readEnvelope(), fmt.Errorf("%w: no entry names the tool", gateway.ErrUnclassified))},
		{"a hash beside arguments canon refuses", codeInvalidFieldValue, func() gateway.Admission {
			a := claiming(func(e *controlv1.ActionEnvelope) { e.Arguments = &controlv1.Arguments{CanonicalHash: empty} })()
			a.Arguments = []byte(`{"a": 1e400}`)
			return a
		}},
		{"arguments canon refuses, with no hash", codeInvalidFieldValue, func() gateway.Admission {
			a := claiming(func(*controlv1.ActionEnvelope) {})()
			a.Arguments = []byte(`{"a": 1e400}`)
			return a
		}},
		{"arguments past canon's depth, with no hash", "LIMIT_EXCEEDED", func() gateway.Admission {
			a := claiming(func(*controlv1.ActionEnvelope) {})()
			a.Arguments = []byte(`{"a":` + strings.Repeat("[", 32) + strings.Repeat("]", 32) + `}`)
			return a
		}},
		{"tags the plane's own take past their bound", "LIMIT_EXCEEDED", claiming(func(e *controlv1.ActionEnvelope) {
			e.Context = &controlv1.RunContext{Tags: make([]string, contract.MaxLabels)}
			for i := range e.Context.Tags {
				e.Context.Tags[i] = "tag-" + strconv.Itoa(i)
			}
		})},
	}
}

func refusalShapes(t *testing.T) []refusalShape {
	t.Helper()
	unclassified := fmt.Errorf("%w: no entry names the tool", gateway.ErrUnclassified)
	forged := readEnvelope()
	forged.Context.Tags = []string{"flow.v1.untrusted=false"}
	missing := readEnvelope()
	missing.Principal.Id = ""
	oversized := readEnvelope()
	oversized.Action.Name = strings.Repeat("n", contract.MaxStringBytes+1)
	undeclared := readEnvelope()
	undeclared.Action.Effect = controlv1.EffectClass(99)
	out := []refusalShape{
		{"no refusal reported, a required field missing", true, refusing(missing, nil)},
		{"no refusal reported, a string past its bound", true, refusing(oversized, nil)},
		{"no refusal reported, an effect no build declares", true, refusing(undeclared, nil)},
		{"complete", false, refusing(readEnvelope(), nil)},
		{"unclassified alone", false, refusing(unclassifiedEnvelope(), unclassified)},
		{"unclassified, wrapped once more", false, refusing(unclassifiedEnvelope(), fmt.Errorf("adapter: %w", unclassified))},
		{"the bare sentinel", false, refusing(unclassifiedEnvelope(), gateway.ErrUnclassified)},
		{"a bound joined with unclassified", true, refusing(unclassifiedEnvelope(), errors.Join(contract.ErrTooLarge, gateway.ErrUnclassified))},
		{"unclassified joined with a bound", true, refusing(unclassifiedEnvelope(), errors.Join(gateway.ErrUnclassified, contract.ErrTooLarge))},
		{"unclassified and an invalid value in one wrap", true, refusing(unclassifiedEnvelope(), fmt.Errorf("%w: %w", gateway.ErrUnclassified, contract.ErrInvalidValue))},
		{"an invalid value and unclassified in one wrap", true, refusing(unclassifiedEnvelope(), fmt.Errorf("%w: %w", contract.ErrInvalidValue, gateway.ErrUnclassified))},
		{"a join nested inside a wrap", true, refusing(unclassifiedEnvelope(), fmt.Errorf("adapter: %w", errors.Join(unclassified, contract.ErrMissingField)))},
		{"a contract refusal", true, refusing(readEnvelope(), &contract.ValidationError{Field: "action.name", Err: contract.ErrMissingField})},
		{"a contract refusal wrapping unclassified", true, refusing(unclassifiedEnvelope(), &contract.ValidationError{Field: "arguments.canonical_hash", Err: fmt.Errorf("%w: %w", contract.ErrInvalidValue, unclassified)})},
		{"a refusal that names no sentinel", true, refusing(readEnvelope(), errors.New("the decoder gave up"))},
		{"no envelope", true, refusing(nil, nil)},
		{"a forged flow tag", true, refusing(forged, nil)},
		// The kernel reads the tenants after the request; a call nothing
		// classifies has no effect for one named tenant to be material to.
		{"unclassified, a tenant named on one side", false, claiming(func(e *controlv1.ActionEnvelope) { e.Resource.TenantId = "" })},
		{"unclassified, the hash of its arguments", false, claiming(func(e *controlv1.ActionEnvelope) {
			e.Arguments = &controlv1.Arguments{CanonicalHash: argumentsHash(t, []byte(`{}`))}
		})},
	}
	for _, c := range claimsOverRefusedEnvelopes(t) {
		out = append(out, refusalShape{"unclassified claimed over " + c.name, true, c.admit})
	}
	return out
}

// declaredModes is every enforcement mode New starts a plane in.
func declaredModes(t *testing.T) []controlv1.EnforcementMode {
	t.Helper()
	var out []controlv1.EnforcementMode
	values := controlv1.EnforcementMode(0).Descriptor().Values()
	for i := range values.Len() {
		mode := controlv1.EnforcementMode(values.Get(i).Number())
		cfg := validConfig(t)
		cfg.Mode = mode
		if _, err := gateway.New(cfg); err == nil {
			out = append(out, mode)
		}
	}
	if !slices.Contains(out, modeObserve) || !slices.Contains(out, modeEnforce) {
		t.Fatalf("declared modes %v lack OBSERVE or ENFORCE", out)
	}
	return out
}

// TestARefusedTranslationIsNeverHandedOut: in every mode New starts, Admit
// hands out a translation only when it is whole or nothing but its
// classification is missing, and the second only in OBSERVE. Whatever joins
// the unclassified cause with another is refused, and no refused call is
// recorded as started.
func TestARefusedTranslationIsNeverHandedOut(t *testing.T) {
	for _, mode := range declaredModes(t) {
		for _, shape := range refusalShapes(t) {
			t.Run(mode.String()+"/"+shape.name, func(t *testing.T) {
				h := build(t, mode, snapshot(t, allowReads))
				expectHandedOut(t, mode, shape, h.admitA(shape.admit()), slices.Contains(h.kinds(), kindStarted))
			})
		}
	}
}

// expectHandedOut holds what Admit did with shape in mode, and whether the
// trail says it started, to what the shape allows.
func expectHandedOut(t *testing.T, mode controlv1.EnforcementMode, shape refusalShape, d gateway.Disposition, started bool) {
	t.Helper()
	runs := d.Action == core.Execute || d.Action == core.ExecuteWithObligations
	if shape.refused {
		if runs || d.Action == core.AwaitApproval || started {
			t.Errorf("Action = %d, started %v for a refused translation, want Block (%v)", d.Action, started, d.Decision.GetReasonCodes())
		}
		return
	}
	switch {
	case shape.name != "complete" && mode != modeObserve && runs:
		t.Errorf("Action = %d for an unclassified call outside OBSERVE, want a block", d.Action)
	case mode == modeObserve && !runs:
		t.Errorf("OBSERVE Action = %d for %s, want it handed out (%v)", d.Action, shape.name, d.Decision.GetReasonCodes())
	case runs != started:
		t.Errorf("handed out %v, recorded as started %v", runs, started)
	}
}

// TestObserveRecordsARefusedTranslationAsEnforceDoes: OBSERVE answers a
// translation refused for more than its classification with the kernel's
// own INDETERMINATE and the refusal's code, on the trail ENFORCE writes.
func TestObserveRecordsARefusedTranslationAsEnforceDoes(t *testing.T) {
	refusal := errors.Join(contract.ErrTooLarge, gateway.ErrUnclassified)
	for _, mode := range []controlv1.EnforcementMode{modeObserve, modeEnforce} {
		t.Run(mode.String(), func(t *testing.T) {
			h := build(t, mode, snapshot(t, allowReads))
			d := h.admitA(refusing(unclassifiedEnvelope(), refusal)())
			expectBlock(t, d, verdictIndeterminate, "LIMIT_EXCEEDED", kernelPDP)
			want := []controlv1.EventKind{kindProposed, kindDecided, kindBlocked}
			if got := h.kinds(); !slices.Equal(got, want) {
				t.Errorf("trail = %v, want %v", got, want)
			}
			if s := h.p.Stats(); s.Executed != 0 || s.Blocks["LIMIT_EXCEEDED"] != 1 {
				t.Errorf("Stats: Executed %d, Blocks %v, want none executed and one LIMIT_EXCEEDED", s.Executed, s.Blocks)
			}
		})
	}
}

// TestARefusedTranslationMintsNoRun: a run is minted for a call that is
// handed out or could be, so OBSERVE mints one for an unclassified call and
// none for a translation refused for anything else, in any mode.
func TestARefusedTranslationMintsNoRun(t *testing.T) {
	joined := errors.Join(contract.ErrTooLarge, gateway.ErrUnclassified)
	for _, c := range []struct {
		name string
		mode controlv1.EnforcementMode
		in   func() gateway.Admission
		runs int
	}{
		{"OBSERVE, unclassified", modeObserve, refusing(unclassifiedEnvelope(), gateway.ErrUnclassified), 1},
		{"OBSERVE, joined", modeObserve, refusing(unclassifiedEnvelope(), joined), 0},
		{"OBSERVE, a contract refusal", modeObserve, refusing(readEnvelope(), contract.ErrMissingField), 0},
		{"ENFORCE, unclassified", modeEnforce, refusing(unclassifiedEnvelope(), gateway.ErrUnclassified), 0},
		{"ENFORCE, complete", modeEnforce, refusing(readEnvelope(), nil), 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := build(t, c.mode, snapshot(t, allowReads))
			h.admitA(c.in())
			if got := h.p.Stats().Runs; got != c.runs {
				t.Errorf("Stats().Runs = %d, want %d", got, c.runs)
			}
		})
	}
}

// TestAnUnclassifiedClaimIsHeldToTheContract: a refusal that claims only that
// nothing classifies the call stands for an envelope the contract takes but
// for its effect and whose hash names its arguments. Over any other envelope
// OBSERVE blocks the call with the code the kernel gives what is wrong with
// it, on the trail ENFORCE writes, in Admit and in Preview, and no raw
// content reaches the trail.
func TestAnUnclassifiedClaimIsHeldToTheContract(t *testing.T) {
	for _, c := range claimsOverRefusedEnvelopes(t) {
		t.Run(c.name, func(t *testing.T) {
			h := build(t, modeObserve, snapshot(t, allowReads))
			d := h.admitA(c.admit())
			expectBlock(t, d, verdictIndeterminate, c.code, kernelPDP)
			if got := d.Decision.GetReasonCodes(); !slices.Equal(got, []string{c.code}) {
				t.Errorf("ReasonCodes = %v, want %s alone", got, c.code)
			}
			if want := []controlv1.EventKind{kindProposed, kindDecided, kindBlocked}; !slices.Equal(h.kinds(), want) {
				t.Errorf("trail = %v, want %v", h.kinds(), want)
			}
			for _, e := range h.events() {
				if b, err := protojson.Marshal(e); err != nil || strings.Contains(string(b), rawPreview) {
					t.Errorf("event %s carries the raw preview, or does not encode (%v)", e.GetKind(), err)
				}
			}
			if p := h.p.Preview(context.Background(), c.admit()).Decision; p.GetVerdict() != verdictIndeterminate || !slices.Equal(p.GetReasonCodes(), []string{c.code}) {
				t.Errorf("Preview = %s %v, want INDETERMINATE with %s", p.GetVerdict(), p.GetReasonCodes(), c.code)
			}
		})
	}
}
