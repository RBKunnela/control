package gateway_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/pkg/contract"
)

// TestAnEnvelopeOutsideTheVocabularyIsRefused: a kind the plane does not
// name, or a protocol that is not the adapter's, is refused as an invalid
// value in OBSERVE as in ENFORCE, and so is a call nothing classifies that
// carries one: OBSERVE would otherwise run a kind no pause scope names.
func TestAnEnvelopeOutsideTheVocabularyIsRefused(t *testing.T) {
	unclassified := fmt.Errorf("%w: no entry names it", gateway.ErrUnclassified)
	cases := map[string]struct {
		kind, protocol string
		refusal        error
		effect         controlv1.EffectClass
	}{
		"a capitalised kind":           {kind: "Tool", protocol: testProtocol},
		"a kind with a trailing space": {kind: "tool ", protocol: testProtocol},
		"no kind":                      {kind: "", protocol: testProtocol},
		"a kind of another vocabulary": {kind: "function", protocol: testProtocol},
		"another adapter's protocol":   {kind: "tool", protocol: "enforce"},
		"a capitalised protocol":       {kind: "tool", protocol: "MCP"},
		"no protocol":                  {kind: "tool", protocol: ""},
		"unclassified, a foreign kind": {kind: "function", protocol: testProtocol, refusal: unclassified},
		"unclassified, a foreign protocol": {
			kind: "prompt", protocol: "enforce", refusal: unclassified,
		},
	}
	for _, mode := range []controlv1.EnforcementMode{modeObserve, modeEnforce} {
		for name, c := range cases {
			t.Run(mode.String()+"/"+name, func(t *testing.T) {
				h := build(t, mode, snapshot(t, allowReads))
				env := readEnvelope()
				env.Action.Kind, env.Action.Protocol = c.kind, c.protocol
				if c.refusal != nil {
					env.Action.Effect = controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED
				}
				a := admission(env, []byte(`{}`))
				a.Refusal = c.refusal
				d := h.p.Admit(context.Background(), a)
				expectBlock(t, d, verdictIndeterminate, codeInvalidFieldValue, kernelPDP)
				if got := d.Decision.GetReasonCodes(); !slices.Equal(got, []string{codeInvalidFieldValue}) {
					t.Errorf("ReasonCodes = %v, want INVALID_FIELD_VALUE alone", got)
				}
				if slices.Contains(h.kinds(), kindStarted) {
					t.Errorf("a refused envelope was recorded as started: %v", h.kinds())
				}
				if p := h.p.Preview(context.Background(), a).Decision; p.GetVerdict() != verdictIndeterminate {
					t.Errorf("Preview = %s %v, want the refusal's INDETERMINATE", p.GetVerdict(), p.GetReasonCodes())
				}
			})
		}
	}
}

// TestTheVocabularyRefusalLeavesAnotherRefusalAlone: a call refused for
// something else keeps that refusal's code, and every kind the plane names
// runs under its adapter's protocol.
func TestTheVocabularyRefusalLeavesAnotherRefusalAlone(t *testing.T) {
	h := build(t, modeObserve, snapshot(t, allowReads))
	env := readEnvelope()
	env.Action.Kind = "function"
	a := admission(env, []byte(`{}`))
	a.Refusal = &contract.ValidationError{Field: "action.name", Err: contract.ErrMissingField}
	d := h.p.Admit(context.Background(), a)
	expectBlock(t, d, verdictIndeterminate, codeRequiredFieldAbsent, kernelPDP)

	for _, kind := range []string{"tool", "prompt", "resource"} {
		h := build(t, modeEnforce, snapshot(t, allowReads))
		env := readEnvelope()
		env.Action.Kind = kind
		if d := h.admit(env, []byte(`{}`)); d.Action != core.Execute {
			t.Errorf("kind %q: Action = %d %v, want it run", kind, d.Action, d.Decision.GetReasonCodes())
		}
	}
}

// TestRewrittenBytesMustNameTheDecidedResource: a rewrite that moves the
// member the classification's pointer names is a DENY the pipeline makes
// before anything is handed out, whatever adapter sent the call; a rewrite
// that leaves the member alone runs, and OBSERVE rewrites nothing.
func TestRewrittenBytesMustNameTheDecidedResource(t *testing.T) {
	for name, c := range map[string]struct {
		mode    controlv1.EnforcementMode
		pointer string
		id      string
		runs    bool
	}{
		"the capped amount names the resource":   {modeEnforce, "/amount", "1250", false},
		"the redacted member names the resource": {modeEnforce, "/ssn", "x", false},
		"an untouched member names it":           {modeEnforce, "/currency", "EUR", true},
		"no member names it":                     {modeEnforce, "", "ord-1", true},
		"OBSERVE rewrites nothing":               {modeObserve, "/amount", "1250", true},
		"APPROVE checks before it holds":         {modeApprove, "/amount", "1250", false},
	} {
		t.Run(name, func(t *testing.T) {
			h := build(t, c.mode, snapshot(t, cappedRefunds))
			args := refundArgs()
			env := refundEnvelope(t, args)
			env.Resource.Id = c.id
			a := admission(env, args)
			a.Classification.ResourceFrom = c.pointer
			d := h.p.Admit(context.Background(), a)
			runs := d.Action == core.Execute || d.Action == core.ExecuteWithObligations
			if runs != c.runs {
				t.Fatalf("Action = %d %v, want handed out %v", d.Action, d.Decision.GetReasonCodes(), c.runs)
			}
			if c.runs {
				return
			}
			expectBlock(t, d, verdictDeny, codeObligationNotUnderstood, gateway.PDPType)
			if want := []controlv1.EventKind{kindProposed, kindDecided, kindBlocked}; !slices.Equal(h.kinds(), want) {
				t.Errorf("trail = %v, want %v", h.kinds(), want)
			}
		})
	}
}

// TestAMalformedResourcePointerIsRefused: a pointer that is not RFC 6901 would
// be read as some other member, or as none, and hold no rewrite to the
// resource, so the call is refused in every mode, in Admit and in Preview,
// whole or unclassified; a well-formed one, and none, run.
func TestAMalformedResourcePointerIsRefused(t *testing.T) {
	unclassified := fmt.Errorf("%w: no entry names it", gateway.ErrUnclassified)
	for name, c := range map[string]struct {
		pointer string
		refused bool
	}{
		"a pointer without its leading slash": {"amount", true},
		"a tilde that escapes nothing":        {"/am~ount", true},
		"a well-formed pointer":               {"/currency", false},
		"no pointer":                          {"", false},
	} {
		for _, mode := range []controlv1.EnforcementMode{modeObserve, modeEnforce} {
			for _, refusal := range []error{nil, unclassified} {
				if refusal != nil && mode != modeObserve {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/unclassified %v", mode, name, refusal != nil), func(t *testing.T) {
					h := build(t, mode, snapshot(t, cappedRefunds))
					args := refundArgs()
					env := refundEnvelope(t, args)
					env.Resource.Id = "EUR"
					if refusal != nil {
						env.Action.Effect = controlv1.EffectClass_EFFECT_CLASS_UNSPECIFIED
					}
					a := admission(env, args)
					a.Refusal, a.Classification.ResourceFrom = refusal, c.pointer
					d := h.p.Admit(context.Background(), a)
					if !c.refused {
						if d.Action != core.Execute && d.Action != core.ExecuteWithObligations {
							t.Errorf("Action = %d %v, want it run", d.Action, d.Decision.GetReasonCodes())
						}
						return
					}
					expectBlock(t, d, verdictIndeterminate, codeInvalidFieldValue, kernelPDP)
					if slices.Contains(h.kinds(), kindStarted) {
						t.Errorf("a call with a malformed pointer was recorded as started: %v", h.kinds())
					}
					if p := h.p.Preview(context.Background(), a).Decision; p.GetVerdict() != verdictIndeterminate {
						t.Errorf("Preview = %s %v, want the refusal's INDETERMINATE", p.GetVerdict(), p.GetReasonCodes())
					}
				})
			}
		}
	}
}
