package core_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/pkg/contract"
)

// TestRefusedInputIsTheRefusalRowAlone: Outcome.RefusedInput is set when the
// decision stopped on the request itself, before any rule ran: a refusal
// handed in, Validate's own, arguments that cannot be digested, or a hash
// that names other bytes. Every other INDETERMINATE, input causes found later
// included, and every determinate verdict leave it unset.
func TestRefusedInputIsTheRefusalRowAlone(t *testing.T) {
	snap := snapshot(t, allowReads, allowWrites, denyGold)
	missing := readEnvelope()
	missing.Principal.Id = ""
	oversized := readEnvelope()
	oversized.Action.Name = strings.Repeat("n", contract.MaxStringBytes+1)
	unknownEffect := readEnvelope()
	unknownEffect.Action.Effect = controlv1.EffectClass(99)
	mismatched := readEnvelope()
	mismatched.Arguments = &controlv1.Arguments{CanonicalHash: argumentsHash(t, []byte(`{"other":1}`))}
	oneSided := writeEnvelope()
	oneSided.Resource.TenantId = ""
	gold := readEnvelope()

	k := kernelAt(t, options())
	for _, c := range []struct {
		name    string
		req     core.Request
		snap    *policy.Snapshot
		k       *core.Kernel
		refused bool
		// undecided: INDETERMINATE for a cause other than the refusal.
		undecided bool
	}{
		{"a refusal handed in", core.Request{Envelope: readEnvelope(), Refusal: contract.ErrMissingField}, snap, k, true, false},
		{"a refusal that names no sentinel", core.Request{Envelope: readEnvelope(), Refusal: errors.New("x")}, snap, k, true, false},
		{"Validate: a required field missing", request(missing), snap, k, true, false},
		{"Validate: a string past its bound", request(oversized), snap, k, true, false},
		{"Validate: an effect no build declares", request(unknownEffect), snap, k, true, false},
		{"Validate: no envelope", core.Request{}, snap, k, true, false},
		{"arguments that cannot be digested", core.Request{Envelope: readEnvelope(), AuthorizedArgs: []byte(`{"a":`)}, snap, k, true, false},
		{"a hash that names other bytes", core.Request{Envelope: mismatched, AuthorizedArgs: []byte(`{}`)}, snap, k, true, false},
		{"refused with no snapshot", request(missing), nil, k, true, false},
		{"no snapshot", request(readEnvelope()), nil, k, false, true},
		{"a stale snapshot", request(readEnvelope()), snapshotAt(t, document(300, allowReads), base().Add(-time.Hour)), k, false, true},
		{"a clock the kernel cannot judge by", request(readEnvelope()), snap, kernel(t, options(), fixedClock(time.Time{})), false, true},
		{"a tenant named on one side of a material call", request(oneSided), snap, k, false, true},
		{"an undetermined rule", request(gold), snap, k, false, true},
		{"an allow", request(readEnvelope()), snap, k, false, false},
		{"no matching rule", request(func() *controlv1.ActionEnvelope {
			e := readEnvelope()
			e.Action.Effect = controlv1.EffectClass_EFFECT_CLASS_DELETE
			return e
		}()), snap, k, false, false},
	} {
		got := decide(c.k, c.req, c.snap)
		if got.RefusedInput != c.refused {
			t.Errorf("%s: RefusedInput = %v, want %v (%s %v)", c.name, got.RefusedInput, c.refused, got.Decision.GetVerdict(), got.Decision.GetReasonCodes())
		}
		if c.undecided && got.Decision.GetVerdict() != controlv1.Verdict_VERDICT_INDETERMINATE {
			t.Errorf("%s: decided %s %v, want an INDETERMINATE that is no refusal", c.name, got.Decision.GetVerdict(), got.Decision.GetReasonCodes())
		}
		if c.refused && (got.Decision.GetVerdict() != controlv1.Verdict_VERDICT_INDETERMINATE || got.Action != core.Block) {
			t.Errorf("%s: a refused request decided %s, action %d", c.name, got.Decision.GetVerdict(), got.Action)
		}
	}
}
