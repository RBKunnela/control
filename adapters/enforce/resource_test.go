package enforce_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/guardana/control/adapters/enforce"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
)

func redactRefunds(field string) string {
	return `{"id":"redact-refunds","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"redact_fields","params":{"fields":"` + field +
		`"}}],"when":{"action":{"name":["refund"]}}}`
}

// A rewrite that takes away the member naming the decided resource would hand
// the client bytes about another resource, so the pipeline denies the call
// before anything is handed out, and the client is told BLOCK.
func TestARewriteThatMovesTheResourceIsBlocked(t *testing.T) {
	o := defaults()
	o.rules = []string{redactRefunds("account")}
	r := newRig(t, o)
	resp := r.admit(t, runA, "refund", `{"account":"acct-1","amount":5}`, `,"requestKey":"k1"`)
	if resp.GetOutcome() != outcomeBlock || resp.GetExecution() != nil || resp.GetDecision() == nil {
		t.Fatalf("a rewrite that moved the resource answered %v", resp)
	}
	planeDeny(t, resp.GetDecision(), "OBLIGATION_NOT_UNDERSTOOD")
	want := []controlv1.EventKind{kindProposed, kindDecided, kindBlocked}
	if got := r.kinds(); !slices.Equal(got, want) {
		t.Fatalf("trail %v, want %v", got, want)
	}
	if s := r.a.Stats(); s.Open != 0 || s.Blocked != 1 || s.Executed != 0 || s.Aborted != 0 {
		t.Fatalf("stats %+v", s)
	}
	if again := r.admit(t, runA, "refund", `{"account":"acct-1","amount":5}`, `,"requestKey":"k1"`); again.GetOutcome() != outcomeBlock {
		t.Fatalf("the request key stayed taken: %v", again)
	}
}

func TestARewriteThatKeepsTheResourceIsHandedOut(t *testing.T) {
	o := defaults()
	o.rules = []string{redactRefunds("note")}
	r := newRig(t, o)
	kept := r.admit(t, runA, "refund", `{"account":"acct-1","amount":5,"note":"x"}`, "")
	if kept.GetOutcome() != outcomeExecute || string(kept.GetExecution().GetAuthorizedArguments()) != `{"account":"acct-1","amount":5}` {
		t.Fatalf("a rewrite that kept the resource answered %v", kept)
	}
}

// A rule on resource 42 holds whichever spelling of 42 the arguments use, and
// only for 42.
func TestEverySpellingOfANumberNamesOneResource(t *testing.T) {
	o := defaults()
	o.rules = append(o.rules, `{"id":"deny-42","effect":"DENY","when":{"resource":{"id":["42"]}}}`)
	r := newRig(t, o)
	for _, args := range []string{`{"account":42}`, `{"account":42.0}`, `{"account":4.2e1}`} {
		if got := r.admit(t, runA, "refund", args, "").GetOutcome(); got != outcomeBlock {
			t.Errorf("%s answered %s", args, got)
		}
	}
	if got := r.admit(t, runA, "refund", `{"account":43.0}`, "").GetOutcome(); got != outcomeExecute {
		t.Errorf("43.0 answered %s", got)
	}
	ids := []string{}
	for _, env := range r.proposed(t) {
		ids = append(ids, env.GetResource().GetId())
	}
	if want := []string{"42", "42", "42", "43"}; !slices.Equal(ids, want) {
		t.Errorf("resource ids %v, want %v", ids, want)
	}
}

// One run at its bound on open executions is refused before anything is
// written, and leaves another run admitted; a block or a closing frees its
// slot.
func TestARunAtItsOpenBoundLeavesAnotherRunAdmitted(t *testing.T) {
	o := defaults()
	o.adapter = func(c *enforce.Config) { c.MaxOpenPerRun = 2 }
	r := newRig(t, o)
	first := r.executed(t, runA, "refund", refund)
	if got := r.admit(t, runA, "send_mail", `{"to":"x"}`, "").GetOutcome(); got != outcomeBlock {
		t.Fatalf("a call no rule allows answered %s", got)
	}
	r.executed(t, runA, "refund", refund)
	written := len(r.sink.Events())
	r.refused(t, runA, enforce.PathAdmit, admitBody("refund", refund), http.StatusServiceUnavailable, codeUnavailable)
	if n := len(r.sink.Events()); n != written {
		t.Fatalf("a refusal at the bound wrote %d events", n-written)
	}
	r.executed(t, runB, "refund", refund)
	r.complete(t, runA, first, refund, "COMPLETION_STATUS_SUCCESS")
	r.executed(t, runA, "refund", refund)
}

func (r *rig) state(run string) gateway.RunState {
	r.runs.mu.Lock()
	defer r.runs.mu.Unlock()
	return r.runs.states[run]
}

// What the table says a tool returns is what the run is raised by: an
// untrusted CONFIDENTIAL read taints its run and lifts its floor, a trusted
// PUBLIC one leaves it as it was.
func TestTheTablesResultLabelsRaiseTheRun(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trust   controlv1.TrustZone
		sens    controlv1.Sensitivity
		trusted bool
		maxRead controlv1.Sensitivity
	}{
		{"untrusted confidential", controlv1.TrustZone_TRUST_ZONE_UNTRUSTED_EXTERNAL, controlv1.Sensitivity_SENSITIVITY_CONFIDENTIAL, false, controlv1.Sensitivity_SENSITIVITY_CONFIDENTIAL},
		{"trusted public", controlv1.TrustZone_TRUST_ZONE_TRUSTED_INTERNAL, controlv1.Sensitivity_SENSITIVITY_PUBLIC, true, controlv1.Sensitivity_SENSITIVITY_PUBLIC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := defaults()
			o.tools[1].ReturnsTrust, o.tools[1].ReturnsSensitivity = tc.trust, tc.sens
			r := newRig(t, o)
			r.executed(t, runA, "read_file", `{"path":"a"}`)
			if st := r.state("run-a"); st.Trusted != tc.trusted || st.MaxRead != tc.maxRead {
				t.Fatalf("run state after the read: %+v", st)
			}
			if st := r.state("run-b"); !st.Trusted || st.MaxRead != controlv1.Sensitivity_SENSITIVITY_PUBLIC {
				t.Fatalf("another run's state moved: %+v", st)
			}
		})
	}
}

// TestAnUntranslatedCallIsHandedOutInNoMode: an envelope the contract refuses,
// here a transaction that names no account, is never handed out, OBSERVE
// included: the pipeline blocks it with the kernel's code for the refusal,
// as over MCP, and nothing is recorded as started.
func TestAnUntranslatedCallIsHandedOutInNoMode(t *testing.T) {
	args := `{"amount":5}`
	for _, mode := range []controlv1.EnforcementMode{controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE, modeEnforce} {
		o := defaults()
		o.mode = mode
		r := newRig(t, o)
		resp := r.admit(t, runA, "refund", args, `,"requestKey":"k1"`)
		if resp.GetOutcome() != outcomeBlock || resp.GetExecution() != nil {
			t.Fatalf("%v: an untranslated call answered %v", mode, resp)
		}
		if got := resp.GetDecision().GetReasonCodes(); !slices.Equal(got, []string{"REQUIRED_FIELD_ABSENT"}) {
			t.Errorf("%v: the block names %v, want the kernel's REQUIRED_FIELD_ABSENT alone", mode, got)
		}
		if want := []controlv1.EventKind{kindProposed, kindDecided, kindBlocked}; !slices.Equal(r.kinds(), want) {
			t.Errorf("%v: trail %v, want %v", mode, r.kinds(), want)
		}
		if s := r.a.Stats(); s.Open != 0 || s.Executed != 0 || s.Blocked != 1 || s.Aborted != 0 {
			t.Fatalf("%v: stats %+v", mode, s)
		}
	}
	// A tool the table does not name is the mode's to decide, and OBSERVE
	// lets it run.
	o := defaults()
	o.mode = controlv1.EnforcementMode_ENFORCEMENT_MODE_OBSERVE
	r := newRig(t, o)
	if resp := r.admit(t, runA, "drop_database", `{"name":"x"}`, `,"requestKey":"k2"`); resp.GetOutcome() != outcomeExecute || resp.GetExecution().GetHandle() == "" {
		t.Fatalf("an unclassified tool under OBSERVE answered %v", resp)
	}
}

// planeDeny fails t unless d is the plane's own DENY naming code alone.
func planeDeny(t *testing.T, d *controlv1.Decision, code string) {
	t.Helper()
	if d.GetVerdict() != controlv1.Verdict_VERDICT_DENY || !slices.Equal(d.GetReasonCodes(), []string{code}) || d.GetPdpType() != gateway.PDPType {
		t.Fatalf("the block's decision is %v, want the plane's DENY %s", d, code)
	}
}
