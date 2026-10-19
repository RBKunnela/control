package hookbridge_test

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/hookbridge"
)

const (
	refundInput = `{"account":"acct-1", "amount":5}`

	kindProposed = controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED
	kindDecided  = controlv1.EventKind_EVENT_KIND_POLICY_DECIDED
	kindStarted  = controlv1.EventKind_EVENT_KIND_ACTION_STARTED
	kindDone     = controlv1.EventKind_EVENT_KIND_ACTION_COMPLETED
	kindFailed   = controlv1.EventKind_EVENT_KIND_ACTION_FAILED

	statusBlocked = controlv1.ResultStatus_RESULT_STATUS_BLOCKED
)

// scenario runs one case against a bridge and returns every way the bridge
// departed from the rule; none means it passed.
type scenario struct {
	name string
	run  func(t *testing.T, b impl) []string
}

func preScenarios() []scenario {
	return []scenario{
		{"pre allows by silence and publishes the handle", preAllows},
		{"pre denies a block", preBlocks},
		{"pre denies a pending call with its approval", prePending},
		{"pre aborts a wanted rewrite and denies", preRewrite},
		{"pre aborts an obligation and denies", preObligation},
		{"pre denies when the receiver is unreachable", preUnreachable},
		{"pre aborts and denies when the store is widened", preStoreWidened},
		{"pre of a call already admitted is refused by its request key", preSameCall},
	}
}

func preAllows(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{allowRefunds}})
	out, err := e.pre(admitEvent("c-1", refundInput))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	_, _, aborts := e.c.sent()
	check(&miss, !out.Allow || out.Reason != "" || out.Err != nil, "outcome %+v, want silence", out)
	check(&miss, e.entries() != 1, "%d entries, want 1", e.entries())
	check(&miss, len(aborts) != 0, "aborts %v", aborts)
	check(&miss, !slices.Equal(e.pl.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindStarted}), "trail %v", e.pl.kinds())
	return miss
}

func preBlocks(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{denyRefunds}})
	out, err := e.pre(admitEvent("c-1", refundInput))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	check(&miss, out.Allow || !strings.HasPrefix(out.Reason, "blocked by policy"), "outcome %+v, want a deny", out)
	check(&miss, strings.Contains(out.Reason, "acct-1"), "the reason quotes the input: %q", out.Reason)
	check(&miss, e.entries() != 0, "%d entries", e.entries())
	check(&miss, slices.Contains(e.pl.kinds(), kindStarted), "trail %v", e.pl.kinds())
	return miss
}

func prePending(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{mode: controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE, rules: []string{approveRefunds}})
	out, err := e.pre(admitEvent("c-1", refundInput))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	e.c.mu.Lock()
	id := e.c.answers[0].Pending.GetApprovalId()
	e.c.mu.Unlock()
	check(&miss, id == "", "the plane answered no approval id")
	check(&miss, out.Allow || !strings.Contains(out.Reason, "held for approval "+id+";") || !strings.HasSuffix(out.Reason, "after 5s"),
		"outcome %+v, want a deny naming approval %s and the 5s wait", out, id)
	check(&miss, strings.Contains(out.Reason, "acct-1") || e.entries() != 0, "reason %q, %d entries", out.Reason, e.entries())
	if err := e.pl.store.Answer(id, controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "", e.pl.clock.read()); err != nil {
		return append(miss, "approve: "+err.Error())
	}
	e.pl.clock.advance(5 * time.Second)
	again, err := e.pre(admitEvent("c-2", refundInput))
	check(&miss, err != nil || !again.Allow || e.entries() != 1, "the approved retry: %+v, %v, %d entries", again, err, e.entries())
	return miss
}

func preRewrite(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{redactNotes}})
	out, err := e.pre(admitEvent("c-1", `{"account":"acct-1","amount":5,"note":"x"}`))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	_, _, aborts := e.c.sent()
	check(&miss, out.Allow || !strings.Contains(out.Reason, "changed input"), "outcome %+v, want a deny", out)
	check(&miss, !slices.Equal(aborts, []enforcev1alpha1.AbortCause{enforcev1alpha1.AbortCause_ABORT_CAUSE_ARGUMENTS_DIFFER}), "aborts %v", aborts)
	check(&miss, e.entries() != 0, "%d entries", e.entries())
	return append(miss, e.wantClosing(kindFailed, statusBlocked, "EXECUTED_ARGS_MISMATCH")...)
}

func preObligation(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{allowRefunds}, obligation: true})
	out, err := e.pre(admitEvent("c-1", refundInput))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	_, _, aborts := e.c.sent()
	check(&miss, out.Allow || !strings.Contains(out.Reason, "obligation"), "outcome %+v, want a deny", out)
	check(&miss, !slices.Equal(aborts, []enforcev1alpha1.AbortCause{enforcev1alpha1.AbortCause_ABORT_CAUSE_OBLIGATION}), "aborts %v", aborts)
	check(&miss, e.entries() != 0, "%d entries", e.entries())
	return append(miss, e.wantClosing(kindFailed, statusBlocked, "OBLIGATION_NOT_UNDERSTOOD")...)
}

func preUnreachable(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{allowRefunds}})
	e.c.inner = clientFor(t, socketPath(t))
	out, err := e.pre(admitEvent("c-1", refundInput))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	check(&miss, out.Allow || out.Reason != "the receiver did not answer" || out.Err == nil, "outcome %+v, want a deny", out)
	check(&miss, e.entries() != 0, "%d entries", e.entries())
	return miss
}

func preStoreWidened(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{allowRefunds}})
	if err := os.Chmod(e.dir, 0o750); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	out, err := e.pre(admitEvent("c-1", refundInput))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	_, _, aborts := e.c.sent()
	check(&miss, out.Allow || out.Err == nil, "outcome %+v, want a deny", out)
	check(&miss, !slices.Equal(aborts, []enforcev1alpha1.AbortCause{enforcev1alpha1.AbortCause_ABORT_CAUSE_NOT_SENT}), "aborts %v", aborts)
	check(&miss, e.entries() != 0, "%d entries", e.entries())
	return append(miss, e.wantClosing(kindFailed, statusBlocked, "EVIDENCE_UNAVAILABLE")...)
}

// The second admit of one call carries the first one's request key, so the
// receiver refuses it before writing anything; without the key it would be
// handed out and aborted.
func preSameCall(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{allowRefunds}})
	if miss := admitted(e); miss != nil {
		return miss
	}
	out, err := e.pre(admitEvent("c-1", refundInput))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	check(&miss, out.Allow || out.Reason != "the receiver refused the request", "outcome %+v, want the receiver's refusal", out)
	check(&miss, !slices.Equal(e.pl.kinds(), []controlv1.EventKind{kindProposed, kindDecided, kindStarted}), "trail %v", e.pl.kinds())
	check(&miss, e.entries() != 1, "%d entries", e.entries())
	return miss
}

func TestPreRefusesWhatItCannotAdmit(t *testing.T) {
	e := setup(t, reference(), planeOptions{rules: []string{allowRefunds}})
	admit, err := e.read(admitEvent("c-1", refundInput))
	if err != nil {
		t.Fatal(err)
	}
	post := admit
	post.Phase = hookbridge.PhaseComplete
	for name, out := range map[string]hookbridge.PreOutcome{
		"no profile":   hookbridge.Pre(context.Background(), nil, admit, e.c, e.s, e.token),
		"no client":    hookbridge.Pre(context.Background(), e.p, admit, nil, e.s, e.token),
		"no store":     hookbridge.Pre(context.Background(), e.p, admit, e.c, nil, e.token),
		"no token":     hookbridge.Pre(context.Background(), e.p, admit, e.c, e.s, ""),
		"a completion": hookbridge.Pre(context.Background(), e.p, post, e.c, e.s, e.token),
	} {
		want := hookbridge.ErrNotConfigured
		if name == "a completion" {
			want = hookbridge.ErrNoInput
		}
		if out.Allow || out.Reason == "" || !errors.Is(out.Err, want) {
			t.Errorf("%s: %+v", name, out)
		}
	}
	if admits, _, _ := e.c.sent(); admits != 0 {
		t.Fatalf("%d admits sent", admits)
	}
}
