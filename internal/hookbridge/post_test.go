package hookbridge_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/hookbridge"
)

const (
	statusSuccess = controlv1.ResultStatus_RESULT_STATUS_SUCCESS
	statusFailure = controlv1.ResultStatus_RESULT_STATUS_FAILURE
	statusUnknown = controlv1.ResultStatus_RESULT_STATUS_UNKNOWN
)

func postScenarios() []scenario {
	return []scenario{
		{"post completes a matching call once", postMatches},
		{"post completes a call whose input is the same value", postSameValue},
		{"post reports another input, which the receiver records as a mismatch", postMismatch},
		{"two posts of one call send one complete", postTwice},
		{"post with no admit sends nothing", postUnmatched},
		{"post reads the interrupt flag into the status", postStatuses},
		{"post with no input sends nothing", postNoInput},
		{"post never resends a complete whose answer was lost", postLost},
	}
}

// admitted runs one allowed admit of call c-1 and returns a miss if it was
// not.
func admitted(e *env) []string {
	out, err := e.pre(admitEvent("c-1", refundInput))
	if err != nil || !out.Allow {
		return []string{"the admit of c-1 did not allow: " + errText(err) + " " + out.Reason}
	}
	return nil
}

func postMatches(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{allowRefunds}})
	if miss := admitted(e); miss != nil {
		return miss
	}
	out, err := e.post(postEvent("AfterTool", "c-1", refundInput, ""))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	_, completes, aborts := e.c.sent()
	check(&miss, out.Result != hookbridge.PostRecorded || out.Ending != enforcev1alpha1.Ending_ENDING_RECORDED || out.Err != nil, "outcome %+v", out)
	check(&miss, completes != 1 || len(aborts) != 0, "%d completes, aborts %v", completes, aborts)
	check(&miss, e.entries() != 0, "%d entries", e.entries())
	return append(miss, e.wantClosing(kindDone, statusSuccess, "")...)
}

func postSameValue(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{allowRefunds}})
	if miss := admitted(e); miss != nil {
		return miss
	}
	if _, err := e.post(postEvent("AfterTool", "c-1", `{"amount":5,"account":"acct-1"}`, "")); err != nil {
		return []string{"read: " + err.Error()}
	}
	return e.wantClosing(kindDone, statusSuccess, "")
}

func postMismatch(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{allowRefunds}})
	if miss := admitted(e); miss != nil {
		return miss
	}
	out, err := e.post(postEvent("AfterTool", "c-1", `{"account":"acct-1","amount":5000}`, ""))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	check(&miss, out.Result != hookbridge.PostRecorded, "outcome %+v", out)
	k, _, p, m := e.closing()
	check(&miss, m != nil || k != kindFailed || p != "EXECUTED_ARGS_MISMATCH", "closing %s %q %v, want the mismatch", k, p, m)
	return miss
}

func postTwice(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{allowRefunds}})
	if miss := admitted(e); miss != nil {
		return miss
	}
	ev, err := e.read(postEvent("AfterTool", "c-1", refundInput, ""))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	outs := make([]hookbridge.PostOutcome, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range outs {
		wg.Go(func() {
			<-start
			outs[i] = e.b.post(context.Background(), e.p, ev, e.c, e.s, e.token)
		})
	}
	close(start)
	wg.Wait()
	got := []hookbridge.PostResult{outs[0].Result, outs[1].Result}
	slices.Sort(got)
	var miss []string
	_, completes, _ := e.c.sent()
	check(&miss, !slices.Equal(got, []hookbridge.PostResult{hookbridge.PostRecorded, hookbridge.PostUnmatched}), "results %v, want one recorded and one unmatched", got)
	check(&miss, completes != 1 || len(e.pl.closings()) != 1, "%d completes, %d closings", completes, len(e.pl.closings()))
	return miss
}

func postUnmatched(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{allowRefunds}})
	out, err := e.post(postEvent("AfterTool", "c-9", refundInput, ""))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	admits, completes, aborts := e.c.sent()
	check(&miss, out.Result != hookbridge.PostUnmatched, "outcome %+v", out)
	check(&miss, admits+completes+len(aborts) != 0 || len(e.pl.kinds()) != 0, "requests sent, trail %v", e.pl.kinds())
	return miss
}

func postStatuses(t *testing.T, b impl) []string {
	var miss []string
	for _, tc := range []struct {
		name, flag string
		want       controlv1.ResultStatus
	}{
		{"AfterToolFailed", `,"interrupted":false`, statusFailure},
		{"AfterToolFailed", ``, statusUnknown},
		{"AfterToolFailed", `,"interrupted":"no"`, statusUnknown},
		{"AfterToolFailed", `,"interrupted":true`, statusUnknown},
		{"AfterTool", `,"interrupted":true`, statusUnknown},
		{"AfterTool", `,"interrupted":false`, statusSuccess},
	} {
		e := setup(t, b, planeOptions{rules: []string{allowRefunds}})
		if m := admitted(e); m != nil {
			return m
		}
		if _, err := e.post(postEvent(tc.name, "c-1", refundInput, tc.flag)); err != nil {
			return append(miss, "read: "+err.Error())
		}
		k, s, _, m := e.closing()
		check(&miss, m != nil || k != kindFailed && tc.want != statusSuccess || s != tc.want, "%s%s closed as %s %s %v, want %s", tc.name, tc.flag, k, s, m, tc.want)
	}
	return miss
}

func postNoInput(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{allowRefunds}})
	if miss := admitted(e); miss != nil {
		return miss
	}
	out, err := e.post(postEvent("AfterTool", "c-1", "", ""))
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	_, completes, aborts := e.c.sent()
	check(&miss, out.Result != hookbridge.PostNoInput || out.Err != nil, "outcome %+v", out)
	check(&miss, completes != 0 || len(aborts) != 0 || len(e.pl.closings()) != 0, "%d completes, aborts %v", completes, aborts)
	check(&miss, e.pl.a.Stats().Open != 1, "the handle is not left open for the sweep: %+v", e.pl.a.Stats())
	check(&miss, e.entries() != 0, "%d entries", e.entries())
	return miss
}

func postLost(t *testing.T, b impl) []string {
	e := setup(t, b, planeOptions{rules: []string{allowRefunds}})
	if miss := admitted(e); miss != nil {
		return miss
	}
	e.c.loseComplete = true
	raw := postEvent("AfterTool", "c-1", refundInput, "")
	out, err := e.post(raw)
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	again, err := e.post(raw)
	if err != nil {
		return []string{"read: " + err.Error()}
	}
	var miss []string
	_, completes, aborts := e.c.sent()
	check(&miss, out.Result != hookbridge.PostNotRecorded || out.Err == nil, "outcome %+v", out)
	check(&miss, again.Result != hookbridge.PostUnmatched, "the second post %+v", again)
	check(&miss, completes != 1 || len(aborts) != 0 || e.entries() != 0, "%d completes, aborts %v, %d entries", completes, aborts, e.entries())
	return miss
}

func TestPostRefusesWhatItCannotComplete(t *testing.T) {
	e := setup(t, reference(), planeOptions{rules: []string{allowRefunds}})
	post, err := e.read(postEvent("AfterTool", "c-1", refundInput, ""))
	if err != nil {
		t.Fatal(err)
	}
	admit := post
	admit.Phase = hookbridge.PhaseAdmit
	for name, out := range map[string]hookbridge.PostOutcome{
		"no profile": hookbridge.Post(context.Background(), nil, post, e.c, e.s, e.token),
		"no client":  hookbridge.Post(context.Background(), e.p, post, nil, e.s, e.token),
		"no store":   hookbridge.Post(context.Background(), e.p, post, e.c, nil, e.token),
		"no token":   hookbridge.Post(context.Background(), e.p, post, e.c, e.s, ""),
		"an admit":   hookbridge.Post(context.Background(), e.p, admit, e.c, e.s, e.token),
	} {
		want := hookbridge.ErrNotConfigured
		if name == "an admit" {
			want = hookbridge.ErrUnknownEvent
		}
		if out.Result != hookbridge.PostFailed || !errors.Is(out.Err, want) {
			t.Errorf("%s: %+v", name, out)
		}
	}
}
