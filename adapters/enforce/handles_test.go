package enforce_test

import (
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/guardana/control/adapters/enforce"
	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

const (
	codeUnknown   = enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_UNKNOWN
	codeSpent     = enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_SPENT
	codeDuplicate = enforcev1alpha1.ErrorCode_ERROR_CODE_DUPLICATE_REQUEST
)

// refused posts body to path and returns the Error it was refused with,
// failing unless the status and code are the ones named.
func (r *rig) refused(t *testing.T, token, path, body string, status int, code enforcev1alpha1.ErrorCode) *enforcev1alpha1.Error {
	t.Helper()
	got, answer := r.post(t, token, path, body)
	return refusal(t, got, answer, status, code)
}

func TestAHandleIsKnownOnlyToItsOwnRunAndAnswersAsIfNeverMinted(t *testing.T) {
	r := newRig(t, defaults())
	handle := r.executed(t, runA, "refund", refund)
	never := r.refused(t, runA, enforce.PathComplete, completeBody("0123456789abcdef0123456789abcdef", refund, "COMPLETION_STATUS_SUCCESS", ""), http.StatusNotFound, codeUnknown)
	foreign := r.refused(t, runB, enforce.PathComplete, completeBody(handle, refund, "COMPLETION_STATUS_SUCCESS", ""), http.StatusNotFound, codeUnknown)
	foreignAbort := r.refused(t, runB, enforce.PathAbort, `{"handle":"`+handle+`","cause":"ABORT_CAUSE_NOT_SENT"}`, http.StatusNotFound, codeUnknown)
	for _, e := range []*enforcev1alpha1.Error{foreign, foreignAbort} {
		if e.GetMessage() != never.GetMessage() || e.GetEnding() != never.GetEnding() {
			t.Fatalf("a foreign handle answered %v, a handle never minted %v", e, never)
		}
	}
	if ending := r.complete(t, runA, handle, refund, "COMPLETION_STATUS_SUCCESS"); ending != recorded {
		t.Fatalf("the foreign attempts spent the handle: %s", ending)
	}
}

func TestAHandleExpiresAtItsLifetime(t *testing.T) {
	r := newRig(t, defaults())
	early := r.executed(t, runA, "refund", refund)
	late := r.executed(t, runA, "refund", refund)
	r.clock.advance(time.Minute - time.Nanosecond)
	if ending := r.complete(t, runA, early, refund, "COMPLETION_STATUS_SUCCESS"); ending != recorded {
		t.Fatalf("a handle one nanosecond before its expiry answered %s", ending)
	}
	r.clock.advance(time.Nanosecond)
	r.refused(t, runA, enforce.PathComplete, completeBody(late, refund, "COMPLETION_STATUS_SUCCESS", ""), http.StatusNotFound, codeUnknown)
	r.refused(t, runA, enforce.PathAbort, `{"handle":"`+late+`","cause":"ABORT_CAUSE_NOT_SENT"}`, http.StatusNotFound, codeUnknown)
}

func TestASpentHandleAnswersHowItEndedToItsOwnRunUntilItExpires(t *testing.T) {
	r := newRig(t, defaults())
	handle := r.executed(t, runA, "refund", refund)
	if ending := r.complete(t, runA, handle, refund, "COMPLETION_STATUS_SUCCESS"); ending != recorded {
		t.Fatalf("ending %s", ending)
	}
	for _, req := range []struct{ path, body string }{
		{enforce.PathComplete, completeBody(handle, refund, "COMPLETION_STATUS_SUCCESS", "")},
		{enforce.PathAbort, `{"handle":"` + handle + `","cause":"ABORT_CAUSE_NOT_SENT"}`},
	} {
		if e := r.refused(t, runA, req.path, req.body, http.StatusConflict, codeSpent); e.GetEnding() != recorded {
			t.Fatalf("%s: a spent handle answered ending %s", req.path, e.GetEnding())
		}
		if e := r.refused(t, runB, req.path, req.body, http.StatusNotFound, codeUnknown); e.GetEnding() != 0 {
			t.Fatalf("another run learned how the handle ended: %v", e)
		}
	}
	if r.count(kindDone) != 1 {
		t.Fatalf("a replayed complete was recorded: %v", r.kinds())
	}
	r.clock.advance(time.Minute)
	r.refused(t, runA, enforce.PathComplete, completeBody(handle, refund, "COMPLETION_STATUS_SUCCESS", ""), http.StatusNotFound, codeUnknown)
}

func TestSpentHandlesAreKeptUpToTheirBound(t *testing.T) {
	for _, tc := range []struct {
		max       int
		firstKept bool
	}{{1, false}, {2, true}} {
		t.Run(strconv.Itoa(tc.max), func(t *testing.T) {
			o := defaults()
			o.adapter = func(c *enforce.Config) { c.MaxSpent = tc.max }
			r := newRig(t, o)
			first := r.executed(t, runA, "refund", refund)
			second := r.executed(t, runA, "refund", refund)
			r.complete(t, runA, first, refund, "COMPLETION_STATUS_SUCCESS")
			r.complete(t, runA, second, refund, "COMPLETION_STATUS_SUCCESS")
			want, status := codeUnknown, http.StatusNotFound
			if tc.firstKept {
				want, status = codeSpent, http.StatusConflict
			}
			r.refused(t, runA, enforce.PathComplete, completeBody(first, refund, "COMPLETION_STATUS_SUCCESS", ""), status, want)
			r.refused(t, runA, enforce.PathComplete, completeBody(second, refund, "COMPLETION_STATUS_SUCCESS", ""), http.StatusConflict, codeSpent)
		})
	}
}

func TestAClosedRunCanNeitherAdmitNorCloseWhatItOpened(t *testing.T) {
	r := newRig(t, defaults())
	handle := r.executed(t, runShut, "refund", refund)
	r.runs.close(runShut)
	r.refused(t, runShut, enforce.PathAdmit, admitBody("read_file", `{"path":"a"}`), http.StatusUnauthorized, enforcev1alpha1.ErrorCode_ERROR_CODE_UNAUTHENTICATED)
	r.refused(t, runShut, enforce.PathComplete, completeBody(handle, refund, "COMPLETION_STATUS_SUCCESS", ""), http.StatusUnauthorized, enforcev1alpha1.ErrorCode_ERROR_CODE_UNAUTHENTICATED)
	r.refused(t, runA, enforce.PathComplete, completeBody(handle, refund, "COMPLETION_STATUS_SUCCESS", ""), http.StatusNotFound, codeUnknown)
	if n := r.a.Sweep(t.Context(), r.clock.read().Add(time.Minute)); n != 1 {
		t.Fatalf("Sweep abandoned %d", n)
	}
}

// Two admits with one key race through one receiver: exactly one gets the
// handle, whichever order they reach it in.
func TestTwoConcurrentAdmitsWithOneKeyGetOneHandle(t *testing.T) {
	r := newRig(t, defaults())
	for i := range 20 {
		key := `,"requestKey":"k-` + strconv.Itoa(i) + `"`
		body := `{"tool":"read_file","arguments":"` + b64(`{"path":"a"}`) + `"` + key + `}`
		var wg sync.WaitGroup
		statuses := make([]int, 2)
		answers := make([][]byte, 2)
		for j := range 2 {
			wg.Go(func() { statuses[j], answers[j] = r.post(t, runA, enforce.PathAdmit, body) })
		}
		wg.Wait()
		var handle string
		var executed, duplicate int
		for j := range 2 {
			switch statuses[j] {
			case http.StatusOK:
				executed++
				handle = outcome(t, statuses[j], answers[j]).GetExecution().GetHandle()
			case http.StatusConflict:
				refusal(t, statuses[j], answers[j], http.StatusConflict, codeDuplicate)
				duplicate++
			}
		}
		if executed != 1 || duplicate != 1 {
			t.Fatalf("round %d: %d executed, %d duplicates: %q", i, executed, duplicate, answers)
		}
		r.complete(t, runA, handle, `{"path":"a"}`, "COMPLETION_STATUS_SUCCESS")
		again := r.admit(t, runA, "read_file", `{"path":"a"}`, key)
		if again.GetOutcome() != outcomeExecute {
			t.Fatalf("round %d: the key stayed taken after its execution closed", i)
		}
		r.complete(t, runA, again.GetExecution().GetHandle(), `{"path":"a"}`, "COMPLETION_STATUS_SUCCESS")
	}
	if r.count(kindProposed) != 40 {
		t.Fatalf("a duplicate wrote a trail: %d proposals", r.count(kindProposed))
	}
}

func TestARequestKeyIsTheRunsOwnAndHeldOnlyWhileItsExecutionIsOpen(t *testing.T) {
	o := defaults()
	o.rules = []string{allowReads, denyRefunds}
	r := newRig(t, o)
	key := `,"requestKey":"shared"`
	if resp := r.admit(t, runA, "read_file", `{"path":"a"}`, key); resp.GetOutcome() != outcomeExecute {
		t.Fatalf("run A: %s", resp.GetOutcome())
	}
	if resp := r.admit(t, runB, "read_file", `{"path":"a"}`, key); resp.GetOutcome() != outcomeExecute {
		t.Fatalf("run B, same key: %s", resp.GetOutcome())
	}
	for range 2 {
		if resp := r.admit(t, runB, "refund", refund, `,"requestKey":"denied"`); resp.GetOutcome() != outcomeBlock {
			t.Fatalf("a blocked admit kept its key: %s", resp.GetOutcome())
		}
	}
	before := len(r.sink.Events())
	r.refused(t, runA, enforce.PathAdmit, `{"tool":"read_file"`+key+`}`, http.StatusConflict, codeDuplicate)
	if after := len(r.sink.Events()); after != before {
		t.Fatalf("a duplicate wrote %d events", after-before)
	}
}

func TestTwoConcurrentResumesSpendTheApprovalOnce(t *testing.T) {
	o := defaults()
	o.mode, o.rules = modeApprove, []string{approveRefunds}
	r := newRig(t, o)
	held := r.admit(t, runA, "refund", refund, "")
	if err := r.store.Answer(held.GetPending().GetApprovalId(), controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "approver-1", "", r.clock.read()); err != nil {
		t.Fatal(err)
	}
	r.clock.advance(5 * time.Second)
	var wg sync.WaitGroup
	answers := make([]*enforcev1alpha1.AdmitResponse, 2)
	for j := range 2 {
		wg.Go(func() {
			status, body := r.post(t, runA, enforce.PathAdmit, admitBody("refund", refund))
			var resp enforcev1alpha1.AdmitResponse
			if status == http.StatusOK && protojson.Unmarshal(body, &resp) == nil {
				answers[j] = &resp
			}
		})
	}
	wg.Wait()
	var executed int
	for _, a := range answers {
		if a.GetOutcome() == outcomeExecute {
			executed++
		}
	}
	if executed != 1 || r.count(kindStarted) != 1 {
		t.Fatalf("%d executes, %d starts: %v", executed, r.count(kindStarted), answers)
	}
}

func TestACompleteAndAnAbortRaceForOneHandle(t *testing.T) {
	r := newRig(t, defaults())
	for i := range 20 {
		handle := r.executed(t, runA, "refund", refund)
		var wg sync.WaitGroup
		statuses := make([]int, 2)
		wg.Go(func() {
			statuses[0], _ = r.post(t, runA, enforce.PathComplete, completeBody(handle, refund, "COMPLETION_STATUS_SUCCESS", ""))
		})
		wg.Go(func() {
			statuses[1], _ = r.post(t, runA, enforce.PathAbort, `{"handle":"`+handle+`","cause":"ABORT_CAUSE_NOT_SENT"}`)
		})
		wg.Wait()
		if (statuses[0] == http.StatusOK) == (statuses[1] == http.StatusOK) || statuses[0]+statuses[1] != http.StatusOK+http.StatusConflict {
			t.Fatalf("round %d: complete %d, abort %d", i, statuses[0], statuses[1])
		}
	}
	if closings := r.count(kindDone) + r.count(kindFailed); closings != 20 {
		t.Fatalf("%d closings for 20 executions", closings)
	}
}
