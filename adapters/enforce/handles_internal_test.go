package enforce

import (
	"testing"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/gateway"
)

// A spent handle keeps what answers HANDLE_SPENT, its run, expiry and ending,
// and lets go of the execution: thousands of spent handles hold no
// authorized bytes.
func TestASpentHandleKeepsOnlyWhatAnswersForIt(t *testing.T) {
	now := time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC)
	h := newHandles(4, 4)
	if code := h.reserve("run-a", "k"); code != 0 {
		t.Fatalf("reserve = %s", code)
	}
	e := &entry{run: "run-a", key: "k", expires: now.Add(time.Minute), d: gateway.Disposition{
		Decision: &controlv1.Decision{DecisionId: "d-1"}, AuthorizedArgs: []byte(`{"pad":"xxxx"}`), ExecutionID: "x-1",
	}}
	id, ok := h.mint(e)
	if !ok {
		t.Fatal("mint refused")
	}
	taken, code, _ := h.take(id, "run-a", now)
	if code != 0 {
		t.Fatalf("take = %s", code)
	}
	h.spend(id, taken, enforcev1alpha1.Ending_ENDING_RECORDED)
	if e.d.Decision != nil || e.d.AuthorizedArgs != nil || e.d.ExecutionID != "" {
		t.Fatalf("a spent handle keeps its execution: %+v", e.d)
	}
	if _, code, ending := h.take(id, "run-a", now); code != enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_SPENT || ending != enforcev1alpha1.Ending_ENDING_RECORDED {
		t.Fatalf("the spent handle answers %s %s", code, ending)
	}
	if _, code, _ := h.take(id, "run-b", now); code != enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_UNKNOWN {
		t.Fatalf("the spent handle answers another run %s", code)
	}
	if _, code, _ := h.take(id, "run-a", now.Add(time.Minute)); code != enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_UNKNOWN {
		t.Fatalf("the spent handle answers after its expiry %s", code)
	}
}
