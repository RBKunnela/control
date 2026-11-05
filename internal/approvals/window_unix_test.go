//go:build unix

package approvals_test

import (
	"errors"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
)

// raceFor bounds each race below.
const raceFor = 4 * time.Second

// swapAfterJudge returns an option whose step, the first time a call's judge
// passes after arm, renames dir away and puts a link to other at its name:
// the swap lands between the judge and every file operation behind it.
func swapAfterJudge(t *testing.T, dir, other string) (opt approvals.Option, arm func()) {
	t.Helper()
	var armed, swapped atomic.Bool
	steps := func(step string) {
		if step != approvals.StepJudged || !armed.Load() || !swapped.CompareAndSwap(false, true) {
			return
		}
		if err := os.Rename(dir, dir+".moved"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(other, dir); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() {
		if armed.Load() && !swapped.Load() {
			t.Error("the swap never ran: no call passed its judge")
		}
	})
	return approvals.WithSteps(steps), func() { armed.Store(true) }
}

// twoStores opens a plane over a directory of its own and one over another
// directory, each holding a record under approval id SHARED for a request of
// its own.
func twoStores(t *testing.T) (p *approvals.Plane, dir string, q *approvals.Plane, other string) {
	t.Helper()
	p, dir = openPlane(t)
	q, other = openPlane(t)
	if err := p.Hold(t.Context(), held(t, "SHARED", "req-home"), minted); err != nil {
		t.Fatal(err)
	}
	if err := q.Hold(t.Context(), held(t, "SHARED", "req-away"), minted); err != nil {
		t.Fatal(err)
	}
	return p, dir, q, other
}

// recordIn reads the request id and the state of approvalID in dir through
// an approver opened now.
func recordIn(t *testing.T, dir, approvalID string) (string, controlv1.ApprovalState) {
	t.Helper()
	l, err := openApprover(t, dir).List(t.Context())
	if err != nil {
		t.Fatalf("listing %s: %v", dir, err)
	}
	for _, e := range l.Entries {
		if e.Record.ApprovalID == approvalID {
			return e.Record.RequestID, e.Record.Approval.GetState()
		}
	}
	t.Fatalf("%s holds no record %s", dir, approvalID)
	return "", 0
}

// TestAnAnswerAfterItsJudgeLandsInTheJudgedDirectory: the name is swapped
// for a link to another store after the approver's call judged its
// directory. The answer is filed in the directory the approver opened, and
// says no plane holds it, which is true of that directory and not of the
// other; the other store's record under the same id stays pending, and the
// next call is refused because the name no longer names the directory.
func TestAnAnswerAfterItsJudgeLandsInTheJudgedDirectory(t *testing.T) {
	p, dir, _, other := twoStores(t)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	opt, arm := swapAfterJudge(t, dir, other)
	a := openApprover(t, dir, opt)
	arm()
	done, err := a.Answer(t.Context(), "SHARED", approved, "approver-1", "", minted)
	if err != nil {
		t.Fatalf("the answer after its judge: %v", err)
	}
	if done.PlaneRunning {
		t.Error("the answer says a plane holds the directory it was filed in, which none does")
	}
	if req, st := recordIn(t, dir+".moved", "SHARED"); req != "req-home" || st != approved {
		t.Errorf("the opened directory's SHARED is %s %s, want req-home approved", req, st)
	}
	if req, st := recordIn(t, other, "SHARED"); req != "req-away" || st != controlv1.ApprovalState_APPROVAL_STATE_PENDING {
		t.Errorf("the other store's SHARED is %s %s, want req-away pending", req, st)
	}
	if _, err := a.List(t.Context()); !errors.Is(err, approvals.ErrDirectoryChanged) {
		t.Errorf("a listing once another store stands at the name = %v, want ErrDirectoryChanged", err)
	}
}

// TestAListingAfterItsJudgeReadsTheJudgedDirectory: the same swap under a
// listing, which names the opened directory's record and nothing of the
// other store's.
func TestAListingAfterItsJudgeReadsTheJudgedDirectory(t *testing.T) {
	p, dir, q, other := twoStores(t)
	if err := p.Hold(t.Context(), held(t, "HOME", "req-home2"), minted); err != nil {
		t.Fatal(err)
	}
	if err := q.Hold(t.Context(), held(t, "ELSEWHERE", "req-away2"), minted); err != nil {
		t.Fatal(err)
	}
	opt, arm := swapAfterJudge(t, dir, other)
	a := openApprover(t, dir, opt)
	arm()
	l, err := a.List(t.Context())
	if err != nil {
		t.Fatalf("the listing after its judge: %v", err)
	}
	var ids, requests []string
	for _, e := range l.Entries {
		ids, requests = append(ids, e.Record.ApprovalID), append(requests, e.Record.RequestID)
	}
	slices.Sort(ids)
	slices.Sort(requests)
	if !slices.Equal(ids, []string{"HOME", "SHARED"}) || !slices.Equal(requests, []string{"req-home", "req-home2"}) {
		t.Errorf("the listing names %v for %v, want HOME and SHARED of the opened directory", ids, requests)
	}
}

// approvedElsewhere is a store no plane holds, with an approved record under
// the binding of req-1.
func approvedElsewhere(t *testing.T) string {
	t.Helper()
	q, other := openPlane(t)
	if err := q.Hold(t.Context(), held(t, firstApproval, "req-1"), minted); err != nil {
		t.Fatal(err)
	}
	if _, err := openApprover(t, other).Answer(t.Context(), firstApproval, approved, "approver-1", "", minted); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	return other
}

// callAfterSwap opens a plane over a fresh directory home, swaps other in at
// its name after the judge of one call, makes that call and puts home back.
func callAfterSwap(t *testing.T, home, other string, call func(p *approvals.Plane) (any, error)) (any, error) {
	t.Helper()
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	opt, arm := swapAfterJudge(t, home, other)
	p, err := approvals.OpenPlane(home, opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	arm()
	got, err := call(p)
	if rerr := errors.Join(os.Remove(home), os.Rename(home+".moved", home)); rerr != nil {
		t.Fatal(rerr)
	}
	return got, err
}

// TestAPlaneAfterItsJudgeReadsTheDirectoryItHolds: the plane holds its own
// directory's lock and the other store holds an approved record under the
// plane's binding. Swapped in after the judge, it is not found, and it stays
// approved.
func TestAPlaneAfterItsJudgeReadsTheDirectoryItHolds(t *testing.T) {
	dir := t.TempDir()
	other := approvedElsewhere(t)
	binding := bindingOf(t, "req-1")
	for name, call := range map[string]func(p *approvals.Plane) (any, error){
		"Find": func(p *approvals.Plane) (any, error) { return p.Find(t.Context(), binding, minted) },
	} {
		got, err := callAfterSwap(t, dir+"/"+name, other, call)
		if !errors.Is(err, approvals.ErrNoApproval) {
			t.Errorf("%s after its judge = %v, %v; want ErrNoApproval from the directory it holds", name, got, err)
		}
	}
	if req, st := recordIn(t, other, firstApproval); req != "req-1" || st != approved {
		t.Errorf("the other store's record is %s %s, want req-1 approved and unspent", req, st)
	}
	if names := recordNames(t, other); !slices.Equal(names, []string{firstApproval + ".1-answered.rec"}) {
		t.Errorf("the other store holds %v, want the answered record alone", names)
	}
}

// swapper renames dir away, puts a link to other at its name, and puts dir
// back, over and over until the test's race ends, and stop reports how many
// swaps put the link in place. The parent of dir is what an attacker writes.
// The racing tests over it catch a store that works fully by path; the
// swapAfterJudge tests above hold each operation on its own.
func swapper(t *testing.T, dir, other string) (stop func() int64) {
	t.Helper()
	done := make(chan struct{})
	var wg sync.WaitGroup
	var swaps atomic.Int64
	wg.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			if os.Rename(dir, dir+".moved") != nil {
				continue
			}
			linked := os.Symlink(other, dir) == nil
			_ = os.Remove(dir)
			if err := os.Rename(dir+".moved", dir); err != nil {
				t.Error(err)
				return
			}
			if linked {
				swaps.Add(1)
			}
		}
	})
	return func() int64 {
		close(done)
		wg.Wait()
		return swaps.Load()
	}
}

// TestAnApproverRacingASwapNeverAnswersTheOtherStore: an approver answers
// the other store's approval id while the name flips between its directory
// and a link to the other store. No answer lands there.
func TestAnApproverRacingASwapNeverAnswersTheOtherStore(t *testing.T) {
	_, dir := openPlane(t)
	a := openApprover(t, dir)
	q, other := openPlane(t)
	if err := q.Hold(t.Context(), held(t, "ELSEWHERE", "req-9"), minted); err != nil {
		t.Fatal(err)
	}
	stop := swapper(t, dir, other)
	calls, landed := 0, false
	for deadline := time.Now().Add(raceFor); time.Now().Before(deadline) && !landed; calls++ {
		_, _ = a.Answer(t.Context(), "ELSEWHERE", approved, "approver-1", "", minted)
		_, err := os.Lstat(other + "/ELSEWHERE.1-answered.rec")
		landed = err == nil
	}
	if swaps := stop(); swaps == 0 || calls == 0 {
		t.Fatalf("%d swaps and %d answers: the race examined nothing", swaps, calls)
	}
	if landed {
		t.Errorf("an approver opened over %s filed an answer in %s", dir, other)
	}
	if _, st := recordIn(t, other, "ELSEWHERE"); st != controlv1.ApprovalState_APPROVAL_STATE_PENDING {
		t.Errorf("the other store's record is %s", st)
	}
}

// TestAPlaneRacingASwapNeverFindsTheOtherStoresApproval: the plane holds its
// own directory while the name flips to a link to a store holding an
// approved record under the plane's binding. Find never returns it.
func TestAPlaneRacingASwapNeverFindsTheOtherStoresApproval(t *testing.T) {
	p, dir := openPlane(t)
	other := approvedElsewhere(t)
	binding := bindingOf(t, "req-1")
	stop := swapper(t, dir, other)
	calls, found := 0, 0
	for deadline := time.Now().Add(raceFor); time.Now().Before(deadline); calls++ {
		if recs, err := p.Find(t.Context(), binding, minted); err == nil && len(recs) > 0 {
			found++
		}
	}
	if swaps := stop(); swaps == 0 || calls == 0 {
		t.Fatalf("%d swaps and %d calls: the race examined nothing", swaps, calls)
	}
	if found > 0 {
		t.Errorf("the plane holding %s read %s's approval %d times", dir, other, found)
	}
}
