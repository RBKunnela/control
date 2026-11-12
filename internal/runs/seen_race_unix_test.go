//go:build unix

package runs_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// heldFor is how long a call held behind another's first admission is
// watched for an answer it must not give.
const heldFor = 200 * time.Millisecond

// resolveAsync resolves token for alice on p in another goroutine and
// answers on the channel it returns.
func resolveAsync(ctx context.Context, p *runs.Plane, token string, at time.Time) chan error {
	answer := make(chan error, 1)
	go func() {
		_, err := p.Resolve(ctx, token, alice, at)
		answer <- err
	}()
	return answer
}

// requireUnanswered fails the test when answer gives an answer within
// heldFor, and puts that answer back.
func requireUnanswered(t *testing.T, answer chan error) {
	t.Helper()
	select {
	case err := <-answer:
		t.Errorf("a second call of the child was answered (%v) while the first still forced its .seen to disk", err)
		answer <- err
	case <-time.After(heldFor):
	}
}

// failFirstSeenSync fails the first directory sync of the child's .seen,
// running during first, and lets every later one through.
func failFirstSeenSync(t *testing.T, child string, during func()) {
	t.Helper()
	var calls atomic.Int32
	restore := runs.FailSyncAfterMaking(child+".seen", func() error {
		if calls.Add(1) > 1 {
			return nil
		}
		during()
		return errSyncFailed
	})
	t.Cleanup(restore)
}

// TestACallWaitsForAnotherCallsFirstAdmission: a call of a child that finds
// the .seen another call of it is still forcing to disk waits for that call,
// so it is never admitted on a marker the other then removes; it makes its
// own, and the child keeps running once its parent's close is carried.
func TestACallWaitsForAnotherCallsFirstAdmission(t *testing.T) {
	dir, a := newSigned(t)
	parent, parentToken := openSignedRoot(t, a, "alice")
	child, childToken := openSignedChild(t, a, parent.ID, opened)
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(time.Minute)
	if _, err := p.Resolve(t.Context(), parentToken, alice, at); err != nil {
		t.Fatalf("the parent's call, which starts the root's state: %v", err)
	}
	var second chan error
	failFirstSeenSync(t, child.ID, func() {
		second = resolveAsync(t.Context(), p, childToken, at)
		requireUnanswered(t, second)
	})
	if _, err := p.Resolve(t.Context(), childToken, alice, at); causeOf(t, err) != runs.CauseUnreadable {
		t.Fatalf("the first call, whose .seen fails = %v, want unreadable", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("the second call, once the first was refused: %v", err)
	}
	requireSeen(t, dir, child.ID, true)
	carryParentClose(t, a, p, parent, parentToken, at)
	if _, err := p.Resolve(t.Context(), childToken, alice, at.Add(time.Minute)); err != nil {
		t.Fatalf("the child admitted before the carry, after it: %v", err)
	}
}

// TestACallAfterTheCarryIsNotAdmittedOnAnUnfinishedSeen: a call of a child
// that starts after its parent's close is carried, while a first call's
// .seen is still being forced to disk, is refused once that first call is
// refused, and no .seen is left.
func TestACallAfterTheCarryIsNotAdmittedOnAnUnfinishedSeen(t *testing.T) {
	dir, a := newSigned(t)
	parent, parentToken := openSignedRoot(t, a, "alice")
	child, childToken := openSignedChild(t, a, parent.ID, opened)
	p := signedPlane(t, dir, alicesJudge)
	at := opened.Add(time.Minute)
	if _, err := p.Resolve(t.Context(), parentToken, alice, at); err != nil {
		t.Fatalf("the parent's call, which starts the root's state: %v", err)
	}
	var second chan error
	failFirstSeenSync(t, child.ID, func() {
		carryParentClose(t, a, p, parent, parentToken, at)
		second = resolveAsync(t.Context(), p, childToken, at)
		requireUnanswered(t, second)
	})
	if _, err := p.Resolve(t.Context(), childToken, alice, at); causeOf(t, err) != runs.CauseUnreadable {
		t.Fatalf("the first call, whose .seen fails = %v, want unreadable", err)
	}
	requireParentClosed(t, <-second)
	requireSeen(t, dir, child.ID, false)
}
