package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// refundNumbered is a refund of its own amount under request id req-n, so no
// two are one held request.
func refundNumbered(t *testing.T, n int) gateway.Admission {
	t.Helper()
	args := []byte(fmt.Sprintf(`{"amount": %d, "currency": "EUR"}`, n))
	return admission(requestNamed(refundEnvelope(t, args), fmt.Sprintf("req-%d", n)), args)
}

// holdUnder admits refund n under run and reports whether it was held.
func holdUnder(t *testing.T, h *harness, n int, run *gateway.OpenedRun) bool {
	t.Helper()
	return h.admitA(under(refundNumbered(t, n), run)).Action == core.AwaitApproval
}

// TestOneRunHoldsNoMoreThanItsBound: with a plane bound of four held
// requests and a run bound of two, run-a's third refund closes the window it
// opened and blocks, while run-b still holds two; a hold of run-a expiring
// makes room for run-a alone.
func TestOneRunHoldsNoMoreThanItsBound(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, approveRefunds), withRuns(newRuns("root-a", "root-b")),
		func(c *gateway.Config) { c.MaxHeld, c.MaxHeldPerRun = 4, 2 })
	a, b := opened("run-a", "root-a"), opened("run-b", "root-b")
	for n := 1; n <= 2; n++ {
		if !holdUnder(t, h, n, a) {
			t.Fatalf("run-a's refund %d was not held", n)
		}
	}
	d := h.admitA(under(refundNumbered(t, 3), a))
	expectBlock(t, d, verdictIndeterminate, codeEvidenceUnavailable, gateway.PDPType)
	expectKinds(t, kindsOf(h.trailOf("req-3")), []controlv1.EventKind{kindProposed, kindDecided, kindApprovalRequested, kindApprovalExpired, kindBlocked})
	for n := 4; n <= 5; n++ {
		if !holdUnder(t, h, n, b) {
			t.Fatalf("run-b's refund %d, with run-a at its bound, was not held", n)
		}
	}
	if s := h.p.Stats(); s.Held != 4 {
		t.Errorf("Stats().Held = %d, want 4", s.Held)
	}
	h.clock.set(base().Add(10 * time.Minute))
	if !holdUnder(t, h, 6, a) {
		t.Fatal("run-a's refund after its holds expired was not held")
	}
}

// TestARunBoundOfZeroTakesTheDefault: with no run bound set and a plane bound
// of forty, one run holds sixteen and its seventeenth is blocked, and another
// run still holds.
func TestARunBoundOfZeroTakesTheDefault(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, approveRefunds), withRuns(newRuns("root-a", "root-b")),
		func(c *gateway.Config) { c.MaxHeld, c.MaxHeldPerRun = 40, 0 })
	a := opened("run-a", "root-a")
	for n := 1; n <= 16; n++ {
		if !holdUnder(t, h, n, a) {
			t.Fatalf("run-a's refund %d was not held", n)
		}
	}
	if holdUnder(t, h, 17, a) {
		t.Fatal("run-a's seventeenth refund was held")
	}
	if !holdUnder(t, h, 18, opened("run-b", "root-b")) {
		t.Fatal("run-b's refund was not held")
	}
}

// TestCallsUnderNoOpenedRunAreHeldToThePlaneBoundAlone: a plane that serves
// no opened runs has no run to bound, so its calls hold up to MaxHeld.
func TestCallsUnderNoOpenedRunAreHeldToThePlaneBoundAlone(t *testing.T) {
	h := build(t, modeEnforce, snapshot(t, approveRefunds), func(c *gateway.Config) { c.MaxHeld, c.MaxHeldPerRun = 3, 1 })
	for n := 1; n <= 3; n++ {
		if d := h.p.Admit(context.Background(), refundNumbered(t, n)); d.Action != core.AwaitApproval {
			t.Fatalf("refund %d was not held", n)
		}
	}
	if d := h.p.Admit(context.Background(), refundNumbered(t, 4)); d.Action == core.AwaitApproval {
		t.Fatal("a refund past MaxHeld was held")
	}
}

func TestNewRefusesANegativeRunBound(t *testing.T) {
	cfg := validConfig(t)
	cfg.MaxHeldPerRun = -1
	if p, err := gateway.New(cfg); p != nil || !errors.Is(err, gateway.ErrMaxHeldPerRun) {
		t.Errorf("New = %v, %v; want nil, ErrMaxHeldPerRun", p, err)
	}
}

// TestAnExpiredHoldTheSweepHasNotReachedLeavesItsRunRoom: a call closes at
// most eight expired holds, so two hundred of them outlast many calls; a run
// whose one hold expired is not at its bound of one, whether or not the sweep
// has reached that hold yet.
func TestAnExpiredHoldTheSweepHasNotReachedLeavesItsRunRoom(t *testing.T) {
	const n = 200
	roots := make([]string, n)
	for i := range roots {
		roots[i] = fmt.Sprintf("root-%d", i)
	}
	h := build(t, modeEnforce, snapshot(t, approveRefunds), withRuns(newRuns(roots...)),
		func(c *gateway.Config) { c.MaxHeld, c.MaxHeldPerRun = 4*n, 1 })
	runs := make([]*gateway.OpenedRun, n)
	for i := range runs {
		runs[i] = opened(fmt.Sprintf("run-%d", i), roots[i])
		if !holdUnder(t, h, i, runs[i]) {
			t.Fatalf("run-%d's first refund was not held", i)
		}
	}
	h.clock.set(base().Add(10 * time.Minute))
	for i, r := range runs {
		if !holdUnder(t, h, n+i, r) {
			t.Fatalf("run-%d's refund after its one hold expired was refused, %d calls after the expiry", i, i)
		}
	}
}
