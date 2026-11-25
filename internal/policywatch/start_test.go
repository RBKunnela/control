package policywatch_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policywatch"
)

// floorAt2 is a floor holding serial 2 at digest, issued at issued.
func floorAt2(t *testing.T, digest string, issued time.Time) policy.Floor {
	t.Helper()
	f, err := policy.NewFloor(planeID, 2, digest, issued, issued)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (r *rig) start() (policywatch.StartResult, error) {
	return policywatch.Start(context.Background(), r.opts)
}

// expectRefused fails unless the start was refused with want, naming the
// bundle's serial and the floor's, 2, and installed nothing.
func (r *rig) expectRefused(err error, want error, bundleSerial string) {
	r.t.Helper()
	if !errors.Is(err, want) {
		r.t.Fatalf("Start = %v, want %v", err, want)
	}
	for _, named := range []string{"bundle serial " + bundleSerial, "floor serial 2"} {
		if !strings.Contains(err.Error(), named) {
			r.t.Errorf("the refusal %q does not name %q", err, named)
		}
	}
	if r.holder.Current() != nil {
		r.t.Fatal("a refused start installed a bundle")
	}
}

func TestAFirstStartWithItsStatementIsConfirmed(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	digest := r.writeBundle(2, "v2", 600)
	r.writeStatement(2, digest, t0)
	res, err := r.start()
	if err != nil || res.Action != policy.StartConfirmed || res.Unconfirmed != nil {
		t.Fatalf("Start = %+v, %v; want confirmed", res, err)
	}
	r.expectSnapshot(2, digest, t0)
	r.expectFloor(2, digest, t0)
}

func TestAFirstStartWithoutAStatementIsUnconfirmed(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	digest := r.writeBundle(2, "v2", 600)
	res, err := r.start()
	if err != nil || res.Action != policy.StartUnconfirmed || !errors.Is(res.Unconfirmed, policy.ErrStatementMissing) {
		t.Fatalf("Start = %+v, %v; want unconfirmed for want of a statement", res, err)
	}
	r.expectSnapshot(2, digest, time.Time{})
	if f, writes := r.store.stored(); f.HasSerial() || writes != 0 {
		t.Errorf("an unconfirmed start raised the floor to %v", f)
	}
}

// A statement that does not verify leaves the floor's own bundle unconfirmed
// and says why.
func TestAStartWithAStatementThatDoesNotVerifyIsUnconfirmed(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	digest := r.writeBundle(2, "v2", 600)
	r.write(r.opts.StatementPath, statementBytes(t, planeID, 2, digest, t0, otherKey, freshKeyID))
	res, err := r.start()
	if err != nil || res.Action != policy.StartUnconfirmed || !errors.Is(res.Unconfirmed, policy.ErrStatementSignature) {
		t.Fatalf("Start = %+v, %v; want unconfirmed, the signature named", res, err)
	}
	r.expectSnapshot(2, digest, time.Time{})
}

// The floor's own bundle starts confirmed by a statement the floor takes, and
// unconfirmed without one.
func TestTheFloorsOwnBundleStarts(t *testing.T) {
	r := newRig(t, emptyFloor(t))
	digest := r.writeBundle(2, "v2", 600)
	r.store.floor = floorAt2(t, digest, t0)
	res, err := r.start()
	if err != nil || res.Action != policy.StartUnconfirmed {
		t.Fatalf("Start = %+v, %v; want unconfirmed", res, err)
	}
	r.expectSnapshot(2, digest, time.Time{})

	r = newRig(t, floorAt2(t, digest, t0))
	r.writeBundle(2, "v2", 600)
	r.writeStatement(2, digest, t0.Add(5*time.Second))
	if res, err := r.start(); err != nil || res.Action != policy.StartConfirmed {
		t.Fatalf("Start = %+v, %v; want confirmed", res, err)
	}
	r.expectSnapshot(2, digest, t0.Add(5*time.Second))
}

func TestAStartBelowOrBesideTheFloorIsRefused(t *testing.T) {
	floorDigest := signed(t, doc(planeID, 2, "v2", 600), bundleKey).GetRef().GetDigest()

	r := newRig(t, floorAt2(t, floorDigest, t0))
	r.writeStatement(1, r.writeBundle(1, "v1", 600), t0.Add(time.Second))
	_, err := r.start()
	r.expectRefused(err, policy.ErrBelowFloor, "1")

	r = newRig(t, floorAt2(t, floorDigest, t0))
	r.writeStatement(2, r.writeBundle(2, "v2-other", 600), t0.Add(time.Second))
	_, err = r.start()
	r.expectRefused(err, policy.ErrFloorSerialReused, "2")
}

// A bundle above the floor starts only with its statement: without one, and
// with one dated ahead of the clock, the start is refused naming both serials.
func TestAStartAboveTheFloorNeedsItsStatement(t *testing.T) {
	floorDigest := signed(t, doc(planeID, 2, "v2", 600), bundleKey).GetRef().GetDigest()

	r := newRig(t, floorAt2(t, floorDigest, t0))
	r.writeBundle(3, "v3", 600)
	_, err := r.start()
	r.expectRefused(err, policy.ErrAboveFloorUnbound, "3")

	r = newRig(t, floorAt2(t, floorDigest, t0))
	r.writeStatement(3, r.writeBundle(3, "v3", 600), r.clock.Wall().Add(time.Minute))
	_, err = r.start()
	r.expectRefused(err, policy.ErrAboveFloorUnbound, "3")

	r = newRig(t, floorAt2(t, floorDigest, t0))
	next := r.writeBundle(3, "v3", 600)
	r.writeStatement(3, next, t0.Add(time.Second))
	if res, err := r.start(); err != nil || res.Action != policy.StartConfirmed {
		t.Fatalf("Start = %+v, %v; want confirmed", res, err)
	}
	r.expectFloor(3, next, t0.Add(time.Second))
}

func TestAStartIsRefusedForWhatItCannotRead(t *testing.T) {
	for _, c := range []struct {
		name  string
		edit  func(r *rig)
		wants string
	}{
		{"a floor the store cannot read", func(r *rig) { r.store.failRead = true }, errStore.Error()},
		{"no bundle file", func(r *rig) {
			if err := os.Remove(r.opts.BundlePath); err != nil {
				r.t.Fatal(err)
			}
		}, "no such file"},
		{"a bundle that is not one", func(r *rig) { r.write(r.opts.BundlePath, []byte("not a bundle")) }, "not a serialized policy bundle"},
		{"a bundle of another id", func(r *rig) {
			r.write(r.opts.BundlePath, marshal(r.t, signed(r.t, doc("other", 2, "v2", 600), bundleKey)))
		}, policy.ErrBundlePin.Error()},
		{"a budget not longer than the interval", func(r *rig) { r.writeBundle(2, "v2", int64(interval/time.Second)) },
			"the budget of 5s is not longer than the poll interval 5s"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, emptyFloor(t))
			r.writeStatement(2, r.writeBundle(2, "v2", 600), t0)
			if _, err := r.start(); err != nil {
				t.Fatalf("the files before the edit do not start: %v", err)
			}
			r = newRig(t, emptyFloor(t))
			r.writeStatement(2, r.writeBundle(2, "v2", 600), t0)
			c.edit(r)
			_, err := r.start()
			if err == nil || !strings.Contains(err.Error(), c.wants) {
				t.Fatalf("Start = %v, want a refusal saying %q", err, c.wants)
			}
			if r.holder.Current() != nil {
				t.Fatal("a refused start installed a bundle")
			}
		})
	}
}

// An expired statement at start is no statement: the floor's own bundle, a
// first one included, starts unconfirmed, a higher bundle is refused as one
// without its statement, and the floor is not raised in any of them.
func TestAnExpiredStatementAtStartIsNoStatement(t *testing.T) {
	expiredAt := func(r *rig) time.Time { return r.clock.Wall().Add(-operatorBudget - 600*time.Second) }

	r := newRig(t, emptyFloor(t))
	digest := r.writeBundle(2, "v2", 600)
	r.writeStatement(2, digest, expiredAt(r))
	res, err := r.start()
	if err != nil || res.Action != policy.StartUnconfirmed || !errors.Is(res.Unconfirmed, policywatch.ErrStatementExpired) {
		t.Fatalf("Start = %+v, %v; want unconfirmed, the expiry named", res, err)
	}
	r.expectSnapshot(2, digest, time.Time{})
	if f, writes := r.store.stored(); f.HasSerial() || writes != 0 {
		t.Errorf("an expired statement raised the floor to %v", f)
	}

	floorDigest := signed(t, doc(planeID, 2, "v2", 600), bundleKey).GetRef().GetDigest()
	old := t0.Add(-time.Hour)
	r = newRig(t, floorAt2(t, floorDigest, old))
	r.writeBundle(2, "v2", 600)
	r.writeStatement(2, floorDigest, expiredAt(r))
	if res, err := r.start(); err != nil || res.Action != policy.StartUnconfirmed {
		t.Fatalf("Start = %+v, %v; want the floor's own bundle unconfirmed", res, err)
	}
	r.expectFloor(2, floorDigest, old)

	r = newRig(t, floorAt2(t, floorDigest, old))
	r.writeStatement(3, r.writeBundle(3, "v3", 600), expiredAt(r))
	_, err = r.start()
	r.expectRefused(err, policy.ErrAboveFloorUnbound, "3")
	r.expectFloor(2, floorDigest, old)
}

// TestAStatementThatExpiresWhileTheFloorIsHeldIsNoStatement starts a bundle
// above the floor a second before its statement expires, and holds the
// floor's read until two seconds later.
func TestAStatementThatExpiresWhileTheFloorIsHeldIsNoStatement(t *testing.T) {
	floorDigest := signed(t, doc(planeID, 2, "v2", 600), bundleKey).GetRef().GetDigest()
	r := newRig(t, floorAt2(t, floorDigest, t0))
	issued := r.clock.Wall().Add(-599 * time.Second)
	r.writeStatement(3, r.writeBundle(3, "v3", 600), issued)
	if res, err := r.start(); err != nil || res.Action != policy.StartConfirmed {
		t.Fatalf("the control, a start not held: %+v, %v; want confirmed", res, err)
	}

	r = newRig(t, floorAt2(t, floorDigest, t0))
	r.writeStatement(3, r.writeBundle(3, "v3", 600), issued)
	r.store.readHeld, r.store.readRelease = make(chan struct{}, 1), make(chan struct{})
	started := make(chan error, 1)
	go func() {
		_, err := r.start()
		started <- err
	}()
	select {
	case <-r.store.readHeld:
	case <-time.After(10 * time.Second):
		t.Fatal("the start never read the floor")
	}
	r.clock.advance(2 * time.Second)
	close(r.store.readRelease)
	var err error
	select {
	case err = <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the start did not return once the floor was read")
	}
	r.expectRefused(err, policy.ErrAboveFloorUnbound, "3")
	r.expectFloor(2, floorDigest, t0)
}

// slowRaise is the rig's store whose raise waits, as on a lock another
// process holds, while the clock moves by wait.
type slowRaise struct {
	*memFloor
	clock *clock
	wait  time.Duration
}

func (s *slowRaise) RaiseAt(ctx context.Context, st policy.Statement, now policy.Reading) (policy.Floor, error) {
	s.clock.advance(s.wait)
	return s.memFloor.RaiseAt(ctx, st, now)
}

// TestAStatementThatExpiresWhileTheRaiseWaitsRaisesNothing starts a bundle
// above the floor a second before its statement expires, and the floor's
// raise waits two seconds on the lock: the start is refused naming the
// expiry, and the floor and the holder are as they were. The control's raise
// waits no time.
func TestAStatementThatExpiresWhileTheRaiseWaitsRaisesNothing(t *testing.T) {
	floorDigest := signed(t, doc(planeID, 2, "v2", 600), bundleKey).GetRef().GetDigest()
	for _, wait := range []time.Duration{0, 2 * time.Second} {
		r := newRig(t, floorAt2(t, floorDigest, t0))
		h, err := policy.NewFloorHolder(planeID, &slowRaise{memFloor: r.store, clock: r.clock, wait: wait})
		if err != nil {
			t.Fatal(err)
		}
		r.holder, r.opts.Holder = h, h
		issued := r.clock.Wall().Add(-599 * time.Second)
		r.writeStatement(3, r.writeBundle(3, "v3", 600), issued)
		res, err := r.start()
		if wait == 0 {
			if err != nil || res.Action != policy.StartConfirmed {
				t.Fatalf("the control, a raise that waits no time: %+v, %v; want confirmed", res, err)
			}
			continue
		}
		var refusal *policywatch.StartError
		if !errors.As(err, &refusal) || refusal.Input != policywatch.InputStatement || !errors.Is(err, policywatch.ErrStatementExpired) {
			t.Errorf("a start whose raise waited past the statement's budget = %v, want a refusal of the statement as expired", err)
		}
		if h.Current() != nil {
			t.Error("a refused start installed a bundle")
		}
		r.expectFloor(2, floorDigest, t0)
	}
}
