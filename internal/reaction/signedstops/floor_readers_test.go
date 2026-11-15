//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package signedstops_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/signedstops"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// TestAnUnchangedReadIsHeldToAFloorAnotherReaderRaised: two readers share
// a floor. A's poller accepted P; B accepts P+X and raises the floor; the
// list is put back to P before A reads X. A's next read, whose accepted part
// did not change, is held to the floor as stored and refused as a broken
// chain rather than served Clear.
func TestAnUnchangedReadIsHeldToAFloorAnotherReaderRaised(t *testing.T) {
	c := newChain(t)
	stops := filepath.Join(c.base, "stops")
	r := c.routeFor(t, c.plane.RouteFile, stops, reaction.VerifySignedRoute)
	a, err := stoplist.Open(stoplist.Options{Dir: stops, Route: r, Interval: time.Second, Clock: func() time.Time { return now },
		Owner: stoplist.AnyOwner, Take: func(l reaction.List, content []byte) error {
			_, err := c.floor.Take(t.Context(), l, content)
			return err
		}})
	if err != nil {
		t.Fatalf("A's poller: %v", err)
	}
	if s := a.Poll(); s.State() != reaction.Clear {
		t.Fatalf("A's read of P: %v %q %s", s.State(), s.Cause(), s.Detail())
	}
	raised := c.appendStop(t, "f1", "run-1")
	if _, err := c.take(t, raised); err != nil {
		t.Fatalf("B's raise to P+X: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stops, stoplist.FileName), c.first.raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s := a.Poll()
	if s.State() != reaction.Unknown || s.Cause() != stoplist.CauseChain {
		t.Errorf("A's read of P put back over a floor at P+X: %v %q %s, want unknown with %q", s.State(), s.Cause(), s.Detail(), stoplist.CauseChain)
	}
	c.expectFloor(t, "after A's read", 1, raised)
}

// TestATakeOfTheListTheFloorHoldsTakesNoLock: while another file holds the
// floor's lock, a Take of the list the floor stands at is held to it at
// once, and a Take that would raise it waits until its context ends.
func TestATakeOfTheListTheFloorHoldsTakesNoLock(t *testing.T) {
	c := newChain(t)
	if _, err := c.take(t, c.first); err != nil {
		t.Fatal(err)
	}
	grown := c.appendStop(t, "f1", "run-1")
	held, err := os.Open(c.floorDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.floor.Take(ctx, c.first.l, c.first.raw); err != nil {
		t.Errorf("a Take of the list the floor holds, under another file's lock: %v", err)
	}
	other := append(bytes.Clone(c.first.raw[:len(c.first.raw)-2]), 'X', '\n')
	if _, err := c.floor.Take(ctx, c.first.l, other); !errors.Is(err, stoplist.ErrChain) {
		t.Errorf("a Take of the list the floor holds with other bytes: %v, want %v", err, stoplist.ErrChain)
	}
	if _, err := c.floor.Take(ctx, grown.l, grown.raw); !errors.Is(err, stoplist.ErrFloor) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a Take that raises, under another file's lock: %v, want the context's deadline", err)
	}
}

// TestPortsAskedPastTheirContextAreUnavailable: the ports asked with a
// context that ended answer as unavailable, never as a refusal.
func TestPortsAskedPastTheirContextAreUnavailable(t *testing.T) {
	f := newFixture(t)
	v, err := signedstops.NewPorts(f.authn, f.authz, f.plane)
	if err != nil {
		t.Fatal(err)
	}
	env := statement(t, reaction.SignedHeaderPayloadType, "alice", "alice")
	if _, err := v.VouchContext(t.Context(), reaction.VouchHeader, env); err != nil {
		t.Fatalf("the ports asked in time: %v", err)
	}
	ended, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = v.VouchContext(ended, reaction.VouchHeader, env)
	if !signedstops.IsUnavailable(err) || !errors.Is(err, reaction.ErrUnanswered) || errors.Is(err, signedstops.ErrUnauthenticated) {
		t.Fatalf("the ports asked past their context: %v", err)
	}
}
