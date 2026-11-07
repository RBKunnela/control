//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package signedstops_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// appendStop appends a stop of runID under findingID to the list in the
// stops directory and returns the list as judged after it.
func (c chainFixture) appendStop(t *testing.T, findingID, runID string) listAt {
	t.Helper()
	stops := filepath.Join(c.base, "stops")
	r := c.routeFor(t, c.plane.RouteFile, stops, reaction.VerifySignedRoute)
	_, _, _, err := stopwrite.AppendFinding(t.Context(), stops, r, func() time.Time { return now }, func(at time.Time) (reaction.Stop, error) {
		return reaction.Stop{EntryID: reaction.EntryID(findingID), TenantID: "t1", ProjectID: "A", Scope: reaction.ScopeRun, RunID: runID,
			FindingID: findingID, ProcedureID: "refund", ProcedureVersion: "3",
			ProcedureDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			RuleID:          "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1", CreatedAt: at, ExpiresAt: at.Add(time.Hour)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return mustJudge(t, stops, r)
}

// onFirstWait is a context that runs wait, once, the first time a lock
// wait asks for its Done channel: after the reader read the floor, before it
// holds the lock.
type onFirstWait struct {
	context.Context
	once sync.Once
	wait func()
}

func (c *onFirstWait) Done() <-chan struct{} {
	c.once.Do(c.wait)
	return c.Context.Done()
}

// TestAStaleReaderCannotReplaceAPartAnotherReaderRaised: two readers share
// a floor at P. One reads P and judges a longer list beginning with P but
// not with P+X; the other raises the floor to P+X while the first waits for
// the floor's lock. The first raise is then refused against the floor as
// stored under the lock, and the floor keeps P+X.
func TestAStaleReaderCannotReplaceAPartAnotherReaderRaised(t *testing.T) {
	c := newChain(t)
	if _, err := c.take(t, c.first); err != nil {
		t.Fatal(err)
	}
	stopsFile := filepath.Join(c.base, "stops", stoplist.FileName)
	divergent := c.appendStop(t, "finding-of-the-stale-reader", "run-of-the-stale-reader")
	if err := os.WriteFile(stopsFile, c.first.raw, 0o600); err != nil {
		t.Fatal(err)
	}
	raised := c.appendStop(t, "f1", "run-1")
	p := len(c.first.raw)
	if len(divergent.raw) <= len(raised.raw) || !bytes.Equal(divergent.raw[:p], c.first.raw) ||
		bytes.Equal(divergent.raw[:len(raised.raw)], raised.raw) {
		t.Fatalf("the lists are not P+X (%d bytes) and a longer P+Y (%d bytes)", len(raised.raw), len(divergent.raw))
	}

	held, err := os.Open(c.floorDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	ran := false
	ctx := &onFirstWait{Context: t.Context(), wait: func() {
		ran = true
		if err := syscall.Flock(int(held.Fd()), syscall.LOCK_UN); err != nil {
			t.Error(err)
			return
		}
		if _, err := c.take(t, raised); err != nil {
			t.Errorf("the other reader's raise to P+X: %v", err)
		}
	}}
	_, err = c.floor.Take(ctx, divergent.l, divergent.raw)
	if !ran {
		t.Fatalf("the stale reader never waited for the floor's lock: %v", err)
	}
	if !errors.Is(err, stoplist.ErrChain) {
		t.Errorf("the stale reader's raise of P+Y over P+X: %v, want %v", err, stoplist.ErrChain)
	}
	c.expectFloor(t, "after the stale reader's raise", 1, raised)
}
