package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"github.com/guardana/control/internal/findinglog"
	"github.com/guardana/control/internal/runs"
)

// TestAPassSpendsNoLockWaitOutsideALock: with no wait for a lock at all, a
// pass over two runs no other writer touches still looks both up and writes
// both stops. The wait bounds taking the lock; the lookups and the reading and
// judging of the list between writes never spend it.
func TestAPassSpendsNoLockWaitOutsideALock(t *testing.T) {
	tr := newStopTree(t)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed), finding(2, tr.second, denial, confirmed))
	a := tr.reactArgs(log)
	a.lockWait = 0
	var out, errOut bytes.Buffer
	code := react(context.Background(), a, time.Now, &out, &errOut)
	if code != exitOK || !strings.HasSuffix(out.String(), "\nstops 2, covered 0, already named 0, not stopping 0, not written 0\n") {
		t.Fatalf("react answered %d: %q\n%s", code, errOut.String(), out.String())
	}
}

// readyReactor is a reactor over the log in findings, looking runs up
// through lookup, which is handed the plane's own lookup.
func readyReactor(ctx context.Context, t *testing.T, tr stopTree, findings string, now time.Time,
	lookup func(plane lookupRun) lookupRun) (*reactor, []*findingv1alpha1.Record) {
	t.Helper()
	records, err := findinglog.ReadFile(filepath.Join(findings, findinglog.FileName))
	if err != nil {
		t.Fatal(err)
	}
	plane, err := runs.OpenPlane(tr.runs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plane.Close() })
	return newReactor(ctx, tr.parsed, tr.judged(t, now), lookup(plane.Lookup), tr.stops, clockAt(now)), records
}

// TestAnInterruptedPassStopsAfterTheLinesItWrote: a pass whose context ends
// after its first finding's lookup still writes that finding's stop, takes no
// further finding, and names the one it stopped before.
func TestAnInterruptedPassStopsAfterTheLinesItWrote(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed), finding(2, tr.second, denial, confirmed))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lookups := 0
	r, records := readyReactor(ctx, t, tr, log, now, func(plane lookupRun) lookupRun {
		return func(ctx context.Context, id string) (runs.Record, error) {
			lookups++
			rec, err := plane(ctx, id)
			cancel()
			return rec, err
		}
	})
	err := r.each(records)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "stopped before finding "+fid(2)) {
		t.Fatalf("each = %v, want it stopped before %s", err, fid(2))
	}
	if r.stops != 1 || len(r.written) != 1 || lookups != 1 {
		t.Errorf("%d stops, written %q, %d lookups; want the first finding's stop alone", r.stops, r.written, lookups)
	}
	if l := tr.judged(t, now); !l.Names(fid(1)) || l.Names(fid(2)) {
		t.Errorf("the list names %s: %v, %s: %v; want the first alone", fid(1), l.Names(fid(1)), fid(2), l.Names(fid(2)))
	}
}
