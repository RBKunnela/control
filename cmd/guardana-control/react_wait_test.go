package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
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
	var looked []string
	r, records := readyReactor(ctx, t, tr, log, now, func(plane lookupRun) lookupRun {
		return func(ctx context.Context, id string) (runs.Record, error) {
			looked = append(looked, id)
			rec, err := plane(ctx, id)
			cancel()
			return rec, err
		}
	})
	err := r.each(records)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "stopped before finding "+fid(2)) {
		t.Fatalf("each = %v, want it stopped before %s", err, fid(2))
	}
	if r.stops != 1 || len(r.written) != 1 || len(looked) == 0 || slices.ContainsFunc(looked, func(id string) bool { return id != tr.open }) {
		t.Errorf("%d stops, written %q, runs looked up %q; want the first finding's stop alone", r.stops, r.written, looked)
	}
	if l := tr.judged(t, now); !l.Names(fid(1)) || l.Names(fid(2)) {
		t.Errorf("the list names %s: %v, %s: %v; want the first alone", fid(1), l.Names(fid(1)), fid(2), l.Names(fid(2)))
	}
}

// TestARunThatCannotBeReadUnderTheLockStopsThePass: the runs directory
// answers the lookup before the lock and fails the one under it. The pass
// stops on that failure, naming it, and writes nothing, as it does for a
// lookup that fails before the lock; it is not a refusal of one finding.
func TestARunThatCannotBeReadUnderTheLockStopsThePass(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed), finding(2, tr.second, denial, confirmed))
	broken := errors.New("the runs directory could not be read")
	lookups := 0
	r, records := readyReactor(context.Background(), t, tr, log, now, func(plane lookupRun) lookupRun {
		return func(ctx context.Context, id string) (runs.Record, error) {
			if lookups++; lookups == 2 {
				return runs.Record{}, broken
			}
			return plane(ctx, id)
		}
	})
	before := tr.listBytes(t)
	err := r.each(records)
	if !errors.Is(err, broken) {
		t.Fatalf("each = %v, want the pass stopped on the lookup under the lock", err)
	}
	if r.stops != 0 || len(r.written) != 0 || len(r.unwritten) != 0 || lookups != 2 {
		t.Errorf("%d stops, written %q, unwritten %q, %d lookups; want the pass stopped at the first finding", r.stops, r.written, r.unwritten, lookups)
	}
	if !bytes.Equal(tr.listBytes(t), before) {
		t.Error("a pass stopped on a lookup changed the list")
	}
}
