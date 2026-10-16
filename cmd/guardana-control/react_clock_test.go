package main

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// TestEachStopIsTimedWhenItIsWritten: the clock moves past a rule's
// lifetime once the pass starts writing its first stop, so the second stop is
// created and expires by the later reading and is active when written, never
// a stop that had expired before it reached the list.
func TestEachStopIsTimedWhenItIsWritten(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	later := now.Add(11 * time.Minute)
	reading := now
	beforeStopsLock = func() { reading = later }
	t.Cleanup(func() { beforeStopsLock = func() {} })
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed), finding(2, tr.second, denial, confirmed))
	var out, errOut bytes.Buffer
	code := react(context.Background(), tr.reactArgs(log), func() time.Time { return reading }, &out, &errOut)
	reacted(t, code, out.String(), errOut.String(),
		"stop line 2 run "+tr.open+" finding "+fid(1)+" rule REPEATED_DENIAL expires_at "+lineTime(now.Add(600*time.Second)),
		"stop line 3 run "+tr.second+" finding "+fid(2)+" rule REPEATED_DENIAL expires_at "+lineTime(later.Add(600*time.Second)),
		"stops 2, covered 0, already named 0, not stopping 0, not written 0")
	entries := tr.judged(t, later).Entries()
	if len(entries) != 2 || !entries[0].CreatedAt.Equal(now) || !entries[1].CreatedAt.Equal(later) || !activeAt(entries[1], later) {
		t.Fatalf("entries %+v, want the second created at %s and active then", entries, later)
	}
}
