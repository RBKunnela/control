package main

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// TestEachStopIsTimedWhenItIsWritten: the clock moves past a rule's
// lifetime once the pass has written its first stop, so the second stop is
// created and expires by the later reading and is active when written, never
// a stop that had expired before it reached the list.
func TestEachStopIsTimedWhenItIsWritten(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	later := now.Add(11 * time.Minute)
	reading := now
	waits := 0
	beforeStopsLock = func() {
		if waits++; waits == 2 {
			reading = later
		}
	}
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

// TestAStopIsTimedOnceTheLockIsHeld: another react writes a stop at a later
// reading while this pass waits for the lock, so this pass's stop is created
// at the reading taken under the lock, and the list it judges holds no line
// ahead of that reading.
func TestAStopIsTimedOnceTheLockIsHeld(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	later := now.Add(30 * time.Second)
	reading := now
	other := tr.findingsDir(t, "other", finding(2, tr.second, denial, confirmed))
	waited := false
	beforeStopsLock = func() {
		if waited {
			return
		}
		waited = true
		reading = later
		var out, errOut bytes.Buffer
		code := react(context.Background(), tr.reactArgs(other), clockAt(later), &out, &errOut)
		reacted(t, code, out.String(), errOut.String(),
			"stop line 2 run "+tr.second+" finding "+fid(2)+" rule REPEATED_DENIAL expires_at "+lineTime(later.Add(600*time.Second)),
			"stops 1, covered 0, already named 0, not stopping 0, not written 0")
	}
	t.Cleanup(func() { beforeStopsLock = func() {} })
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed))
	var out, errOut bytes.Buffer
	code := react(context.Background(), tr.reactArgs(log), func() time.Time { return reading }, &out, &errOut)
	reacted(t, code, out.String(), errOut.String(),
		"stop line 3 run "+tr.open+" finding "+fid(1)+" rule REPEATED_DENIAL expires_at "+lineTime(later.Add(600*time.Second)),
		"stops 1, covered 0, already named 0, not stopping 0, not written 0")
	if entries := tr.judged(t, later).Entries(); len(entries) != 2 || !entries[1].CreatedAt.Equal(later) {
		t.Fatalf("entries %+v, want this pass's stop created at %s", entries, later)
	}
}

// TestARunThatExpiresDuringTheWaitIsNotStopping: a finding eligible before
// the lock whose run has expired by the reading taken under it is counted as
// not stopping, and nothing is written for it.
func TestARunThatExpiresDuringTheWaitIsNotStopping(t *testing.T) {
	tr := newStopTree(t)
	now := time.Now().UTC().Truncate(time.Second)
	reading := now
	beforeStopsLock = func() { reading = now.Add(2 * time.Hour) }
	t.Cleanup(func() { beforeStopsLock = func() {} })
	before := tr.listBytes(t)
	log := tr.findingsDir(t, "log", finding(1, tr.open, denial, confirmed))
	var out, errOut bytes.Buffer
	code := react(context.Background(), tr.reactArgs(log), func() time.Time { return reading }, &out, &errOut)
	reacted(t, code, out.String(), errOut.String(), "stops 0, covered 0, already named 0, not stopping 1, not written 0")
	if !bytes.Equal(tr.listBytes(t), before) {
		t.Error("a finding that no longer stops changed the list")
	}
}
