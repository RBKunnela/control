//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/trust"
)

// TestASignerThatCannotTakeTheLockWritesNothing: while another holder keeps
// the output directory's lock past the wait, roster sign refuses, names the
// lock, prints nothing and leaves --out as it was; once the lock is free the
// same signing is taken.
func TestASignerThatCannotTakeTheLockWritesNothing(t *testing.T) {
	tr := newRosterTree(t)
	now := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	if code, _, stderr := rosterSignAt(t, tr, trust.DefaultLifetime, now); code != exitOK {
		t.Fatalf("the first signing answered %d: %q", code, stderr)
	}
	before := readFile(t, tr.out)
	writeFixture(t, tr.source, strings.Replace(rosterSource(seeded(0x61).Public().(ed25519.PublicKey)), `"serial":3`, `"serial":4`, 1))
	saved := rosterLockWait
	rosterLockWait = 50 * time.Millisecond
	defer func() { rosterLockWait = saved }()
	root, err := os.OpenRoot(tr.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	unlock, err := lockRoot(context.Background(), root)
	if err != nil {
		t.Fatalf("taking the lock: %v", err)
	}

	code, stdout, stderr := rosterSignAt(t, tr, trust.DefaultLifetime, now.Add(time.Hour))
	if want := "another signer kept the directory's lock past 50ms"; code != exitFail || stdout != "" || !strings.Contains(stderr, want) {
		t.Errorf("signing while the lock is held answered %d %q %q; want a refusal holding %q", code, stdout, stderr, want)
	}
	if readFile(t, tr.out) != before {
		t.Error("a signer that never held the lock changed --out")
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := rosterSignAt(t, tr, trust.DefaultLifetime, now.Add(time.Hour)); code != exitOK || !strings.Contains(stdout, "serial: 4\n") {
		t.Errorf("signing once the lock is free answered %d %q %q", code, stdout, stderr)
	}
}

// TestTheSerialIsCheckedInTheDirectoryWritten: --out names its directory
// through a link. Once the signer holds the lock on the directory the link
// named, that directory takes a roster at serial 2 and the link is pointed at
// another directory holding serial 1. The signer checks the directory it
// writes into, refuses its own serial 2 and leaves both directories as they
// were.
func TestTheSerialIsCheckedInTheDirectoryWritten(t *testing.T) {
	tr := newRosterTree(t)
	now := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	operator := seeded(0x61).Public().(ed25519.PublicKey)
	a, b, link := filepath.Join(tr.dir, "a"), filepath.Join(tr.dir, "b"), filepath.Join(tr.dir, "current")
	serial2 := filepath.Join(tr.dir, "serial2.signed")
	writeFixture(t, tr.source, strings.Replace(rosterSource(operator), `"serial":3`, `"serial":1`, 1))
	for _, dir := range []string{a, b} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		signRosterInto(t, tr, filepath.Join(dir, "roster.signed"), now)
	}
	writeFixture(t, tr.source, strings.Replace(rosterSource(operator), `"serial":3`, `"serial":2`, 1))
	signRosterInto(t, tr, serial2, now)
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	inB := readFile(t, filepath.Join(b, "roster.signed"))
	held := readFile(t, serial2)
	afterRosterLock = func() {
		afterRosterLock = func() {}
		writeFixture(t, filepath.Join(a, "roster.signed"), held)
		if err := os.Remove(link); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(b, link); err != nil {
			t.Error(err)
		}
	}
	defer func() { afterRosterLock = func() {} }()

	writeFixture(t, tr.source, strings.Replace(rosterSource(seeded(0x62).Public().(ed25519.PublicKey)), `"serial":3`, `"serial":2`, 1))
	tr.out = filepath.Join(link, "roster.signed")
	code, stdout, stderr := rosterSignAt(t, tr, trust.DefaultLifetime, now.Add(time.Minute))
	if want := "it holds roster roster-a at serial 2"; code != exitFail || stdout != "" || !strings.Contains(stderr, want) {
		t.Errorf("signing serial 2 into a directory holding serial 2 answered %d %q %q; want a refusal holding %q", code, stdout, stderr, want)
	}
	if readFile(t, filepath.Join(a, "roster.signed")) != held || readFile(t, filepath.Join(b, "roster.signed")) != inB {
		t.Error("a directory's roster changed")
	}
}

// signRosterInto signs tr's source into out at now.
func signRosterInto(t *testing.T, tr rosterTree, out string, now time.Time) {
	t.Helper()
	tr.out = out
	if code, _, stderr := rosterSignAt(t, tr, trust.DefaultLifetime, now); code != exitOK {
		t.Fatalf("signing into %s answered %d: %q", out, code, stderr)
	}
}
