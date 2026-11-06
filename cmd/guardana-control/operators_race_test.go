package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/trust"
)

// signerRun is one roster sign's exit status and output.
type signerRun struct {
	status         int
	stdout, stderr bytes.Buffer
}

// TestTwoSignersOfOneSerialWriteOnce: two signers of one roster id at serial
// 2, over the roster at serial 1, both pass the check made before the lock.
// The second, started while the first holds the output directory's lock,
// finds it held and waits until the first wrote, and then finds serial 2 at
// --out and refuses, so --out holds the first's roster and no fork exists.
func TestTwoSignersOfOneSerialWriteOnce(t *testing.T) {
	tr := newRosterTree(t)
	now := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	writeFixture(t, tr.source, strings.Replace(rosterSource(seeded(0x61).Public().(ed25519.PublicKey)), `"serial":3`, `"serial":1`, 1))
	if code, _, stderr := rosterSignAt(t, tr, trust.DefaultLifetime, now); code != exitOK {
		t.Fatalf("signing serial 1 answered %d: %q", code, stderr)
	}
	first, second := filepath.Join(tr.dir, "first.json"), filepath.Join(tr.dir, "second.json")
	writeFixture(t, first, strings.Replace(rosterSource(seeded(0x61).Public().(ed25519.PublicKey)), `"serial":3`, `"serial":2`, 1))
	writeFixture(t, second, strings.Replace(rosterSource(seeded(0x62).Public().(ed25519.PublicKey)), `"serial":3`, `"serial":2`, 1))

	a, b, held := signDuringSign(t, tr, first, second, now.Add(time.Minute))
	if !held {
		t.Error("the second signer never found the output directory's lock held")
	}
	if a.status != exitOK || a.stderr.Len() != 0 {
		t.Errorf("the first signer: exit %d, stderr %q", a.status, a.stderr.String())
	}
	want := "it holds roster roster-a at serial 2, and each signing needs a higher serial than that, not 2"
	if b.status != exitFail || b.stdout.Len() != 0 || !strings.Contains(b.stderr.String(), want) {
		t.Errorf("the second signer: exit %d, stdout %q, stderr %q; want a refusal holding %q", b.status, b.stdout.String(), b.stderr.String(), want)
	}
	sum := sha256.Sum256(payloadAt(t, tr.out))
	if digest := "digest: sha256:" + hex.EncodeToString(sum[:]) + "\n"; !strings.Contains(a.stdout.String(), digest) {
		t.Errorf("--out holds %s; the first signer printed %q", digest, a.stdout.String())
	}
}

// signDuringSign signs firstSource and, from inside that signing once it
// holds the lock, starts a signing of secondSource. held reports whether the
// second found the lock held before it finished.
func signDuringSign(t *testing.T, tr rosterTree, firstSource, secondSource string, now time.Time) (a, b *signerRun, held bool) {
	t.Helper()
	a, b = &signerRun{}, &signerRun{}
	v := rosterSignValues{key: tr.key, out: tr.out, validFor: trust.DefaultLifetime}
	secondDone, contended := make(chan struct{}), make(chan struct{}, 1)
	started := false
	lockContended = func() {
		select {
		case contended <- struct{}{}:
		default:
		}
	}
	afterRosterLock = func() {
		started = true
		afterRosterLock = func() {}
		go func() {
			b.status = rosterSign(v, secondSource, now, &b.stdout, &b.stderr)
			close(secondDone)
		}()
		select {
		case <-contended:
			held = true
		case <-secondDone:
		case <-time.After(rosterLockWait):
		}
	}
	defer func() { afterRosterLock, lockContended = func() {}, func() {} }()
	a.status = rosterSign(v, firstSource, now, &a.stdout, &a.stderr)
	if !started {
		t.Fatalf("the first signer never took the lock: exit %d, stderr %q", a.status, a.stderr.String())
	}
	select {
	case <-secondDone:
	case <-time.After(2 * rosterLockWait):
		t.Fatal("the second signer never finished")
	}
	return a, b, held
}

// payloadAt is the payload of the roster envelope at path.
func payloadAt(t *testing.T, path string) []byte {
	t.Helper()
	env, err := trust.ParseFile([]byte(readFile(t, path)))
	if err != nil {
		t.Fatalf("%s holds no roster envelope: %v", path, err)
	}
	return env.Payload
}

// TestFloorInitTakesOnlyARosterIDThePortTakes: an id the trust port refuses
// at start gets no floor, and one it takes does, so a floor is never made for
// a roster no plane can load.
func TestFloorInitTakesOnlyARosterIDThePortTakes(t *testing.T) {
	for _, c := range []struct {
		id    string
		takes bool
	}{
		{"roster-a", true},
		{"r", true},
		{strings.Repeat("r", trust.MaxRosterIDBytes), true},
		{"Roster-A", false},
		{"roster_a.2", true},
		{"-roster", false},
		{"roster@a", false},
		{strings.Repeat("r", trust.MaxRosterIDBytes+1), false},
	} {
		dir := filepath.Join(t.TempDir(), "floor")
		code, _, stderr := invoke(t, "operators", "floor", "init", "--roster-id", c.id, dir)
		_, readErr := policystate.ReadAuthority(dir, c.id)
		switch {
		case c.takes && (code != exitOK || readErr != nil):
			t.Errorf("%q: floor init answered %d %q, the floor reads %v; want a floor", c.id, code, stderr, readErr)
		case !c.takes && (code != exitFail || !strings.Contains(stderr, "not a roster id a roster may carry") || readErr == nil):
			t.Errorf("%q: floor init answered %d %q, the floor reads %v; want a refusal and no floor", c.id, code, stderr, readErr)
		}
	}
}

// TestARosterChangedSinceItWasReadIsNotReplaced: a roster of another root
// put at --out after roster sign first read it, here once it holds the lock,
// as a writer that skips the lock could, passes the serial check, which reads
// only this root's rosters; it is refused all the same, and --out keeps it.
func TestARosterChangedSinceItWasReadIsNotReplaced(t *testing.T) {
	tr := newRosterTree(t)
	now := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	if code, _, stderr := rosterSignAt(t, tr, trust.DefaultLifetime, now); code != exitOK {
		t.Fatalf("the first signing answered %d: %q", code, stderr)
	}
	other, _, err := trust.SignDocument([]byte(rosterSource(seeded(0x61).Public().(ed25519.PublicKey))), now, trust.DefaultLifetime, seeded(0x73))
	if err != nil {
		t.Fatal(err)
	}
	planted, err := trust.MarshalFile(other)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, tr.source, strings.Replace(rosterSource(seeded(0x61).Public().(ed25519.PublicKey)), `"serial":3`, `"serial":4`, 1))
	afterRosterLock = func() { writeFixture(t, tr.out, string(planted)) }
	defer func() { afterRosterLock = func() {} }()
	code, stdout, stderr := rosterSignAt(t, tr, trust.DefaultLifetime, now.Add(time.Minute))
	if code != exitFail || stdout != "" || !strings.Contains(stderr, "changed since roster sign first read it") {
		t.Errorf("exit %d, stdout %q, stderr %q; want the changed file refused", code, stdout, stderr)
	}
	if got := readFile(t, tr.out); got != string(planted) {
		t.Error("--out was replaced after it changed under the signer")
	}
}
