package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/trust"
)

// renameOver puts body at path by a rename, as another writer's replace
// does, so the file at path is no longer the one a command judged.
func renameOver(t *testing.T, path, body string) {
	t.Helper()
	tmp := path + ".other"
	writeFixture(t, tmp, body)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// meddleBeforeReplace sets beforeOutReplaced to run meddle once, for the
// test's length.
func meddleBeforeReplace(t *testing.T, meddle func()) {
	t.Helper()
	beforeOutReplaced = func(string) {
		beforeOutReplaced = func(string) {}
		meddle()
	}
	t.Cleanup(func() { beforeOutReplaced = func(string) {} })
}

// TestACommandReplacesOnlyTheOutputItJudged: each command that replaces an
// earlier output of its own kind finds, once it judged --out, an unrelated
// file renamed over it; the command fails and the file keeps its bytes. The
// control is each command over the output it judged.
func TestACommandReplacesOnlyTheOutputItJudged(t *testing.T) {
	const unrelated = "an unrelated file\n"
	for name, setup := range outWriters {
		t.Run(name, func(t *testing.T) {
			out, run := setup(t)
			meddleBeforeReplace(t, func() { renameOver(t, out, unrelated) })
			code, stderr := run()
			if code != exitFail || !strings.Contains(stderr, "--out "+out) {
				t.Errorf("a run whose --out was replaced after it was judged: exit %d, stderr %q; want a refusal naming --out", code, stderr)
			}
			if got := readFile(t, out); got != unrelated {
				t.Errorf("--out was replaced after it was judged; it holds %q", got)
			}
			_, run = setup(t)
			if code, stderr := run(); code != exitOK {
				t.Errorf("the control, --out as it was judged: exit %d, stderr %q", code, stderr)
			}
		})
	}
}

// outWriters sets up each command that replaces an earlier output of its own
// kind at --out, and returns that path and a run of the command over it.
var outWriters = map[string]func(t *testing.T) (out string, run func() (int, string)){
	"policy sign": func(t *testing.T) (string, func() (int, string)) {
		tr := newSignTree(t)
		if code, _, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", tr.out, tr.doc); code != exitOK {
			t.Fatalf("the first sign: %d %q", code, stderr)
		}
		return tr.out, func() (int, string) {
			code, _, stderr := invoke(t, "policy", "sign", "--key", tr.key, "--out", tr.out, tr.doc)
			return code, stderr
		}
	},
	"route sign": func(t *testing.T) (string, func() (int, string)) {
		tr := newStopTree(t)
		doc := filepath.Join(tr.dir, "route.json")
		writeFixture(t, doc, routeDoc(seeded(0x4c), 2))
		return tr.route, func() (int, string) {
			code, _, stderr := invoke(t, signArgs(tr.routeKey, tr.route, doc)...)
			return code, stderr
		}
	},
	"roster sign": func(t *testing.T) (string, func() (int, string)) {
		tr := newRosterTree(t)
		now := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
		if code, _, stderr := rosterSignAt(t, tr, trust.DefaultLifetime, now); code != exitOK {
			t.Fatalf("the first signing: %d %q", code, stderr)
		}
		writeFixture(t, tr.source, strings.Replace(rosterSource(seeded(0x61).Public().(ed25519.PublicKey)), `"serial":3`, `"serial":4`, 1))
		return tr.out, func() (int, string) {
			code, _, stderr := rosterSignAt(t, tr, trust.DefaultLifetime, now.Add(time.Minute))
			return code, stderr
		}
	},
	"policy renew": func(t *testing.T) (string, func() (int, string)) {
		r := newRenewTree(t)
		renewed(t, r, r.bundle, 3)
		return r.out, func() (int, string) {
			var stderr bytes.Buffer
			code := renew(r.paths(), time.Now().Add(time.Second), &bytes.Buffer{}, &stderr)
			return code, stderr.String()
		}
	},
}

// TestTwoRenewsOfOneOutUnderTwoFloorsKeepTheNewer: a renew whose check of
// --out passed finds that a renew under another signer floor directory
// wrote a newer statement there before its own write; that one is kept.
func TestTwoRenewsOfOneOutUnderTwoFloorsKeepTheNewer(t *testing.T) {
	start := time.Now().Truncate(time.Second).Add(-time.Minute)
	r := newRenewTree(t)
	other := r.paths()
	other.floor = filepath.Join(r.dir, "other-floors")
	if err := policystate.Init(context.Background(), other.floor, policystate.KindSigner, "orders-policy"); err != nil {
		t.Fatal(err)
	}
	other.bundle = filepath.Join(r.dir, "other.bundle")
	writeBundle(t, other.bundle, renewDocument(4, "allow-reads"), r.bundleSigner)
	meddleBeforeReplace(t, func() {
		var stderr bytes.Buffer
		if code := renew(other, start, &bytes.Buffer{}, &stderr); code != exitOK {
			t.Errorf("the renew under the other floor: exit %d, stderr %q", code, stderr.String())
		}
	})
	var stderr bytes.Buffer
	if code := renew(r.paths(), start, &bytes.Buffer{}, &stderr); code != exitFail {
		t.Errorf("the older renew: exit %d, stderr %q; want it refused", code, stderr.String())
	}
	if _, st := freshStatement(t, r.out); st.Serial() != 4 {
		t.Errorf("--out holds the statement for serial %d, want the newer, 4", st.Serial())
	}
}

// TestSuperviseViewReplacesOnlyThePageItJudged: a file renamed over the
// page after supervise judged it again is kept, and the run says --view.
func TestSuperviseViewReplacesOnlyThePageItJudged(t *testing.T) {
	tr := newSupTree(t)
	x := tr.export(t, tr.run, supBase, deviating()...)
	tr.closeRun(t, tr.run)
	page := filepath.Join(tr.dir, "page.html")
	if code, _, stderr := invoke(t, tr.args("--evidence", x, "--view", page)...); code != exitFail || stderr != "" {
		t.Fatalf("the first page: exit %d, stderr %q", code, stderr)
	}
	const notes = "<!DOCTYPE html>\n<p>my notes</p>\n"
	meddleBeforeReplace(t, func() { renameOver(t, page, notes) })
	findings := filepath.Join(tr.dir, "second-findings")
	if err := os.Mkdir(findings, 0o700); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := invoke(t, "supervise", "--procedure", tr.procedure, "--runs", tr.runs, "--run", tr.run,
		"--findings", findings, "--evidence", x, "--view", page)
	if code == exitOK || !strings.Contains(stderr, "--view "+page) {
		t.Errorf("a page replaced after it was judged: exit %d, stderr %q; want a failure naming --view", code, stderr)
	}
	if got := readFile(t, page); got != notes {
		t.Errorf("the file renamed over the page was replaced; it holds %q", got)
	}
}

// TestARenewWhoseOutAnOlderRenewWroteSinceKeepsTheNewer: the renew of the
// newer bundle judged --out, and a renew of the older one under another
// signer floor directory wrote there before the newer's write; the newer
// judges --out again and replaces the older statement.
func TestARenewWhoseOutAnOlderRenewWroteSinceKeepsTheNewer(t *testing.T) {
	start := time.Now().Truncate(time.Second).Add(-time.Minute)
	r := newRenewTree(t)
	newer := r.paths()
	newer.bundle = filepath.Join(r.dir, "newer.bundle")
	writeBundle(t, newer.bundle, renewDocument(4, "allow-reads"), r.bundleSigner)
	older := r.paths()
	older.floor = filepath.Join(r.dir, "other-floors")
	if err := policystate.Init(context.Background(), older.floor, policystate.KindSigner, "orders-policy"); err != nil {
		t.Fatal(err)
	}
	meddleBeforeReplace(t, func() {
		var stderr bytes.Buffer
		if code := renew(older, start, &bytes.Buffer{}, &stderr); code != exitOK {
			t.Errorf("the older renew under the other floor: exit %d, stderr %q", code, stderr.String())
		}
	})
	var stderr bytes.Buffer
	if code := renew(newer, start, &bytes.Buffer{}, &stderr); code != exitOK {
		t.Errorf("the newer renew: exit %d, stderr %q; want its statement written", code, stderr.String())
	}
	if _, st := freshStatement(t, r.out); st.Serial() != 4 {
		t.Errorf("--out holds the statement for serial %d, want the newer, 4", st.Serial())
	}
}

// TestARenewJudgesOutAgainABoundedNumberOfTimes: a renew whose --out an
// older statement replaces before every write gives up after three
// judgements and names --out, leaving the older statement there.
func TestARenewJudgesOutAgainABoundedNumberOfTimes(t *testing.T) {
	r := newRenewTree(t)
	renewed(t, r, r.bundle, 3)
	older := readFile(t, r.out)
	newer := r.paths()
	newer.bundle = filepath.Join(r.dir, "newer.bundle")
	writeBundle(t, newer.bundle, renewDocument(4, "allow-reads"), r.bundleSigner)
	judgements := 0
	beforeOutReplaced = func(string) {
		judgements++
		if judgements > 10 {
			return
		}
		tmp := r.out + ".older"
		if err := os.WriteFile(tmp, []byte(older), 0o644); err != nil { //nolint:gosec // G306: a statement is public, 0644 as renew writes it
			t.Fatal(err)
		}
		if err := os.Rename(tmp, r.out); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { beforeOutReplaced = func(string) {} })
	var stderr bytes.Buffer
	code := renew(newer, time.Now().Add(time.Second), &bytes.Buffer{}, &stderr)
	if code != exitFail || !strings.Contains(stderr.String(), "--out "+r.out) {
		t.Errorf("a renew whose --out was replaced before every write: exit %d, stderr %q; want a refusal naming --out", code, stderr.String())
	}
	if judgements != 3 {
		t.Errorf("--out was judged %d times, want 3", judgements)
	}
	if _, st := freshStatement(t, r.out); st.Serial() != 3 {
		t.Errorf("--out holds the statement for serial %d, want the older, 3, put there last", st.Serial())
	}
}
