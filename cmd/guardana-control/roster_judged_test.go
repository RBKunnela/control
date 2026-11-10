package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/findinglog"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/trust"
)

// judgedSerial is the serial resignRoster gives a fixture's roster, apart
// from every serial a fixture writes.
const judgedSerial = 41

// resignRoster signs the roster at path again with root at judgedSerial,
// expiring within the hour, keeping its id and keys, and returns the words a
// command that judges with it says on standard error.
func resignRoster(t *testing.T, path string, root ed25519.PrivateKey) string {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	env, err := trust.ParseFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(env.Payload, &doc); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(53 * time.Minute).Truncate(time.Second)
	doc["serial"] = judgedSerial
	doc["issuedAt"] = expires.Add(-2 * time.Hour).Format(time.RFC3339)
	doc["expiresAt"] = expires.Format(time.RFC3339)
	body, err := canon.Canonicalize(doc)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(trust.PayloadType, body, root)
	if err != nil {
		t.Fatal(err)
	}
	out, err := trust.MarshalFile(trust.Envelope{PayloadType: trust.PayloadType, Payload: body,
		Signatures: []trust.Signature{{KeyID: policykey.KeyID(root.Public().(ed25519.PublicKey)), Signature: sig}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return "judged with roster roster-a serial 41, expires " + expires.Format(time.RFC3339)
}

// judgedOnce reports whether stderr says command's judged line exactly once,
// on a line of its own before the first line holding after, or anywhere when
// after is empty.
func judgedOnce(stderr, command, judged, after string) bool {
	want := ": " + command + ": " + judged + "\n"
	at := strings.Index(stderr, want)
	if at < 0 || strings.Count(stderr, judged) != 1 {
		return false
	}
	return after == "" || (strings.Contains(stderr, after) && at < strings.Index(stderr, after))
}

// afterJudged requires stderr's first line to hold judged and returns the
// one line after it.
func afterJudged(t *testing.T, stderr, judged string) string {
	t.Helper()
	first, rest, _ := strings.Cut(stderr, "\n")
	if !strings.Contains(first, judged) {
		t.Errorf("stderr begins %q, want %q", first, judged)
	}
	return oneStderrLine(t, rest)
}

// TestPauseWritesSayWhichRosterTheyJudgedWith: a signed pause add and remove
// each say on stderr, once and before what they signed, the roster's id,
// serial and expiry as the document states them.
func TestPauseWritesSayWhichRosterTheyJudgedWith(t *testing.T) {
	keyFile, pub, _ := operatorKey(t)
	judge := rosterOf(t, pub)
	judged := resignRoster(t, judge[1], seeded(0x7e))
	path := signedInitialized(t, keyFile)
	code, id, stderr := invokeSigned(t, []string{"add", "--global"}, keyFile, judge, path)
	if code != exitOK || !judgedOnce(stderr, pauseAddName, judged, "signed serial 8") {
		t.Fatalf("pause add --key answered %d: %q; want %q before what it signed", code, stderr, judged)
	}
	code, _, stderr = invokeSigned(t, []string{"remove"}, keyFile, judge, path, strings.TrimSpace(id))
	if code != exitOK || !judgedOnce(stderr, pauseRemoveName, judged, "signed serial 9") {
		t.Fatalf("pause remove --key answered %d: %q; want %q before what it signed", code, stderr, judged)
	}
}

// TestSignedRunsWritesSayWhichRosterTheyJudgedWith: runs open and runs close
// with --key each say the roster's line once, before what they signed; an
// open whose roster does not read writes nothing, the signed layout
// included.
func TestSignedRunsWritesSayWhichRosterTheyJudgedWith(t *testing.T) {
	s := newSignedRuns(t)
	judged := resignRoster(t, s.roster, seeded(0x72))
	code, stdout, stderr := invoke(t, openArgs(s.dir, tenantP1, "1h", s.flags()...)...)
	if code != exitOK || !judgedOnce(stderr, runsOpenName, judged, "runs open: signed run ") {
		t.Fatalf("runs open --key answered %d: %q; want %q before what it signed", code, stderr, judged)
	}
	id := fieldAfter(t, stdout, "run_id: ")
	code, _, stderr = invoke(t, s.closeArgs(s.dir, id)...)
	if code != exitOK || !judgedOnce(stderr, runsCloseName, judged, "runs close: signed run ") {
		t.Fatalf("runs close --key answered %d: %q; want %q before what it signed", code, stderr, judged)
	}

	empty := runsDir(t)
	missing := filepath.Join(t.TempDir(), "no-roster.json")
	code, _, stderr = invoke(t, openArgs(empty, tenantP1, "1h", "--key", s.key, "--roster", missing, "--root-key", s.root)...)
	if code != exitFail || !strings.Contains(stderr, "--roster: ") || strings.Contains(stderr, "judged with roster") {
		t.Fatalf("runs open --key over a missing roster answered %d: %q", code, stderr)
	}
	if entries, err := os.ReadDir(empty); err != nil || len(entries) != 0 {
		t.Errorf("runs open --key over a missing roster left %v, %v in the directory; want nothing written", entries, err)
	}
}

// TestSignedStopsCommandsSayWhichRosterTheyJudgedWith: stops init, list and
// lift under a v1alpha2 route each say the roster's line once, init and lift
// before what they signed.
func TestSignedStopsCommandsSayWhichRosterTheyJudgedWith(t *testing.T) {
	tr := newSignedTree(t)
	judged := resignRoster(t, tr.judge[1], seeded(0x7e))
	code, _, stderr := tr.run(t, "stops init", "--key", tr.keys["alice"], tr.stops)
	if code != exitOK || !judgedOnce(stderr, stopsInitName, judged, "signed list header") {
		t.Fatalf("stops init --key answered %d: %q; want %q before what it signed", code, stderr, judged)
	}
	tr.appendRunStop(t)
	code, _, stderr = tr.run(t, "stops list", tr.stops)
	if code != exitOK || !judgedOnce(stderr, stopsListName, judged, "") {
		t.Fatalf("stops list answered %d: %q; want %q", code, stderr, judged)
	}
	code, _, stderr = tr.run(t, "stops lift", "--key", tr.keys["alice"], "--run", "run-1", tr.stops)
	if code != exitOK || !judgedOnce(stderr, stopsLiftName, judged, "signed lift of run run-1") {
		t.Fatalf("stops lift --key answered %d: %q; want %q before what it signed", code, stderr, judged)
	}
}

// TestSuperviseSaysWhichRosterItJudgedARunWith: supervise reading a signed
// layout under the four flags says the roster's line once.
func TestSuperviseSaysWhichRosterItJudgedARunWith(t *testing.T) {
	l := newJudgedLayout(t)
	judged := resignRoster(t, l.s.roster, seeded(0x72))
	tr := newSupTree(t)
	_, _, stderr := invoke(t, "supervise", "--procedure", tr.procedure, "--runs", l.s.dir, "--run", l.taken,
		"--findings", tr.findings, "--roster", l.s.roster, "--root-key", l.s.root, "--tenant", "t1", "--project", "p1")
	first, _, _ := strings.Cut(stderr, "\n")
	if !judgedOnce(stderr, superviseName, judged, "") || !strings.Contains(first, judged) {
		t.Fatalf("supervise of a signed layout said %q; want %q first", stderr, judged)
	}
}

// TestReactUnderASignedRouteSaysWhichRosterItJudgedWith: past its guard
// against the plane's account, which every directory trips on one account,
// react under a v1alpha2 route says the roster's line once, first.
func TestReactUnderASignedRouteSaysWhichRosterItJudgedWith(t *testing.T) {
	saved := reactPlaneAccount
	reactPlaneAccount = func(string) error { return nil }
	t.Cleanup(func() { reactPlaneAccount = saved })
	tr := newSignedTree(t)
	judged := resignRoster(t, tr.judge[1], seeded(0x7e))
	if code, _, stderr := tr.run(t, "stops init", "--key", tr.keys["alice"], tr.stops); code != exitOK {
		t.Fatalf("stops init: %d, %q", code, stderr)
	}
	findings := ownerDir(t, filepath.Join(tr.dir, "findings"))
	if err := os.WriteFile(filepath.Join(findings, findinglog.FileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runsAt := runsDir(t)
	openRun(t, runsAt, who, "1h")
	code, stdout, stderr := invoke(t, "react", "--findings", findings, "--runs", runsAt, "--route", tr.route,
		"--roster", tr.judge[1], "--root-key", tr.judge[3], "--approvals", filepath.Join(tr.dir, "approvals"), "--stops", tr.stops)
	first, _, _ := strings.Cut(stderr, "\n")
	if code != exitOK || !strings.Contains(stdout, "stops 0, covered 0") || !judgedOnce(stderr, reactName, judged, "") ||
		!strings.Contains(first, judged) {
		t.Fatalf("react under a signed route answered %d: %q %q; want %q first", code, stdout, stderr, judged)
	}
}
