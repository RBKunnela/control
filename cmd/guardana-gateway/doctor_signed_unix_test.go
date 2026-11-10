//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/trust"
)

// doctorRun runs doctor over tr and returns its status, what it printed and
// the one line of stdout that starts with prefix, or "" where none does.
func doctorRun(t *testing.T, tr tree, prefix string) (int, string, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	status := doctor(context.Background(), tr.config, &stdout, &stderr)
	line := ""
	for _, l := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(l, prefix) {
			line = l
		}
	}
	return status, stdout.String(), stderr.String(), line
}

// TestDoctorFailsARosterThePlanesAccountMayWrite: doctor makes the signed
// start's checks, so a roster file the plane's account may write fails its
// trust check, naming trust.roster, and stops the run there; placed apart,
// the same tree passes it and names the roster it read.
func TestDoctorFailsARosterThePlanesAccountMayWrite(t *testing.T) {
	tr := signedPlaneTree(t, "roster-a", []ed25519.PublicKey{signedTestPublic("alice")}, "roster-a")
	judgedWith(t, filepath.Join(tr.dir, "trust", "roster.json"), func(string) error { return errPlaneWritesForTest })
	status, out, stderr, line := doctorRun(t, tr, "fail    trust ")
	if status != exitFail || !strings.Contains(line, "trust.roster: under the signed authority the plane's own account may not be able to change it") {
		t.Fatalf("doctor over a plane-writable roster = %d, trust line %q:\n%s", status, line, out)
	}
	if !strings.HasPrefix(stderr, "doctor: trust: trust.roster: ") || !strings.HasSuffix(out, line+"\n") {
		t.Errorf("doctor did not stop at the trust check: stderr %q:\n%s", stderr, out)
	}
	judgedWith(t, tr.dir, func(string) error { return nil })
	if _, out, _, line := doctorRun(t, tr, "ok      trust "); !strings.Contains(line, "roster roster-a serial 1 names 1 key(s)") {
		t.Errorf("doctor over a roster placed apart: trust line %q:\n%s", line, out)
	}
}

// TestDoctorReadsASignedStopListAsThePlaneJudgesIt: over alice's list under
// dave's route, doctor's reaction check passes, naming both signers, and the
// run fails only later, at the upstream nobody serves; once the roster names
// dave alone, alice's list is one it does not vouch for, and the reaction
// check fails and stops the run there.
func TestDoctorReadsASignedStopListAsThePlaneJudgesIt(t *testing.T) {
	placedApart(t)
	doctorPlaneOwned = true
	t.Cleanup(func() { doctorPlaneOwned = false })

	tr := signedStopsTree(t)
	status, out, stderr, line := doctorRun(t, tr, "ok      reaction ")
	for _, want := range []string{
		"; 0 active stop(s); ",
		"; route signed by dave (key " + policykey.KeyID(signedTestPublic("dave")) + "), list header serial 1 signed by alice (key " +
			policykey.KeyID(signedTestPublic("alice")) + ")",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("doctor's reaction line over alice's list does not say %q: %q\n%s", want, line, out)
		}
	}
	if status != exitFail || !strings.HasPrefix(stderr, "doctor: upstreams: ") {
		t.Errorf("doctor over alice's list = %d, stderr %q; want it to fail at the unserved upstream alone", status, stderr)
	}

	forged := signedStopsTree(t)
	writeAdminOnlyRoster(t, filepath.Join(forged.dir, "trust", "roster.json"))
	status, out, stderr, line = doctorRun(t, forged, "fail    reaction ")
	if status != exitFail || line == "" || !strings.HasPrefix(stderr, "doctor: reaction: ") || !strings.HasSuffix(out, line+"\n") ||
		!strings.Contains(line, "reaction.stops: stoplist: the stop list cannot be served: a header that does not verify") ||
		!strings.Contains(line, "no operator key of the roster signed the document for its act") {
		t.Fatalf("doctor over alice's list under a roster naming dave alone = %d, reaction line %q, stderr %q:\n%s", status, line, stderr, out)
	}
}

// writeAdminOnlyRoster writes a roster of roster-a at serial 1 that names
// dave as admin and no one else.
func writeAdminOnlyRoster(t *testing.T, path string) {
	t.Helper()
	k := signedTestPublic("dave")
	now := time.Now().UTC().Truncate(time.Second)
	body, err := canon.Canonicalize(map[string]any{
		"kind": trust.DocumentKind, "rosterId": "roster-a", "serial": 1,
		"issuedAt": now.Add(-time.Hour).Format(time.RFC3339), "expiresAt": now.Add(time.Hour).Format(time.RFC3339),
		"keys": []any{map[string]any{
			"keyId": policykey.KeyID(k), "alg": "ed25519", "role": "operator", "subject": "dave",
			"publicKey": policykey.FormatPublic(k), "grants": []any{map[string]any{"tenant": "acme", "project": "orders", "level": "admin"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(trust.PayloadType, body, signedTestKey("root"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := trust.MarshalFile(trust.Envelope{PayloadType: trust.PayloadType, Payload: body,
		Signatures: []trust.Signature{{KeyID: policykey.KeyID(signedTestPublic("root")), Signature: sig}}})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, raw)
}

// TestDoctorRefusesWhatThePlanesOwnAccountOwnsUnderSigned: off the one-account
// test switch, where this account is the plane's and owns every file, doctor
// fails at the runs check naming records/ the plane's account owns, its
// reaction check names the route that account owns, and the stop list read as
// doctor reads it is refused as that account's.
func TestDoctorRefusesWhatThePlanesOwnAccountOwnsUnderSigned(t *testing.T) {
	placedApart(t)
	tr := signedStopsTree(t)
	status, out, stderr, line := doctorRun(t, tr, "fail    runs ")
	if status != exitFail || !strings.HasPrefix(stderr, "doctor: runs: ") || !strings.Contains(line, runs.ErrPlaneOwned.Error()) {
		t.Fatalf("doctor on one account = %d, stderr %q:\n%s", status, stderr, out)
	}
	d := &examination{cfg: tr.load(t)}
	if verdict, _, found := d.reaction(t.Context()); verdict != verdictFail || !strings.Contains(found, "reaction.route: ") ||
		!strings.Contains(found, errPlaneOwnedRoute.Error()) {
		t.Errorf("doctor's reaction check on one account = %s, %q; want the route the plane's account owns", verdict, found)
	}
	doc := writeLeveledRoster(t, filepath.Join(tr.dir, "trust", "roster.json"))
	route := rosterRouteOf(t, doc, filepath.Join(tr.dir, "route.json"), filepath.Join(tr.dir, "stops"))
	if _, err := openStopList(d.cfg, route, nil, d.signedListRead()); !errors.Is(err, stoplist.ErrNotServable) ||
		!strings.Contains(err.Error(), string(stoplist.CausePlaneOwned)) {
		t.Errorf("the stop list read as doctor reads it on one account = %v; want it refused as the plane's own", err)
	}
}
