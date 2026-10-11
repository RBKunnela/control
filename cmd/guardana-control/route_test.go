package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/supervise"
)

// routeDigestOf is "sha256:" and the hex SHA-256 of doc's RFC 8785 form,
// computed apart from the route reader.
func routeDigestOf(t *testing.T, doc string) string {
	t.Helper()
	form, err := canon.CanonicalizeJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(form)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func signArgs(key, out, doc string) []string {
	return []string{"route", "sign", "--key", key, "--out", out, doc}
}

func TestRouteSignSignsWhatAPlaneVerifies(t *testing.T) {
	tr := newStopTree(t)
	out := filepath.Join(tr.dir, "new.signed")
	for _, serial := range []int{3, 4} {
		doc := filepath.Join(tr.dir, "route.json")
		body := routeDoc(seeded(0x4c), serial)
		writeFixture(t, doc, body)
		code, stdout, stderr := invoke(t, signArgs(tr.routeKey, out, doc)...)
		sum := sha256.Sum256(seeded(0x52).Public().(ed25519.PublicKey))
		want := "route_id: refund-stops\nserial: " + strconv.Itoa(serial) + "\ndigest: " + routeDigestOf(t, body) +
			"\nkey_id: ed25519-" + hex.EncodeToString(sum[:8]) + "\nout: " + out + "\n"
		if code != exitOK || stderr != "" || stdout != want {
			t.Fatalf("route sign answered %d: %q\n%s\nwant\n%s", code, stderr, stdout, want)
		}
		raw, err := os.ReadFile(out) //nolint:gosec // G304: this test's own directory
		if err != nil {
			t.Fatal(err)
		}
		env, err := reaction.ParseRouteFile(raw)
		if err != nil {
			t.Fatal(err)
		}
		r, err := reaction.VerifyRoute(env, seeded(0x52).Public().(ed25519.PublicKey))
		if err != nil || r.Serial() != int64(serial) || r.Digest() != routeDigestOf(t, body) {
			t.Fatalf("the route written verifies as %d %s: %v", r.Serial(), r.Digest(), err)
		}
		if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o644 {
			t.Fatalf("the route is written with %v: %v", info.Mode(), err)
		}
	}
}

// TestRouteSignRefusesARuleThatMayNotStop: a rule id supervise does not
// have, another rule version, and each rule supervise has whose finding may
// not stop a run, are refused before the key is read, and nothing is written.
func TestRouteSignRefusesARuleThatMayNotStop(t *testing.T) {
	tr := newStopTree(t)
	const first, second = `"rule_id":"REPEATED_DENIAL"`, `"rule_id":"STEP_OUTSIDE_PROCEDURE"`
	refused := "may not stop a run"
	for _, c := range []struct{ from, to, want string }{
		{first, `"rule_id":"REPEATED_DENIALS"`, `rules[0]: rule_id "REPEATED_DENIALS" is no rule supervise has`},
		{first, `"rule_id":"NO_SUCH_RULE"`, `rules[0]: rule_id "NO_SUCH_RULE" is no rule supervise has`},
		{second + `,"rule_version":"1"`, second + `,"rule_version":"2"`, `rules[1]: rule_version "2" is not supervise's "1"`},
		{first + `,"rule_version":"2"`, first + `,"rule_version":"1"`, `rules[0]: rule_version "1" is not supervise's "2"`},
		{first + `,"rule_version":"2"`, first + `,"rule_version":"02"`, `rules[0]: rule_version "02" is not supervise's "2"`},
		{first + `,"rule_version":"2"`, first + `,"rule_version":"9"`, `rules[0]: rule_version "9" is not supervise's "2"`},
		{first + `,"rule_version":"2"`, `"rule_id":"REQUIRED_STEP_SKIPPED","rule_version":"1"`, "rules[0]: REQUIRED_STEP_SKIPPED: reaction: the route names a rule that " + refused},
		{first + `,"rule_version":"2"`, `"rule_id":"STEP_OUT_OF_ORDER","rule_version":"2"`, "rules[0]: STEP_OUT_OF_ORDER: reaction: the route names a rule that " + refused},
		{second + `,"rule_version":"1"`, `"rule_id":"CONTINUED_AFTER_FAILURE","rule_version":"2"`, "rules[1]: CONTINUED_AFTER_FAILURE: reaction: the route names a rule that " + refused},
		{second, `"rule_id":"DENIED_ACTION_RETRIED_AROUND"`, "rules[1]: DENIED_ACTION_RETRIED_AROUND: reaction: the route names a rule that " + refused},
		{first + `,"rule_version":"2"`, `"rule_id":"EXCEPTION_TAKEN","rule_version":"1"`, "rules[0]: EXCEPTION_TAKEN: reaction: the route names a rule that " + refused},
	} {
		body := routeDoc(seeded(0x4c), 1)
		if !strings.Contains(body, c.from) {
			t.Fatalf("the route fixture holds no %s", c.from)
		}
		doc := filepath.Join(tr.dir, "route.json")
		writeFixture(t, doc, strings.Replace(body, c.from, c.to, 1))
		out := filepath.Join(tr.dir, "refused.signed")
		code, stdout, stderr := invoke(t, signArgs(filepath.Join(tr.dir, "no-key"), out, doc)...)
		if code != exitFail || stdout != "" || !strings.Contains(stderr, c.want) {
			t.Errorf("%s: route sign answered %d: %q %q, want 1 and %q", c.to, code, stdout, stderr, c.want)
		}
		if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: a refused route was written: %v", c.to, err)
		}
	}
}

// TestRouteSignSignsEveryRuleThatMayStop: a route naming each of the six,
// three of them only a 0.2 procedure configures, is signed.
func TestRouteSignSignsEveryRuleThatMayStop(t *testing.T) {
	tr := newStopTree(t)
	var rules []string
	for _, r := range [][2]string{{"REPEATED_DENIAL", "2"}, {"STEP_OUTSIDE_PROCEDURE", "1"}, {"DEADLINE_EXCEEDED", "1"},
		{"RESOURCE_OUTSIDE_RUN", "1"}, {"DENIED_ACTION_RETRIED_ARGUMENTS", "1"}, {"DENIED_ACTION_RETRIED_RESOURCE", "1"}} {
		rules = append(rules, `{"procedure_id":"refund","version":"1","digest":"`+stopProcDigest+`","rule_id":"`+r[0]+`","rule_version":"`+r[1]+`"}`)
	}
	lift := base64.StdEncoding.EncodeToString(seeded(0x4c).Public().(ed25519.PublicKey))
	doc := filepath.Join(tr.dir, "route.json")
	writeFixture(t, doc, `{"kind":"reaction-route/v1alpha1","route_id":"refund-stops","serial":2,"tenant_id":"acme",`+
		`"scope":"run","lift_public_key":"`+lift+`","rules":[`+strings.Join(rules, ",")+`]}`)
	if code, stdout, stderr := invoke(t, signArgs(tr.routeKey, filepath.Join(tr.dir, "six.signed"), doc)...); code != exitOK || stderr != "" {
		t.Fatalf("route sign answered %d: %q %q", code, stdout, stderr)
	}
}

// TestTheStoppingRulesAreSupervisesMayStop holds reaction's table, which a
// plane reads without linking supervise, equal to supervise's own: every
// rule a procedure of either schema configures may stop, at supervise's
// version of it, in one exactly when it may in the other, and at any other
// version in neither; and the table names no rule, and no version, supervise
// lacks.
func TestTheStoppingRulesAreSupervisesMayStop(t *testing.T) {
	known := slices.Compact(slices.Sorted(slices.Values(slices.Concat(
		supervise.RuleIDsOf(supervise.ProcedureSchema01), supervise.RuleIDsOf(supervise.ProcedureSchema02)))))
	stopping, notStopping := 0, 0
	for _, id := range known {
		version, ok := supervise.RuleVersionOf(id)
		if !ok {
			t.Fatalf("supervise lists %s and has no version of it", id)
		}
		if reaction.MayStop(id, version) != supervise.MayStop(id) {
			t.Errorf("%s %s: reaction.MayStop %v, supervise.MayStop %v", id, version, reaction.MayStop(id, version), supervise.MayStop(id))
		}
		if reaction.MayStop(id, version+"0") {
			t.Errorf("%s: reaction.MayStop at version %s, which is not supervise's %s", id, version+"0", version)
		}
		if supervise.MayStop(id) {
			stopping++
		} else {
			notStopping++
		}
	}
	if stopping == 0 || notStopping == 0 {
		t.Fatalf("supervise listed %d rule(s), %d that may stop; the comparison saw one side only", len(known), stopping)
	}
	for _, r := range reaction.StoppingRules() {
		if version, ok := supervise.RuleVersionOf(r.ID); !ok || version != r.Version || !supervise.MayStop(r.ID) {
			t.Errorf("reaction's table names %s %s, which supervise does not let stop a run at that version", r.ID, r.Version)
		}
	}
}

// TestRouteSignReplacesNothingButASignedRoute: the key, the document and a
// directory at --out are refused and left as they were, and the lift key is
// refused as the route key.
func TestRouteSignReplacesNothingButASignedRoute(t *testing.T) {
	tr := newStopTree(t)
	doc := filepath.Join(tr.dir, "route.json")
	writeFixture(t, doc, routeDoc(seeded(0x4c), 2))
	for _, out := range []string{tr.routeKey, doc, tr.findings} {
		before, _ := os.ReadFile(out) //nolint:gosec // G304: this test's own directory
		code, stdout, stderr := invoke(t, signArgs(tr.routeKey, out, doc)...)
		if code != exitFail || stdout != "" || !strings.Contains(stderr, "is not a route's envelope") {
			t.Errorf("--out %s: route sign answered %d: %q %q", out, code, stdout, stderr)
		}
		if after, _ := os.ReadFile(out); string(after) != string(before) { //nolint:gosec // G304: this test's own directory
			t.Errorf("--out %s changed", out)
		}
	}
	out := filepath.Join(tr.dir, "lift.signed")
	code, stdout, stderr := invoke(t, signArgs(tr.liftKey, out, doc)...)
	if code != exitFail || stdout != "" || !strings.Contains(stderr, "the route key is the route's lift key") {
		t.Errorf("the lift key as the route key: %d %q %q", code, stdout, stderr)
	}
	if _, err := os.Lstat(out); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a route signed by its lift key was written: %v", err)
	}
	if code, _, stderr := invoke(t, signArgs(tr.routeKey, tr.route, doc)...); code != exitOK {
		t.Errorf("an earlier signed route was not replaced: %q", stderr)
	}
}
