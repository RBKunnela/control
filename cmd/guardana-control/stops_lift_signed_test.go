package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
)

// retiredAgentRouteDoc is signedRouteDoc as a route signed before the retry
// rules were retired: DENIED_ACTION_RETRIED_ARGUMENTS version "1" stops an
// agent for two hours.
const retiredAgentRouteDoc = `{"kind":"reaction-route/v1alpha3","plane_id":"plane-a","route_id":"refund-stops","serial":1,` +
	`"tenant_id":"acme","project_id":"orders","rules":[` +
	`{"procedure_id":"refund","version":"1","digest":"` + stopProcDigest + `",` +
	`"rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","scope":"run"},` +
	`{"procedure_id":"refund","version":"1","digest":"` + stopProcDigest + `",` +
	`"rule_id":"DENIED_ACTION_RETRIED_ARGUMENTS","rule_version":"1","scope":"agent","expires_seconds":7200}]}`

// writeRetiredAgentList signs retiredAgentRouteDoc with dave's key at path,
// as route sign no longer does, and writes into tr's stops directory a list
// alice's key started under it, holding a stop of agent-1 under the retry
// rule. It returns the route as a lift takes it.
func (tr signedTree) writeRetiredAgentList(t *testing.T, path string) reaction.Route {
	t.Helper()
	env, _, err := signedRouteEnvelope([]byte(retiredAgentRouteDoc), path, signedKey("dave"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := reaction.MarshalRouteFile(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := rosterRoute("--route", path, tr.judge[1], tr.judge[3], tr.stops, "", nil, reaction.VerifySignedCarrySource)
	if err != nil {
		t.Fatal(err)
	}
	alice := policykey.KeyID(signedKey("alice").Public().(ed25519.PublicKey))
	body, err := reaction.HeaderBody(reaction.Header{ListID: "lst-0123456789abcdef0123456789abcdef", RouteID: r.ID(), RouteSerial: r.Serial(),
		RouteDigest: r.Digest(), Signed: reaction.HeaderSigned{KeyID: alice, PlaneID: r.PlaneID(), TenantID: "acme", ProjectID: "orders",
			File: r.Plane().ListFile, Serial: 1}})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := headerSigner(signedKey("alice")).Sign(reaction.SignedHeaderPayloadType, body)
	if err != nil {
		t.Fatal(err)
	}
	header, err := reaction.SignedHeaderLine(reaction.Envelope{PayloadType: reaction.SignedHeaderPayloadType, Payload: body,
		Signatures: []reaction.Signature{{KeyID: alice, Signature: sig}}})
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	stop, err := reaction.Stop{EntryID: reaction.EntryID("f-1"), TenantID: "acme", ProjectID: "orders", Scope: reaction.ScopeAgent,
		Subject: "agent-1", RunID: "run-1", FindingID: "f-1", ProcedureID: "refund", ProcedureVersion: "1", ProcedureDigest: stopProcDigest,
		RuleID: "DENIED_ACTION_RETRIED_ARGUMENTS", RuleVersion: "1", CreatedAt: created, ExpiresAt: created.Add(2 * time.Hour)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	list := append(append(append(header, '\n'), stop...), '\n')
	if err := os.WriteFile(filepath.Join(tr.stops, stoplist.FileName), list, 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestASignedLiftEndsAnAgentStopUnderTheRouteItWasWrittenUnder: a signed
// list holds an agent stop of DENIED_ACTION_RETRIED_ARGUMENTS version "1"
// under the route that let it stop an agent. stops lift --roster takes that
// route, which every writer of a stop refuses, and appends alice's lift of
// the agent as line 3, after which the list under it stops no one.
func TestASignedLiftEndsAnAgentStopUnderTheRouteItWasWrittenUnder(t *testing.T) {
	tr := newSignedTree(t)
	tr.route = filepath.Join(tr.dir, "route-old.json")
	route := tr.writeRetiredAgentList(t, tr.route)
	before := listBytes(t, tr.stops)

	code, stdout, stderr := tr.run(t, "stops lift", "--key", tr.keys["alice"], "--agent", "agent-1", tr.stops)
	if code != exitOK || !strings.HasPrefix(stdout, "lift line 3 agent agent-1 through line 2") ||
		!strings.Contains(stderr, "signed lift of agent agent-1 through line 2") {
		t.Fatalf("stops lift under the route the list was written under: %d, %q, %q", code, stdout, stderr)
	}
	after := listBytes(t, tr.stops)
	if !bytes.HasPrefix(after, before) || bytes.Count(after, []byte{'\n'}) != 3 {
		t.Fatalf("the list after the lift:\n%s", after)
	}
	l, err := reaction.JudgeForLift(route, after, time.Now())
	if err != nil || len(l.Entries()) != 0 {
		t.Fatalf("the list after the lift: %d stops, %v", len(l.Entries()), err)
	}
}
