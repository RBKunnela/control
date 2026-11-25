package reaction_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/reaction"
)

// FuzzParseRoute: for any bytes, ParseRoute returns a route or exactly one of
// its refusals and never panics. A route it accepts is held to its bounds,
// reads back from its canonical bytes as the same route, signs, verifies
// exactly when every rule it names may stop a run, and permits a claim of
// each of its rules.
func FuzzParseRoute(f *testing.F) {
	doc := withLift(routeTemplate)
	f.Add([]byte(doc))
	f.Add([]byte(withLift(routeCanonical)))
	f.Add([]byte(routeWith("r", "t", []string{ruleJSON("p"), ruleJSON("q")})))
	f.Add([]byte(strings.Replace(doc, `"serial": 7`, `"serial": 9007199254740991`, 1)))
	f.Add([]byte(strings.Replace(doc, `"serial": 7,`, `"serial": 7, "serial": 8,`, 1)))
	f.Add([]byte(strings.Replace(doc, `"RESOURCE_OUTSIDE_RUN"`, `"STEP_OUTSIDE_PROCEDURE"`, 1)))
	f.Add([]byte(strings.Replace(doc, `"scope": "run"`, `"scope": "agent"`, 1)))
	f.Add([]byte(strings.Replace(doc, `3600`, `2592001`, 1)))
	f.Add([]byte(strings.Replace(doc, `"refunds"`, `"ref\ud800unds"`, 1)))
	signed := routeEnvelope(f, sProject, sRouteFile, operatorKey()).Payload
	f.Add(signed)
	f.Add(editedBody(f, signed, map[string]any{"kind": reaction.SignedRouteKind, "plane_id": nil}))
	f.Add([]byte(strings.Replace(string(signed), `"scope":"run"`, `"scope":"agent"`, 1)))
	f.Fuzz(func(t *testing.T, raw []byte) {
		held := bytes.Clone(raw)
		r, err := reaction.ParseRoute(raw)
		if !bytes.Equal(raw, held) {
			t.Fatal("ParseRoute changed its input")
		}
		if err != nil {
			matched := 0
			for _, s := range routeRefusals() {
				if errors.Is(err, s) {
					matched++
				}
			}
			if matched != 1 {
				t.Fatalf("refusal %v matches %d sentinels", err, matched)
			}
			return
		}
		checkAccepted(t, raw, r)
	})
}

func checkAccepted(t *testing.T, raw []byte, r reaction.Route) {
	t.Helper()
	if len(raw) > reaction.MaxRouteBytes || r.Serial() < 1 || r.Serial() > policy.MaxSerial || r.TenantID() == "" ||
		len(r.Rules()) == 0 || len(r.Rules()) > reaction.MaxRules {
		t.Fatalf("accepted a route outside its bounds: %d bytes, serial %d, %d rules", len(raw), r.Serial(), len(r.Rules()))
	}
	checkReadBack(t, raw, r)
	checkSignedAndPermits(t, r)
}

func checkReadBack(t *testing.T, raw []byte, r reaction.Route) {
	t.Helper()
	want, err := canon.CanonicalizeJSON(raw)
	if err != nil || !bytes.Equal(want, r.Canonical()) {
		t.Fatalf("the canonical bytes are not the canonical form of the input: %v", err)
	}
	again, err := reaction.ParseRoute(r.Canonical())
	if err != nil || again.Digest() != r.Digest() || again.ID() != r.ID() || fmt.Sprint(again.Rules()) != fmt.Sprint(r.Rules()) {
		t.Fatalf("the canonical bytes read back as another route: %v", err)
	}
}

func checkSignedAndPermits(t *testing.T, r reaction.Route) {
	t.Helper()
	if reaction.DistinctKeys(r.LiftKey(), pubOf(routeKey())) != nil {
		return
	}
	env, err := reaction.SignRoute(r, routeKey())
	if err != nil {
		t.Fatalf("SignRoute: %v", err)
	}
	v, err := reaction.VerifyRoute(env, pubOf(routeKey()))
	if !namesOnlyStoppingRules(r) {
		expectOnly(t, "VerifyRoute of a signed route naming a rule that may not stop", err, reaction.ErrRouteRuleStops,
			append(routeRefusals(), envelopeRefusals()...))
	} else if err != nil || v.Digest() != r.Digest() {
		t.Fatalf("VerifyRoute of the signed route: %v", err)
	}
	for _, rule := range r.Rules() {
		claim := reaction.StopClaim{
			TenantID: r.TenantID(), ProcedureID: rule.ProcedureID, ProcedureVersion: rule.ProcedureVersion,
			ProcedureDigest: rule.ProcedureDigest, RuleID: rule.RuleID, RuleVersion: rule.RuleVersion,
			CreatedAt: created, ExpiresAt: created.Add(reaction.MinLifetime),
		}
		if err := r.Permits(claim); err != nil {
			t.Fatalf("the route does not permit a claim of its own rule: %v", err)
		}
	}
}

// FuzzVerifyLift: for any body signed under the lift key, VerifyLift returns
// a lift or exactly one of the lift's refusals, and a lift it returns has
// exactly that body as its payload.
func FuzzVerifyLift(f *testing.F) {
	f.Add([]byte(liftCanonical))
	f.Add([]byte(strings.Replace(liftCanonical, `"through_line":12`, `"through_line":9007199254740991`, 1)))
	f.Add([]byte(strings.Replace(liftCanonical, `"1.0"`, `"1.7"`, 1)))
	f.Add([]byte(strings.Replace(liftCanonical, `,"version"`, `, "version"`, 1)))
	f.Add([]byte(`{}`))
	key := liftKey()
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > reaction.MaxLiftBytes {
			return
		}
		l, err := reaction.VerifyLift(liftSigned(t, string(body)), pubOf(key))
		if err != nil {
			matched := 0
			for _, s := range liftRefusals() {
				if errors.Is(err, s) {
					matched++
				}
			}
			if matched != 1 {
				t.Fatalf("refusal %v matches %d sentinels", err, matched)
			}
			return
		}
		payload, err := l.Payload()
		if err != nil || !bytes.Equal(payload, body) {
			t.Fatalf("the lift read back as another payload: %s, %v", payload, err)
		}
	})
}
