package reaction_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

func TestParseRouteReadsADocument(t *testing.T) {
	r := validRoute(t)
	if r.ID() != "refunds" || r.Serial() != 7 || r.TenantID() != "acme" || !bytes.Equal(r.LiftKey(), pubOf(liftKey())) {
		t.Fatalf("route = %q %d %q, lift key %x", r.ID(), r.Serial(), r.TenantID(), r.LiftKey())
	}
	want := []reaction.Rule{
		{ProcedureID: "refund", ProcedureVersion: "3", ProcedureDigest: procDigest, RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1", Lifetime: time.Hour},
		{ProcedureID: "refund", ProcedureVersion: "3", ProcedureDigest: procDigest, RuleID: "DEADLINE_EXCEEDED", RuleVersion: "1"},
	}
	got := r.Rules()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("rules = %+v, want %+v", got, want)
	}
	canonical := withLift(routeCanonical)
	if string(r.Canonical()) != canonical {
		t.Fatalf("canonical = %s\nwant        %s", r.Canonical(), canonical)
	}
	sum := sha256.Sum256([]byte(canonical))
	if want := "sha256:" + hex.EncodeToString(sum[:]); r.Digest() != want {
		t.Fatalf("digest = %s, want %s", r.Digest(), want)
	}
}

// The accessors hand out copies: a caller writing into one changes nothing
// the route holds.
func TestRouteAccessorsCopy(t *testing.T) {
	r := validRoute(t)
	r.LiftKey()[0] ^= 0xff
	r.Canonical()[0] = '['
	r.Rules()[0].RuleID = "OTHER"
	if !bytes.Equal(r.LiftKey(), pubOf(liftKey())) || r.Canonical()[0] != '{' || r.Rules()[0].RuleID != "STEP_OUTSIDE_PROCEDURE" {
		t.Fatal("a write into an accessor's result reached the route")
	}
}

func TestParseRouteRefuses(t *testing.T) {
	doc := withLift(routeTemplate)
	edit := func(old, repl string) string {
		t.Helper()
		if !strings.Contains(doc, old) {
			t.Fatalf("the template holds no %q", old)
		}
		return strings.Replace(doc, old, repl, 1)
	}
	firstRule := `"rule_id": "STEP_OUTSIDE_PROCEDURE", "rule_version": "1", "expires_seconds": 3600`
	for _, c := range []struct {
		name, doc string
		want      error
	}{
		{"an array", `[]`, reaction.ErrRouteJSON},
		{"nothing", ``, reaction.ErrRouteJSON},
		{"a second object after it", doc + `{}`, reaction.ErrRouteJSON},
		{"invalid UTF-8", edit(`"refunds"`, "\"ref\xffunds\""), reaction.ErrRouteJSON},
		{"an unpaired surrogate", edit(`"refunds"`, `"ref\ud800unds"`), reaction.ErrRouteJSON},
		{"a member twice", edit(`"serial": 7,`, `"serial": 7, "serial": 8,`), reaction.ErrRouteRepeated},
		{"a member twice, once escaped", edit(`"serial": 7,`, `"serial": 7, "seri\u0061l": 8,`), reaction.ErrRouteRepeated},
		{"a rule member twice", edit(`"rule_version": "1", "expires`, `"rule_version": "1", "rule_version": "1", "expires`), reaction.ErrRouteRepeated},
		{"another kind", edit(`reaction-route/v1alpha1`, `reaction-route/v1alpha3`), reaction.ErrRouteKind},
		{"a kind that is not a string", edit(`"reaction-route/v1alpha1"`, `1`), reaction.ErrRouteKind},
		{"no kind", edit(`"kind": "reaction-route/v1alpha1",`, ``), reaction.ErrRouteMember},
		{"an unknown member", edit(`"serial": 7,`, `"serial": 7, "x": 1,`), reaction.ErrRouteMember},
		{"an agent member", edit(`"serial": 7,`, `"serial": 7, "agent_id": "a",`), reaction.ErrRouteMember},
		{"a principal member", edit(`"serial": 7,`, `"serial": 7, "principal_id": "p",`), reaction.ErrRouteMember},
		{"a member in another case", edit(`"serial"`, `"Serial"`), reaction.ErrRouteMember},
		{"no scope", edit(`"scope": "run",`, ``), reaction.ErrRouteMember},
		{"no lift key", edit(`"lift_public_key"`, `"lift_key"`), reaction.ErrRouteMember},
		{"no rules", edit(`"rules"`, `"rule"`), reaction.ErrRouteMember},
		{"an unknown rule member", edit(firstRule, firstRule+`, "escalation": "x"`), reaction.ErrRouteMember},
		{"a rule with no digest", edit(`"digest": "`+procDigest+`",
     "rule_id": "STEP_OUTSIDE`, `"rule_id": "STEP_OUTSIDE`), reaction.ErrRouteMember},
		{"an agent scope", edit(`"scope": "run"`, `"scope": "agent"`), reaction.ErrRouteScope},
		{"a principal scope", edit(`"scope": "run"`, `"scope": "principal"`), reaction.ErrRouteScope},
		{"a tenant scope", edit(`"scope": "run"`, `"scope": "tenant"`), reaction.ErrRouteScope},
		{"a scope in capitals", edit(`"scope": "run"`, `"scope": "RUN"`), reaction.ErrRouteScope},
		{"an empty scope", edit(`"scope": "run"`, `"scope": ""`), reaction.ErrRouteScope},
		{"a null scope", edit(`"scope": "run"`, `"scope": null`), reaction.ErrRouteScope},
		{"serial 0", edit(`"serial": 7`, `"serial": 0`), reaction.ErrRouteSerial},
		{"a negative serial", edit(`"serial": 7`, `"serial": -7`), reaction.ErrRouteSerial},
		{"a serial with a fraction", edit(`"serial": 7`, `"serial": 7.0`), reaction.ErrRouteSerial},
		{"a serial with an exponent", edit(`"serial": 7`, `"serial": 7e0`), reaction.ErrRouteSerial},
		{"a serial as a string", edit(`"serial": 7`, `"serial": "7"`), reaction.ErrRouteSerial},
		{"a null serial", edit(`"serial": 7`, `"serial": null`), reaction.ErrRouteSerial},
		{"serial 2^53", edit(`"serial": 7`, `"serial": 9007199254740992`), reaction.ErrRouteSerial},
		{"an empty route id", edit(`"refunds"`, `""`), reaction.ErrRouteValue},
		{"a null route id", edit(`"refunds"`, `null`), reaction.ErrRouteValue},
		{"a route id with a line break", edit(`"refunds"`, `"ref\nunds"`), reaction.ErrRouteValue},
		{"a route id ending in a space", edit(`"refunds"`, `"refunds "`), reaction.ErrRouteValue},
		{"an empty tenant", edit(`"acme"`, `""`), reaction.ErrRouteValue},
		{"a tenant with a format character", edit(`"acme"`, `"ac\u200bme"`), reaction.ErrRouteValue},
		{"a lift key line with its newline", edit(`"lift_public_key": "`+keyLine(liftKey())+`"`, `"lift_public_key": "`+keyLine(liftKey())+`\n"`), reaction.ErrRouteValue},
		{"a lift key of 31 bytes", edit(keyLine(liftKey()), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="), reaction.ErrRouteValue},
		{"a lift key that is not a string", edit(`"`+keyLine(liftKey())+`"`, `[]`), reaction.ErrRouteValue},
		{"rules that are not an array", edit(`"rules": [`, `"rules": {"a": [`) + "}", reaction.ErrRouteValue},
		{"null rules", `{"kind":"reaction-route/v1alpha1","route_id":"r","serial":1,"tenant_id":"t","scope":"run","lift_public_key":"` +
			keyLine(liftKey()) + `","rules":null}`, reaction.ErrRouteValue},
		{"no rule", `{"kind":"reaction-route/v1alpha1","route_id":"r","serial":1,"tenant_id":"t","scope":"run","lift_public_key":"` +
			keyLine(liftKey()) + `","rules":[]}`, reaction.ErrRouteRules},
		{"a rule that is not an object", edit(`"rules": [`, `"rules": [1, `), reaction.ErrRouteJSON},
		{"an upper-case digest", edit(`"digest": "`+procDigest+`",
     "rule_id": "STEP_OUTSIDE`, `"digest": "`+strings.ToUpper(procDigest)+`",
     "rule_id": "STEP_OUTSIDE`), reaction.ErrRouteValue},
		{"a short digest", edit(`"digest": "`+procDigest+`",
     "rule_id": "STEP_OUTSIDE`, `"digest": "`+procDigest[:len(procDigest)-1]+`",
     "rule_id": "STEP_OUTSIDE`), reaction.ErrRouteValue},
		{"a long digest", edit(`"digest": "`+procDigest+`",
     "rule_id": "STEP_OUTSIDE`, `"digest": "`+procDigest+`0",
     "rule_id": "STEP_OUTSIDE`), reaction.ErrRouteValue},
		{"a digest with the algorithm prefix a route digest carries", edit(`"digest": "`+procDigest+`",
     "rule_id": "STEP_OUTSIDE`, `"digest": "sha256:`+procDigest+`",
     "rule_id": "STEP_OUTSIDE`), reaction.ErrRouteValue},
		{"a digest that is not hex", edit(`"digest": "`+procDigest+`",
     "rule_id": "STEP_OUTSIDE`, `"digest": "`+strings.Replace(procDigest, "0", "g", 1)+`",
     "rule_id": "STEP_OUTSIDE`), reaction.ErrRouteValue},
		{"an empty rule id", edit(`"STEP_OUTSIDE_PROCEDURE"`, `""`), reaction.ErrRouteValue},
		{"a number for a version", edit(`"version": "3", "digest": "`+procDigest+`",
     "rule_id": "STEP_OUTSIDE`, `"version": 3, "digest": "`+procDigest+`",
     "rule_id": "STEP_OUTSIDE`), reaction.ErrRouteValue},
		{"expires_seconds 59", edit(`3600`, `59`), reaction.ErrRouteLifetime},
		{"expires_seconds 0", edit(`3600`, `0`), reaction.ErrRouteLifetime},
		{"expires_seconds one past the longest run", edit(`3600`, `2592001`), reaction.ErrRouteLifetime},
		{"expires_seconds with a fraction", edit(`3600`, `3600.0`), reaction.ErrRouteLifetime},
		{"expires_seconds as a string", edit(`3600`, `"3600"`), reaction.ErrRouteLifetime},
		{"null expires_seconds", edit(`3600`, `null`), reaction.ErrRouteLifetime},
		{"one rule twice", edit(`"DEADLINE_EXCEEDED"`, `"STEP_OUTSIDE_PROCEDURE"`), reaction.ErrRouteRuleRepeated},
	} {
		_, err := reaction.ParseRoute([]byte(c.doc))
		expectOnly(t, c.name, err, c.want, routeRefusals())
	}
}

// Two rules alike but for their lifetime are one rule twice.
func TestParseRouteRefusesARuleRepeatedWithAnotherLifetime(t *testing.T) {
	doc := strings.Replace(withLift(routeTemplate), `"DEADLINE_EXCEEDED", "rule_version": "1"`, `"STEP_OUTSIDE_PROCEDURE", "rule_version": "1", "expires_seconds": 60`, 1)
	_, err := reaction.ParseRoute([]byte(doc))
	expectOnly(t, "a repeated rule", err, reaction.ErrRouteRuleRepeated, routeRefusals())
	doc = strings.Replace(doc, `"expires_seconds": 60`, `"expires_seconds": 60}, {"procedure_id": "refund", "version": "4", "digest": "`+procDigest+`", "rule_id": "R", "rule_version": "1"`, 1)
	if _, err := reaction.ParseRoute([]byte(strings.Replace(doc, `"STEP_OUTSIDE_PROCEDURE", "rule_version": "1", "expires_seconds": 60`, `"STEP_OUTSIDE_PROCEDURE", "rule_version": "2", "expires_seconds": 60`, 1))); err != nil {
		t.Fatalf("rules that differ in their rule version: %v", err)
	}
}

// ruleJSON is one rule naming procedure p.
func ruleJSON(p string) string {
	return `{"procedure_id":"` + p + `","version":"1","digest":"` + procDigest + `","rule_id":"R","rule_version":"1"}`
}

// routeWith is a compact route with the given members' values in place.
func routeWith(routeID, tenant string, rules []string) string {
	return `{"kind":"reaction-route/v1alpha1","route_id":"` + routeID + `","serial":1,"tenant_id":"` + tenant +
		`","scope":"run","lift_public_key":"` + keyLine(liftKey()) + `","rules":[` + strings.Join(rules, ",") + `]}`
}

func TestParseRouteBounds(t *testing.T) {
	ruleWith := func(member string, n int) []string {
		return []string{strings.Replace(ruleJSON("p"), `"`+member+`":"`, `"`+member+`":"`+strings.Repeat("x", n-1), 1)}
	}
	for _, c := range []struct {
		name string
		doc  func(n int) string
		at   int
		want error
	}{
		{"route_id", func(n int) string { return routeWith(strings.Repeat("r", n), "t", []string{ruleJSON("p")}) }, 1024, reaction.ErrRouteValue},
		{"tenant_id", func(n int) string { return routeWith("r", strings.Repeat("t", n), []string{ruleJSON("p")}) }, 256, reaction.ErrRouteValue},
		{"procedure_id", func(n int) string { return routeWith("r", "t", ruleWith("procedure_id", n)) }, 1024, reaction.ErrRouteValue},
		{"version", func(n int) string { return routeWith("r", "t", ruleWith("version", n)) }, 1024, reaction.ErrRouteValue},
		{"rule_id", func(n int) string { return routeWith("r", "t", ruleWith("rule_id", n)) }, 1024, reaction.ErrRouteValue},
		{"rule_version", func(n int) string { return routeWith("r", "t", ruleWith("rule_version", n)) }, 1024, reaction.ErrRouteValue},
		{"rules", func(n int) string {
			rules := make([]string, n)
			for i := range rules {
				rules[i] = ruleJSON(fmt.Sprintf("p%d", i))
			}
			return routeWith("r", "t", rules)
		}, 256, reaction.ErrRouteRules},
		{"bytes", func(n int) string {
			doc := routeWith("r", "t", []string{ruleJSON("p")})
			return doc + strings.Repeat(" ", n-len(doc))
		}, 65536, reaction.ErrRouteTooLarge},
	} {
		if _, err := reaction.ParseRoute([]byte(c.doc(c.at))); err != nil {
			t.Errorf("%s at %d: %v", c.name, c.at, err)
		}
		_, err := reaction.ParseRoute([]byte(c.doc(c.at + 1)))
		expectOnly(t, fmt.Sprintf("%s at %d", c.name, c.at+1), err, c.want, routeRefusals())
	}
}

func TestParseRouteTakesTheBoundaryNumbers(t *testing.T) {
	doc := withLift(routeTemplate)
	r, err := reaction.ParseRoute([]byte(strings.Replace(doc, `"serial": 7`, `"serial": 9007199254740991`, 1)))
	if err != nil || r.Serial() != 9007199254740991 {
		t.Fatalf("serial 2^53-1: %d, %v", r.Serial(), err)
	}
	if r, err = reaction.ParseRoute([]byte(strings.Replace(doc, `"serial": 7`, `"serial": 1`, 1))); err != nil || r.Serial() != 1 {
		t.Fatalf("serial 1: %d, %v", r.Serial(), err)
	}
	for _, c := range []struct {
		seconds string
		want    time.Duration
	}{{"60", time.Minute}, {"2592000", 720 * time.Hour}} {
		r, err := reaction.ParseRoute([]byte(strings.Replace(doc, `3600`, c.seconds, 1)))
		if err != nil || r.Rules()[0].Lifetime != c.want {
			t.Errorf("expires_seconds %s: %v, %v", c.seconds, r.Rules(), err)
		}
	}
}
