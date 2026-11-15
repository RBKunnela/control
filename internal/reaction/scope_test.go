package reaction_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

// TestAScopeOtherThanRunParsesAndIsRefused: a v1alpha3 rule, a 3.0 stop,
// covered or lift line and a v1alpha3 lift may name scope agent or
// principal, which this build refuses with ErrRouteScope; a scope outside
// the grammar, an empty one and none are refused too, and a v1alpha2 rule
// names run alone.
func TestAScopeOtherThanRunParsesAndIsRefused(t *testing.T) {
	doc := strings.NewReplacer("PLANE", sPlane, "PROJECT", sProject).Replace(signedRouteDoc)
	if _, err := reaction.ParseRouteDocument([]byte(doc)); err != nil {
		t.Fatalf("a rule of scope run: %v", err)
	}
	for _, c := range []struct {
		scope string
		want  error
	}{
		{`"scope":"agent"`, reaction.ErrRouteScope},
		{`"scope":"principal"`, reaction.ErrRouteScope},
		{`"scope":"tree"`, reaction.ErrRouteScope},
		{`"scope":""`, reaction.ErrRouteScope},
		{`"scope":1`, reaction.ErrRouteScope},
	} {
		edited := strings.Replace(doc, `"scope":"run"`, c.scope, 1)
		if _, err := reaction.ParseRouteDocument([]byte(edited)); !errors.Is(err, c.want) {
			t.Errorf("a v1alpha3 rule of %s: %v, want %v", c.scope, err, c.want)
		}
	}
	if _, err := reaction.ParseRouteDocument([]byte(strings.Replace(doc, `,"scope":"run"`, ``, 1))); !errors.Is(err, reaction.ErrRouteMember) {
		t.Errorf("a v1alpha3 rule with no scope: %v, want %v", err, reaction.ErrRouteMember)
	}
	v2 := v2RouteEnvelope(t).Payload
	if _, err := reaction.ParseRoute(v2); err != nil {
		t.Fatalf("a v1alpha2 rule of scope run: %v", err)
	}
	if _, err := reaction.ParseRoute([]byte(strings.Replace(string(v2), `"scope":"run"`, `"scope":"agent"`, 1))); !errors.Is(err, reaction.ErrRouteScope) {
		t.Errorf("a v1alpha2 rule of scope agent: %v, want %v", err, reaction.ErrRouteScope)
	}
}

// TestA30LineNamesItsScopeAndARunSubjectIsItsRun: a 3.0 stop or covered
// line of scope run whose subject is its run_id is read; another subject,
// an empty or missing one, a missing or empty scope and scope agent or
// principal are each refused.
func TestA30LineNamesItsScopeAndARunSubjectIsItsRun(t *testing.T) {
	covered, err := reaction.Covered{FindingID: "f-2", TenantID: sTenant, RunID: "run-1", ProjectID: sProject,
		Scope: reaction.ScopeRun, Subject: "run-1", CreatedAt: sCreated}.Marshal()
	if err != nil {
		t.Fatalf("Covered.Marshal: %v", err)
	}
	for kind, line := range map[string]string{"stop": string(signedStop(t, sProject)), "covered": string(covered)} {
		l, err := reaction.ParseLine([]byte(line))
		if err != nil || l.Version != reaction.SignedListVersionV3 {
			t.Fatalf("a 3.0 %s line of run-1's subject: version %q, %v", kind, l.Version, err)
		}
		for _, c := range []struct {
			name, from, to string
			want           error
		}{
			{"another run as its subject", `"subject":"run-1"`, `"subject":"run-2"`, reaction.ErrLineValue},
			{"an empty subject", `"subject":"run-1"`, `"subject":""`, reaction.ErrLineValue},
			{"no subject", `,"subject":"run-1"`, ``, reaction.ErrLineMember},
			{"no scope", `"scope":"run",`, ``, reaction.ErrLineMember},
			{"an empty scope", `"scope":"run"`, `"scope":""`, reaction.ErrLineValue},
			{"scope agent", `"scope":"run"`, `"scope":"agent"`, reaction.ErrRouteScope},
			{"scope principal", `"scope":"run"`, `"scope":"principal"`, reaction.ErrRouteScope},
		} {
			edited := strings.Replace(line, c.from, c.to, 1)
			if edited == line {
				t.Fatalf("%s: %q is not in the %s line", c.name, c.from, kind)
			}
			if _, err := reaction.ParseLine([]byte(edited)); !errors.Is(err, c.want) {
				t.Errorf("a 3.0 %s line with %s: %v, want %v", kind, c.name, err, c.want)
			}
		}
	}
}

// TestALiftOfAnAgentScopeIsRefused: a v1alpha3 lift naming scope agent or
// principal is never signed, and a 3.0 lift line naming one never read.
func TestALiftOfAnAgentScopeIsRefused(t *testing.T) {
	r := vouchedRoute(t, newVoucher())
	header, head := signedHeaderLine(t, r, headerOpts{})
	lift := reaction.SignedLiftV3{KeyID: keyIDOf(operatorKey()), PlaneID: sPlane, ListHead: head, Scope: reaction.ScopeRun,
		Subject: "run-1", ThroughLine: 2, TenantID: sTenant, Project: sProject, File: sListFile}
	line := signedLiftLineOf(t, lift, operatorKey(), "run-1", 2)
	if l, err := reaction.Judge(r, reaction.Prefix{}, joinLines(header, signedStop(t, sProject), line), sNow, 0); err != nil || len(l.Entries()) != 0 {
		t.Fatalf("a lift of scope run: %d entries, %v", len(l.Entries()), err)
	}
	for _, scope := range []string{reaction.ScopeAgent, reaction.ScopePrincipal} {
		wide := lift
		wide.Scope = scope
		if _, err := wide.Payload(); !errors.Is(err, reaction.ErrRouteScope) {
			t.Errorf("a v1alpha3 lift of scope %s: %v, want %v", scope, err, reaction.ErrRouteScope)
		}
		edited := strings.Replace(string(line), `"scope":"run"`, `"scope":"`+scope+`"`, 1)
		if _, err := reaction.ParseLine([]byte(edited)); !errors.Is(err, reaction.ErrRouteScope) {
			t.Errorf("a 3.0 lift line of scope %s: %v, want %v", scope, err, reaction.ErrRouteScope)
		}
	}
}

// TestA20LineNamesScopeRunAlone: a 2.0 stop line, which 0.17 wrote and a
// carry still reads, names scope run and no subject; scope agent is refused.
func TestA20LineNamesScopeRunAlone(t *testing.T) {
	stop, err := reaction.Stop{
		EntryID: reaction.EntryID("f-1"), TenantID: sTenant, ProjectID: sProject, Scope: reaction.ScopeRun, RunID: "run-1",
		FindingID: "f-1", ProcedureID: "refund", ProcedureVersion: "3", ProcedureDigest: procDigest,
		RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1", CreatedAt: sCreated, ExpiresAt: sCreated.Add(time.Hour),
	}.Marshal()
	noErr(t, err)
	if l, err := reaction.ParseLine(stop); err != nil || l.Version != reaction.SignedListVersion {
		t.Fatalf("a 2.0 stop line of scope run: version %q, %v", l.Version, err)
	}
	agent := strings.Replace(string(stop), `"scope":"run"`, `"scope":"agent"`, 1)
	if agent == string(stop) {
		t.Fatal("the 2.0 stop line names no scope")
	}
	if _, err := reaction.ParseLine([]byte(agent)); !errors.Is(err, reaction.ErrLineValue) {
		t.Fatalf("a 2.0 stop line of scope agent: %v, want %v", err, reaction.ErrLineValue)
	}
}
