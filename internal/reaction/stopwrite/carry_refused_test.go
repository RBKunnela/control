package stopwrite_test

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// routeOfPlane is a v1alpha3 route of plane-a at serial for tenant and
// project, whose rules are rules, taken for the plane of that tenant and
// project whose stop list is in dir.
func routeOfPlane(t *testing.T, dir string, serial int, tenant, project string, rules ...string) reaction.Route {
	t.Helper()
	doc := `{"kind":"reaction-route/v1alpha3","plane_id":"plane-a","route_id":"refunds","serial":` + strconv.Itoa(serial) +
		`,"tenant_id":"` + tenant + `","project_id":"` + project + `","rules":[` + strings.Join(rules, ",") + `]}`
	body, err := reaction.SignedRouteBody([]byte(doc), operatorID(), "/plane/route.json")
	noErr(t, err)
	v := planeVoucher(dir)
	v.plane.Tenant, v.plane.Project = tenant, project
	r, err := reaction.VerifySignedRoute(envelopeBy(t, operatorKey(), reaction.SignedRoutePayloadType, body), v)
	noErr(t, err)
	return r
}

// agentStopList writes into a fresh directory a 3.0 list under a route
// letting DENIED_ACTION_RETRIED_ARGUMENTS "1" stop an agent for two hours,
// holding such a stop of agent-1, and returns the directory, the route and
// the list as a lift judges it.
func agentStopList(t *testing.T) (string, reaction.Route, reaction.List) {
	t.Helper()
	from := emptyDir(t)
	fromRoute := retiredWideRoute(t, from, 5, true, refundRule(t, "STEP_OUTSIDE_PROCEDURE", "1", "run", "3600"),
		refundRule(t, "DENIED_ACTION_RETRIED_ARGUMENTS", "1", "agent", "7200"))
	header, err := stopwrite.SignedHeaderLine(fromRoute, signer(), 7)
	noErr(t, err)
	stop := reaction.Stop{
		EntryID: reaction.EntryID("f-1"), TenantID: "acme", ProjectID: "shop", Scope: reaction.ScopeAgent, Subject: "agent-1",
		RunID: "run-1", FindingID: "f-1", ProcedureID: "refund", ProcedureVersion: "1", ProcedureDigest: refundDigest(t),
		RuleID: "DENIED_ACTION_RETRIED_ARGUMENTS", RuleVersion: "1", CreatedAt: clock0.Add(-time.Minute),
		ExpiresAt: clock0.Add(-time.Minute + 2*time.Hour),
	}
	setContent(t, from, append(append(append(header, '\n'), must(t)(stop.Marshal())...), '\n'))
	l, err := reaction.JudgeForLift(fromRoute, content(t, from), clock0)
	noErr(t, err)
	return from, fromRoute, l
}

// liftAgent appends the operator's lift of agent-1 through line 2 to the list
// in from, l as a lift judges it, under fromRoute.
func liftAgent(t *testing.T, from string, fromRoute reaction.Route, l reaction.List) (int64, error) {
	t.Helper()
	body, err := reaction.SignedLiftV3{KeyID: operatorID(), PlaneID: "plane-a", ListHead: l.Header().Signed.Digest, Scope: reaction.ScopeAgent,
		Subject: "agent-1", ThroughLine: 2, TenantID: "acme", Project: "shop", File: listPath(from)}.Payload()
	noErr(t, err)
	return stopwrite.AppendLift(bg, from, fromRoute, reaction.LiftLine{Scope: reaction.ScopeAgent, Subject: "agent-1", ThroughLine: 2,
		Envelope: envelopeBy(t, operatorKey(), reaction.SignedLiftPayloadType, body)}, clock0)
}

// TestASignedCarryIntoADirectoryHoldingAListLeavesTheOldListWritable: a
// carry whose new list the judge would refuse at a stop, into a directory
// that already holds a list, is refused as one that exists, and leaves the
// old list's mode as it was, so the lift of that stop still appends.
func TestASignedCarryIntoADirectoryHoldingAListLeavesTheOldListWritable(t *testing.T) {
	from, fromRoute, l := agentStopList(t)
	occupied := emptyDir(t)
	route := signedRouteIn(t, occupied, 6)
	if _, err := stopwrite.InitSigned(bg, occupied, route, clock0, signer(), 1); err != nil {
		t.Fatal(err)
	}
	before, beside := listMode(t, from), content(t, occupied)
	if _, err := stopwrite.CarrySigned(bg, from, fromRoute, occupied, route, clock0, signer(), nil); !errors.Is(err, stopwrite.ErrExists) {
		t.Fatalf("CarrySigned into a directory holding a list: %v, want %v", err, stopwrite.ErrExists)
	}
	if got := listMode(t, from); got != before {
		t.Errorf("the old list is %04o after the refused carry, want %04o", got, before)
	}
	if !bytes.Equal(content(t, occupied), beside) {
		t.Error("the refused carry changed the list it found")
	}
	if n, err := liftAgent(t, from, fromRoute, l); err != nil || n != 3 {
		t.Errorf("the lift of the stop after the refused carry: line %d, %v", n, err)
	}
}

// TestACarryIntoAnotherTenantOrProjectNamesNoLiftAndNoRule: a carry keeps
// each stop's tenant and project, so one into a route of another refuses
// the stop naming that, and a new list, never a lift or a route rule, which
// leave the stop refused.
func TestACarryIntoAnotherTenantOrProjectNamesNoLiftAndNoRule(t *testing.T) {
	keeps := "a carry keeps each stop's tenant and project, and the new route's differ: " +
		"carry under a route of the list's tenant and project, or start a new list with stops init"
	cases := []struct {
		name  string
		carry func(t *testing.T) error
		cause error
		floor bool
	}{
		{"a 3.0 list into another project", func(t *testing.T) error {
			from, fromRoute, _ := agentStopList(t)
			into := emptyDir(t)
			to := routeOfPlane(t, into, 6, "acme", "orders", refundRule(t, "STEP_OUTSIDE_PROCEDURE", "1", "run", "3600"),
				refundRule(t, "REPEATED_DENIAL", "2", "agent", "7200"))
			_, err := stopwrite.CarrySigned(bg, from, fromRoute, into, to, clock0, signer(), nil)
			return err
		}, reaction.ErrClaimProject, true},
		{"a 2.0 list into another project whose rule would keep the stop", func(t *testing.T) error {
			from := emptyDir(t)
			fromRoute := v2RouteWith(t, from, 3, v2Rule(t, "STEP_OUTSIDE_PROCEDURE"))
			v2ListOf(t, from, fromRoute, 5, stopOf(t, "f-1", "run-1", clock0.Add(-time.Minute)))
			into := emptyDir(t)
			to := routeOfPlane(t, into, 4, "acme", "orders", refundRule(t, "STEP_OUTSIDE_PROCEDURE", "1", "run", "3600"))
			_, err := stopwrite.CarrySigned(bg, from, fromRoute, into, to, clock0, signer(), nil)
			return err
		}, reaction.ErrClaimProject, true},
		{"a 1.0 list into another tenant", func(t *testing.T) error {
			from, _ := initDir(t, routeOf(t, 3, false))
			if _, _, err := appendFinding(bg, from, routeOf(t, 3, false), stopOf(t, "f-1", "run-1", clock0), clock0); err != nil {
				t.Fatal(err)
			}
			_, err := stopwrite.Carry(bg, from, routeOf(t, 3, false), emptyDir(t), routeFor(t, 4, "other", false), clock0)
			return err
		}, reaction.ErrClaimTenant, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.carry(t)
			if !errors.Is(err, stopwrite.ErrRefused) || !errors.Is(err, c.cause) {
				t.Fatalf("the carry: %v; want %v", err, c.cause)
			}
			msg := err.Error()
			if !strings.Contains(msg, `run "run-1"`) && !strings.Contains(msg, `agent "agent-1"`) || !strings.Contains(msg, keeps) {
				t.Errorf("the refusal names no stop or no %q: %v", keeps, err)
			}
			if strings.Contains(msg, "stops lift --") || strings.Contains(msg, "give the new route") {
				t.Errorf("the refusal names a lift or a route rule: %v", err)
			}
			if got := strings.Contains(msg, "under a new stop list floor (stops floor init)"); got != c.floor {
				t.Errorf("the refusal names a new stop list floor: %v, want %v: %v", got, c.floor, err)
			}
		})
	}
}
