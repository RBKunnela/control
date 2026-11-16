package reaction

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestNoFormatIsNoneOfTheFormats: every switch on a route's format refuses
// FormatNone and a value past the last format, which no reader makes, rather
// than take either as one it knows.
func TestNoFormatIsNoneOfTheFormats(t *testing.T) {
	p := Plane{ID: "plane-a", Tenant: "t", Project: "p", RouteFile: "/r", ListFile: "/l"}
	for _, f := range []RouteFormat{FormatNone, FormatV1Alpha3 + 1} {
		if err := samePlane(p, binding{format: f, plane: "plane-a"}); !errors.Is(err, ErrOtherPlane) {
			t.Errorf("format %d naming the plane: %v, want %v", f, err, ErrOtherPlane)
		}
		if err := samePlane(p, binding{format: f}); !errors.Is(err, ErrOtherPlane) {
			t.Errorf("format %d naming no plane: %v, want %v", f, err, ErrOtherPlane)
		}
		r := Route{format: f, digest: "d", voucher: fakeInternalVoucher{p}}
		if err := formatJudges(r, true); !errors.Is(err, ErrListRoute) {
			t.Errorf("format %d judged as a carry's source: %v, want %v", f, err, ErrListRoute)
		}
		if _, err := listVersion(f); !errors.Is(err, ErrListRoute) {
			t.Errorf("format %d named a list version: %v", f, err)
		}
		if err := vouchAgain(context.Background(), r, nil); !errors.Is(err, ErrListRoute) {
			t.Errorf("format %d vouched again: %v, want %v", f, err, ErrListRoute)
		}
	}
}

type fakeInternalVoucher struct{ p Plane }

func (v fakeInternalVoucher) Plane() Plane { return v.p }

func (fakeInternalVoucher) Vouch(SignedKind, Envelope) (Signer, error) {
	return Signer{Subject: "alice", KeyID: "k"}, nil
}

// TestALiftEndsTheScopeAndSubjectItNames: a 1.0 or 2.0 lift line ends its
// run's stops, and a 3.0 one the stops of its scope and subject alone; one
// naming no subject, a run_id beside its subject, or a scope outside the
// grammar ends nothing and is refused.
func TestALiftEndsTheScopeAndSubjectItNames(t *testing.T) {
	for _, c := range []struct {
		l    LiftLine
		want Target
	}{
		{LiftLine{RunID: "run-1"}, Target{ScopeRun, "run-1"}},
		{LiftLine{Scope: ScopeRun, Subject: "run-1"}, Target{ScopeRun, "run-1"}},
		{LiftLine{Scope: ScopeAgent, Subject: "agent-a"}, Target{ScopeAgent, "agent-a"}},
		{LiftLine{Scope: ScopePrincipal, Subject: "alice"}, Target{ScopePrincipal, "alice"}},
	} {
		if got, err := liftedTarget(c.l); err != nil || got != c.want {
			t.Errorf("a lift line %+v: %+v, %v; want %+v", c.l, got, err, c.want)
		}
	}
	for _, l := range []LiftLine{
		{}, {Scope: ScopeRun}, {Scope: ScopeAgent}, {Scope: ScopeRun, Subject: "run-1", RunID: "run-1"},
		{Scope: ScopeAgent, Subject: "agent-a", RunID: "run-1"}, {Scope: ScopeRun, RunID: "run-1"},
		{Scope: "tree", Subject: "run-1"}, {Subject: "run-1"},
	} {
		if got, err := liftedTarget(l); err == nil || got != (Target{}) {
			t.Errorf("a lift line %+v: %+v, %v; want a refusal", l, got, err)
		}
	}
}

// TestAnEntryOfAScopeNoReaderMakesNamesNoCall: every reader refuses a scope
// the grammar does not name, so no List holds one; the matcher still reads
// an active entry of such a scope as a call it cannot name, never as clear.
func TestAnEntryOfAScopeNoReaderMakesNamesNoCall(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := List{entries: []Entry{{Line: 2, Stop: Stop{TenantID: "acme", Scope: "tree", Subject: "root-1", RunID: "run-1",
		ExpiresAt: now.Add(time.Hour)}}}}
	who := Subject{Tenant: "acme", Run: "run-1", Agent: "agent-a", Principal: "alice"}
	if m, named := l.match(who, now, time.Time{}); named || m != 0 {
		t.Errorf("an entry of scope tree: match %b, named %v; want none and not named", m, named)
	}
}
