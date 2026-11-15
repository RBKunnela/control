package reaction

import (
	"context"
	"errors"
	"testing"
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

// TestARunLiftNamingNoRunIsRefused: a lift line of scope run ends a run's
// stops only by its subject alone; one naming no subject, or a run_id beside
// its subject, ends nothing and is refused.
func TestARunLiftNamingNoRunIsRefused(t *testing.T) {
	if run, err := liftedRun(LiftLine{Scope: ScopeRun, Subject: "run-1"}); err != nil || run != "run-1" {
		t.Fatalf("a lift of run-1: %q, %v", run, err)
	}
	for _, l := range []LiftLine{{Scope: ScopeRun}, {Scope: ScopeRun, Subject: "run-1", RunID: "run-1"}, {Scope: ScopeRun, RunID: "run-1"}} {
		if run, err := liftedRun(l); err == nil || run != "" {
			t.Errorf("a lift line %+v: %q, %v; want a refusal", l, run, err)
		}
	}
	if _, err := liftedRun(LiftLine{}); err == nil {
		t.Error("the zero lift line was taken")
	}
}
