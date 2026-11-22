package stopwrite_test

import (
	"errors"
	"os"
	"testing"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// listMode is the permission bits of the list in dir, read from the file.
func listMode(t *testing.T, dir string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(listPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// TestANewListsModeFollowsItsRoute: a list started or carried under a
// v1alpha3 route, which a plane on another account serves, is 0640; one
// started or carried under a v1alpha1 route is 0600. A signed carry leaves
// the list it carried from 0440, and an unsigned one leaves it as it was.
func TestANewListsModeFollowsItsRoute(t *testing.T) {
	signed := emptyDir(t)
	signedRoute := signedRouteIn(t, signed, 3)
	if _, err := stopwrite.InitSigned(bg, signed, signedRoute, clock0, signer(), 1); err != nil {
		t.Fatalf("InitSigned: %v", err)
	}
	if got := listMode(t, signed); got != 0o640 {
		t.Errorf("InitSigned under a v1alpha3 route left the list %04o, want 0640", got)
	}
	carried := emptyDir(t)
	if _, err := stopwrite.CarrySigned(bg, signed, signedRoute, carried, signedRouteIn(t, carried, 4), clock0, signer(), nil); err != nil {
		t.Fatalf("CarrySigned: %v", err)
	}
	keyed, _ := initDir(t, testRoute(t))
	restored := emptyDir(t)
	if _, err := stopwrite.Carry(bg, keyed, testRoute(t), restored, routeOf(t, 4, false), clock0); err != nil {
		t.Fatalf("Carry: %v", err)
	}
	for _, c := range []struct {
		name string
		dir  string
		want os.FileMode
	}{
		{"CarrySigned from a v1alpha3 route", signed, 0o440},
		{"CarrySigned into a v1alpha3 route", carried, 0o640},
		{"Carry from a v1alpha1 route", keyed, 0o600},
		{"Carry into a v1alpha1 route", restored, 0o600},
	} {
		if got := listMode(t, c.dir); got != c.want {
			t.Errorf("%s left the list %04o, want %04o", c.name, got, c.want)
		}
	}
}

// TestAListTheGroupReadsTakesItsWritersAppends: the writer appends a stop
// and a lift to a 0640 list, which keeps its mode, and a read of any owner
// takes it, while a plane's read under the signed authority refuses it as
// the reading account's own.
func TestAListTheGroupReadsTakesItsWritersAppends(t *testing.T) {
	dir := emptyDir(t)
	r := signedRouteIn(t, dir, 3)
	h, err := stopwrite.InitSigned(bg, dir, r, clock0, signer(), 1)
	if err != nil {
		t.Fatalf("InitSigned: %v", err)
	}
	if n, _, err := appendFinding(bg, dir, r, signedStop(t, "f-1", "run-1", "shop", clock0), clock0); err != nil || n != 2 {
		t.Fatalf("a stop appended to a 0640 list: line %d, %v", n, err)
	}
	if n, err := stopwrite.AppendLift(bg, dir, r, operatorLift(t, dir, h), clock0); err != nil || n != 3 {
		t.Fatalf("a lift appended to a 0640 list: line %d, %v", n, err)
	}
	if got := listMode(t, dir); got != 0o640 {
		t.Errorf("the appends left the list %04o, want 0640", got)
	}
	raw, err := stoplist.ReadAs(dir, stoplist.AnyOwner)
	if err != nil {
		t.Fatalf("ReadAs any owner: %v", err)
	}
	l, err := reaction.Judge(r, reaction.Prefix{}, raw, clock0, poll)
	if err != nil || l.Usage().Lines != 3 || len(l.Entries()) != 0 {
		t.Fatalf("the list read: %v; want three lines and the stop lifted", err)
	}
	if _, err := stoplist.ReadAs(dir, stoplist.OwnedByAnother); !errors.Is(err, stoplist.ErrPlaneOwned) {
		t.Errorf("a signed plane's read of a list its own account owns: %v, want ErrPlaneOwned", err)
	}
}

// operatorLift is a lift of run-1 through line 2 of the list in dir, whose
// header is h, signed by the operator's key.
func operatorLift(t *testing.T, dir string, h reaction.Header) reaction.LiftLine {
	t.Helper()
	lift := reaction.SignedLiftV3{KeyID: operatorID(), PlaneID: "plane-a", ListHead: h.Signed.Digest, Scope: reaction.ScopeRun,
		Subject: "run-1", ThroughLine: 2, TenantID: "acme", Project: "shop", File: listPath(dir)}
	body, err := lift.Payload()
	if err != nil {
		t.Fatal(err)
	}
	return reaction.LiftLine{Scope: reaction.ScopeRun, Subject: "run-1", ThroughLine: 2,
		Envelope: envelopeBy(t, operatorKey(), reaction.SignedLiftPayloadType, body)}
}
