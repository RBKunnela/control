package reaction_test

import (
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

// levelVoucher is a rosterVoucher in which a key named in operateOnly holds
// the operate grant and not admin: it signs headers and lifts, and no route.
type levelVoucher struct {
	*rosterVoucher
	operateOnly map[string]bool
}

func (v levelVoucher) Vouch(kind reaction.SignedKind, env reaction.Envelope) (reaction.Signer, error) {
	if kind == reaction.VouchRoute && v.operateOnly[env.Signatures[0].KeyID] {
		v.asked++
		return reaction.Signer{}, errDenied
	}
	return v.rosterVoucher.Vouch(kind, env)
}

// routeUnvouched is the cause of a route its signer no longer vouches for.
const routeUnvouched = reaction.Cause("a route no operator vouches for")

// TestARosterThatRevokesTheRoutesAdminTakesTheClearAway: alice signs the
// route as admin and bob the header and the lift; a roster that revokes
// alice, or keeps her at operate only, makes the next poll of the same list
// unknown although bob's documents are still taken.
func TestARosterThatRevokesTheRoutesAdminTakesTheClearAway(t *testing.T) {
	for _, c := range []struct {
		name   string
		demote func(levelVoucher)
	}{
		{"alice revoked", func(v levelVoucher) { v.revoked[keyIDOf(operatorKey())] = true }},
		{"alice kept at operate", func(v levelVoucher) { v.operateOnly[keyIDOf(operatorKey())] = true }},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := levelVoucher{rosterVoucher: newRosterVoucher(), operateOnly: map[string]bool{}}
			r := vouchedRoute(t, v)
			header, head := signedHeaderLine(t, r, headerOpts{key: strangerKey()})
			content := joinLines(header, signedStop(t, sProject), liftOf(t, head, strangerKey(), 2))
			s := reaction.Snapshot{}.Next(r, content, sNow, time.Second)
			if s.State() != reaction.Clear || s.Header().Signed.KeyID != keyIDOf(strangerKey()) {
				t.Fatalf("the list bob wrote: %v %q %s", s.State(), s.Cause(), s.Detail())
			}
			c.demote(v)
			expectUnknown(t, c.name, s.Next(r, content, sNow.Add(time.Second), time.Second), routeUnvouched)
		})
	}
}

// TestAFirstReadUnderARouteItsAdminLostIsUnknown: the route verified, then
// its admin revoked before the first read, makes that read unknown.
func TestAFirstReadUnderARouteItsAdminLostIsUnknown(t *testing.T) {
	v := newRosterVoucher()
	r := vouchedRoute(t, v)
	header, _ := signedHeaderLine(t, r, headerOpts{key: strangerKey()})
	v.revoked[keyIDOf(operatorKey())] = true
	expectUnknown(t, "the first read", reaction.Snapshot{}.Next(r, joinLines(header, signedStop(t, sProject)), sNow, time.Second), routeUnvouched)
}
