package operators_test

import (
	"errors"
	"testing"
	"time"

	"github.com/guardana/control/internal/operators"
	"github.com/guardana/control/internal/trust"
)

func wantPerm(t *testing.T, what string, got operators.Permission, state operators.PermState, cause operators.Cause) {
	t.Helper()
	if got.State() != state || got.Cause() != cause {
		t.Errorf("%s = state %d cause %q, want state %d cause %q", what, got.State(), got.Cause(), state, cause)
	}
	if state != operators.PermPermitted && (got.Grant() != trust.Grant{} || got.RosterSerial() != 0) {
		t.Errorf("%s carries grant %+v though not permitted", what, got.Grant())
	}
}

func approve(tenant, project string) operators.Request {
	return operators.Request{Act: operators.ActApprove, Tenant: tenant, Project: project}
}

// TestTwoOperatorsEachActOnlyWhereTheirGrantsReach is the two-user case:
// alice operates A, bob operates B and only reads A.
func TestTwoOperatorsEachActOnlyWhereTheirGrantsReach(t *testing.T) {
	w := newWorld(t, standard())
	z := authorizer(t, w.roster, operators.Bounds{})
	alice, bob, carol := authenticated(t, w, "alice"), authenticated(t, w, "bob"), authenticated(t, w, "carol")
	got := z.Authorize(t.Context(), alice, approve("t1", "A"))
	wantPerm(t, "alice on A", got, operators.PermPermitted, operators.CauseNone)
	if got.Grant() != (trust.Grant{Tenant: "t1", Project: "A", Level: trust.LevelOperate}) || got.RosterSerial() != 1 {
		t.Errorf("alice's permission = %+v at serial %d", got.Grant(), got.RosterSerial())
	}
	wantPerm(t, "bob, who reads A, on A", z.Authorize(t.Context(), bob, approve("t1", "A")), operators.PermDenied, operators.CauseNoGrant)
	wantPerm(t, "bob on B", z.Authorize(t.Context(), bob, approve("t1", "B")), operators.PermPermitted, operators.CauseNone)
	wantPerm(t, "alice on B", z.Authorize(t.Context(), alice, approve("t1", "B")), operators.PermDenied, operators.CauseNoGrant)
	wantPerm(t, "alice on A of another tenant", z.Authorize(t.Context(), alice, approve("t2", "A")), operators.PermDenied, operators.CauseNoGrant)
	wantPerm(t, "carol, who administers A, on A", z.Authorize(t.Context(), carol, approve("t1", "A")), operators.PermPermitted, operators.CauseNone)
}

func TestARequestNamesOneTenantAndOneProject(t *testing.T) {
	w := newWorld(t, standard())
	z := authorizer(t, w.roster, operators.Bounds{})
	alice := authenticated(t, w, "alice")
	for name, req := range map[string]operators.Request{
		"an empty project":  approve("t1", ""),
		"an empty tenant":   approve("", "A"),
		"both empty":        approve("", ""),
		"a padded project":  approve("t1", " A"),
		"a project of a NL": approve("t1", "A\n"),
	} {
		wantPerm(t, name, z.Authorize(t.Context(), alice, req), operators.PermDenied, operators.CauseScope)
	}
	wantPerm(t, "a project that reads as a pattern", z.Authorize(t.Context(), alice, approve("t1", "*")), operators.PermDenied, operators.CauseNoGrant)
	wantPerm(t, "an act this build lacks", z.Authorize(t.Context(), alice, operators.Request{Act: "unknown", Tenant: "t1", Project: "A"}), operators.PermDenied, operators.CauseAct)
}

func TestOnlyAnAuthenticatedOperatorIsAuthorized(t *testing.T) {
	w := newWorld(t, standard())
	z := authorizer(t, w.roster, operators.Bounds{})
	refused := authenticator(t, w.roster, operators.Bounds{}).Authenticate(t.Context(), operators.ActApprove, answer(t, "mallory"))
	wantPerm(t, "a refused authentication", z.Authorize(t.Context(), refused, approve("t1", "A")), operators.PermDenied, operators.CauseNotAuthenticated)
	var zero operators.Authentication
	wantPerm(t, "the zero authentication", z.Authorize(t.Context(), zero, approve("t1", "A")), operators.PermUnavailable, operators.CauseNotAuthenticated)
	var none operators.Permission
	if none.State() != operators.PermUnavailable {
		t.Errorf("the zero permission's state = %d", none.State())
	}
}

func TestAKeyRevokedAfterItsAuthenticationPermitsNothing(t *testing.T) {
	w := newWorld(t, standard())
	z := authorizer(t, w.roster, operators.Bounds{})
	alice, bob := authenticated(t, w, "alice"), authenticated(t, w, "bob")
	w.write(t, 2, []any{entry("bob", "bob", grant{"t1", "B", "operate"}), entry("alice", "mallory", grant{"t1", "A", "operate"})})
	wantPerm(t, "alice's key given to another subject", z.Authorize(t.Context(), alice, approve("t1", "A")), operators.PermDenied, operators.CauseRevoked)
	w.write(t, 3, []any{entry("bob", "bob", grant{"t1", "B", "operate"})})
	wantPerm(t, "alice's key removed", z.Authorize(t.Context(), alice, approve("t1", "A")), operators.PermDenied, operators.CauseRevoked)
	got := z.Authorize(t.Context(), bob, approve("t1", "B"))
	wantPerm(t, "the control, bob still in the roster", got, operators.PermPermitted, operators.CauseNone)
	if got.RosterSerial() != 3 {
		t.Errorf("bob's permission is from serial %d, want 3", got.RosterSerial())
	}
	w.write(t, 4, []any{entry("bob", "bob", grant{"t1", "B", "read"})})
	wantPerm(t, "bob lowered to read after his answer", z.Authorize(t.Context(), bob, approve("t1", "B")), operators.PermDenied, operators.CauseNoGrant)
}

func TestAnAuthorizerWithNoRosterAnswerIsUnavailable(t *testing.T) {
	w := newWorld(t, standard())
	alice := authenticated(t, w, "alice")
	quick := operators.Bounds{Timeout: 50 * time.Millisecond}
	cases := []struct {
		name   string
		roster *fakeRoster
		want   operators.Cause
	}{
		{"a roster that is unavailable", &fakeRoster{answer: trust.Unavailable(trust.CauseExpired)}, operators.CauseRosterUnavailable},
		{"a roster that answers the zero answer", &fakeRoster{}, operators.CauseRosterUnavailable},
		{"a roster that never answers", &fakeRoster{release: make(chan struct{}), deaf: true}, operators.CauseLate},
	}
	for _, c := range cases {
		wantPerm(t, c.name, authorizer(t, c.roster, quick).Authorize(t.Context(), alice, approve("t1", "A")), operators.PermUnavailable, c.want)
		if c.roster.release != nil {
			close(c.roster.release)
		}
	}
	unknown := &fakeRoster{answer: trust.Answer{}}
	if _, err := operators.NewAuthorizer("authzen", unknown, operators.Bounds{}); !errors.Is(err, operators.ErrUnknownKind) {
		t.Errorf("an authorizer kind this build lacks = %v", err)
	}
	if _, err := operators.NewAuthorizer("roster", nil, operators.Bounds{}); !errors.Is(err, operators.ErrConfig) {
		t.Errorf("an authorizer with no roster = %v", err)
	}
}
