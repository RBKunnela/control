package core_test

import (
	"context"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/pkg/contract"
)

// clockCase is one call decided at a clock the kernel must not judge by.
type clockCase struct {
	name string
	env  *controlv1.ActionEnvelope
	snap *policy.Snapshot
}

// expectClockStop asserts the clock step stopped the decision: INDETERMINATE,
// POLICY_STALE alone, Block under fail-open, STALE, the digest and no rule,
// and an explanation that names why.
func expectClockStop(t *testing.T, clock string, now time.Time, c clockCase, state core.ClockState) {
	t.Helper()
	out, e := explainAgrees(t, failOpen(), fixedClock(now), request(c.env), c.snap)
	check(t, out, expect{verdict: verdictIndeterminate, action: core.Block, codes: []string{codePolicyStale}})
	d := out.Decision
	if d.GetPolicyFreshness() != stale {
		t.Errorf("%s, %s: freshness %s, want STALE", clock, c.name, d.GetPolicyFreshness())
	}
	if d.GetActionDigest() == "" || len(d.GetPolicyRuleIds()) != 0 {
		t.Errorf("%s, %s: digest %q, rules %q; want the digest and no rule", clock, c.name, d.GetActionDigest(), d.GetPolicyRuleIds())
	}
	if e.Clock != state || e.Refusal != nil || e.Rules != nil || e.Delegation.State != core.DelegationNotChecked {
		t.Errorf("%s, %s: explanation %+v; want clock state %d, no refusal, no rule, delegation not checked", clock, c.name, e, state)
	}
}

// TestAClockOutsideTheUsableRangeIsACauseInTheRequest: a reading before
// 1970-01-01T00:00:00Z, the zero time among them, or after the last instant a
// Timestamp holds, is no "now" at all. The decision stops after the digest
// with POLICY_STALE as a cause in the request, so nothing is judged against
// it: no delegation expiry, no freshness, and no fail-open read, whatever the
// effect class, the bundle, or its absence. It carries no decided_at, since
// the reading is no time a record can state.
func TestAClockOutsideTheUsableRangeIsACauseInTheRequest(t *testing.T) {
	expired := readEnvelope()
	expired.Delegation = chain([]string{"read"}, base())
	cases := []clockCase{
		{"a READ under a bundle confirmed at base", readEnvelope(), snapshot(t, allowReads)},
		{"a READ under a bundle confirmed at the zero time", readEnvelope(), snapshotAt(t, document(300, allowReads), time.Time{})},
		{"a READ with no bundle", readEnvelope(), nil},
		{"a WRITE under a bundle confirmed at base", writeEnvelope(), snapshot(t, allowWrites)},
		{"a WRITE under a bundle confirmed at the zero time", writeEnvelope(), snapshotAt(t, document(300, allowWrites), time.Time{})},
		{"a READ whose only hop expired at base", expired, snapshotAt(t, document(300, allowReads), time.Time{})},
	}
	clocks := []struct {
		name string
		now  time.Time
	}{
		{"the zero time", time.Time{}},
		{"1600", time.Date(1600, time.January, 1, 0, 0, 0, 0, time.UTC)},
		{"1677", time.Date(1677, time.June, 1, 0, 0, 0, 0, time.UTC)},
		{"Unix -2^62 seconds", time.Unix(-1<<62, 0)},
		{"one nanosecond before the epoch", time.Date(1969, time.December, 31, 23, 59, 59, 999999999, time.UTC)},
		{"one nanosecond after 9999", time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)},
		{"Unix 2^62 seconds", time.Unix(1<<62, 0)},
	}
	for _, clock := range clocks {
		for _, c := range cases {
			expectClockStop(t, clock.name, clock.now, c, core.ClockOutOfRange)
			if at := decide(kernel(t, failOpen(), fixedClock(clock.now)), request(c.env), c.snap).Decision.GetDecidedAt(); at != nil {
				t.Errorf("%s, %s: decided_at %v, want none", clock.name, c.name, at)
			}
		}
	}
}

// TestAClockBehindAVerifiedTimeIsACauseInTheRequest: a reading in range but
// earlier than the snapshot's not-before, a time the plane verified, is
// provably wrong, and stops the decision as an unusable one does. The
// decision keeps the reading as its decided_at.
func TestAClockBehindAVerifiedTimeIsACauseInTheRequest(t *testing.T) {
	epoch := time.Unix(0, 0)
	behindExpired := readEnvelope()
	behindExpired.Delegation = []*controlv1.Delegation{hop("user-1", "agent-1", []string{"read"}, at(-30*time.Minute))}
	behindExpired.Delegation[0].IssuedAt = timestampOf(at(-2 * time.Hour))
	cases := []struct {
		clockCase
		now time.Time
	}{
		{clockCase{"the epoch, a hop expired by base, a bundle confirmed at base", behindExpired, snapshot(t, allowReads)}, epoch},
		{clockCase{"a nanosecond before the confirmation, a READ", readEnvelope(), snapshot(t, allowReads)}, at(-time.Nanosecond)},
		{clockCase{"a nanosecond before the confirmation, a WRITE", writeEnvelope(), snapshot(t, allowWrites)}, at(-time.Nanosecond)},
	}
	for _, c := range cases {
		expectClockStop(t, "", c.now, c.clockCase, core.ClockBeforeVerified)
		if at := decide(kernel(t, failOpen(), fixedClock(c.now)), request(c.env), c.snap).Decision.GetDecidedAt(); at == nil || !at.AsTime().Equal(c.now) {
			t.Errorf("%s: decided_at %v, want the reading %v", c.name, at, c.now)
		}
	}
}

// TestAClockAtItsBoundsDecides is the accepting twin of each refusal: the
// epoch and the last nanosecond of 9999 are usable readings, and a reading
// equal to the snapshot's not-before is not behind it.
func TestAClockAtItsBoundsDecides(t *testing.T) {
	epoch := time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)
	k := kernel(t, failOpen(), fixedClock(epoch))
	snap := snapshotAt(t, document(300, allowReads), epoch)
	check(t, decide(k, request(readEnvelope()), snap), expect{verdict: verdictAllow, action: core.Execute, codes: []string{codeRuleAllow}})
	expired := readEnvelope()
	expired.Delegation = chain([]string{"read"}, epoch)
	expired.Delegation[0].IssuedAt = timestampOf(epoch)
	check(t, decide(k, request(expired), snap), expect{verdict: verdictDeny, action: core.Block, codes: []string{codeDelegationExpired, codeRuleAllow}})
	check(t, decide(k, request(readEnvelope()), nil), expect{verdict: verdictIndeterminate, action: core.Execute, codes: []string{codePolicyUnavailable, codeFailOpenRead}})

	last := time.Date(9999, time.December, 31, 23, 59, 59, 999999999, time.UTC)
	out := decide(kernel(t, failOpen(), fixedClock(last)), request(readEnvelope()), snapshot(t, allowReads))
	check(t, out, expect{verdict: verdictIndeterminate, action: core.Execute, codes: []string{codePolicyStale, codeRuleAllow, codeFailOpenRead}})
	if err := out.Decision.GetDecidedAt().CheckValid(); err != nil || !out.Decision.GetDecidedAt().AsTime().Equal(last) {
		t.Errorf("decided_at %v (%v), want the last nanosecond of 9999", out.Decision.GetDecidedAt(), err)
	}

	out, e := explainAgrees(t, failOpen(), fixedClock(base()), request(readEnvelope()), snapshot(t, allowReads))
	check(t, out, expect{verdict: verdictAllow, action: core.Execute, codes: []string{codeRuleAllow}})
	if e.Clock != core.ClockUsable {
		t.Errorf("explanation clock state %d, want usable", e.Clock)
	}
	refused := request(readEnvelope())
	refused.Refusal = contract.ErrTooLarge
	if _, e := kernel(t, failOpen(), fixedClock(base())).Explain(context.Background(), refused, nil); e.Clock != core.ClockNotChecked {
		t.Errorf("a refused request's clock state %d, want not checked", e.Clock)
	}
}

// TestAHopIssuedAfterTheReadingIsNotTheClocksFault: a hop's issued_at is the
// producer's unsigned claim and proves nothing about this plane's clock, so a
// chain issued after the reading decides as any other.
func TestAHopIssuedAfterTheReadingIsNotTheClocksFault(t *testing.T) {
	for _, env := range []*controlv1.ActionEnvelope{readEnvelope(), writeEnvelope()} {
		env.Delegation = []*controlv1.Delegation{
			hop("user-1", "svc", []string{"read", "write"}, at(time.Hour)),
			hop("svc", "agent-1", []string{"read", "write"}, at(time.Hour)),
		}
		env.Delegation[0].IssuedAt = timestampOf(at(-time.Minute))
		env.Delegation[1].IssuedAt = timestampOf(at(time.Nanosecond))
		out, e := explainAgrees(t, failOpen(), fixedClock(base()), request(env), snapshot(t, allowReads, allowWrites))
		check(t, out, expect{verdict: verdictAllow, action: core.Execute, codes: []string{codeRuleAllow}})
		if e.Clock != core.ClockUsable || e.Delegation.State != core.DelegationPassed {
			t.Errorf("%s: clock state %d, delegation %+v; want usable and passed", env.GetAction().GetEffect(), e.Clock, e.Delegation)
		}
	}
}

// TestARefusedRequestAtAnUnusableClockReadsStale: the clock step never runs
// for a refused request, yet its freshness is STALE for a reading out of
// range, even under a snapshot confirmed at that same reading.
func TestARefusedRequestAtAnUnusableClockReadsStale(t *testing.T) {
	refused := request(readEnvelope())
	refused.Refusal = contract.ErrTooLarge
	out := decide(kernel(t, failOpen(), fixedClock(time.Time{})), refused, snapshotAt(t, document(300, allowReads), time.Time{}))
	if got := out.Decision.GetPolicyFreshness(); got != stale {
		t.Errorf("freshness %s, want STALE", got)
	}
}

// TestARefusedRequestPastItsBudgetReadsStaleWithoutTheCode: the freshness
// step never runs for a refused request, so a snapshot past its budget makes
// its freshness STALE and adds no POLICY_STALE to the refusal's code.
func TestARefusedRequestPastItsBudgetReadsStaleWithoutTheCode(t *testing.T) {
	refused := request(readEnvelope())
	refused.Refusal = contract.ErrTooLarge
	out := decide(kernelAt(t, failOpen()), refused, snapshotAt(t, document(300, allowReads), at(-300*time.Second-time.Nanosecond)))
	check(t, out, expect{verdict: verdictIndeterminate, action: core.Block, codes: []string{codeLimitExceeded}})
	if got := out.Decision.GetPolicyFreshness(); got != stale {
		t.Errorf("freshness %s, want STALE", got)
	}
}
