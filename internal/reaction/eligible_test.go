package reaction_test

import (
	"fmt"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/reaction"
)

var now = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func eligibleFacts() (reaction.FindingFacts, reaction.RunFacts) {
	return reaction.FindingFacts{
		Source: controlv1.FindingSource_FINDING_SOURCE_DETERMINISTIC, Verdict: controlv1.FindingVerdict_FINDING_VERDICT_CONFIRMED,
		TenantID: "acme", ProjectID: "orders", RunID: runID,
	}, reaction.RunFacts{
		RunID: runID, TenantID: "acme", ProjectID: "orders", Open: true, ExpiresAt: now.Add(time.Hour),
	}
}

func eligibleRefusals() []error {
	return []error{
		reaction.ErrFindingSource, reaction.ErrFindingVerdict, reaction.ErrRunUnknown, reaction.ErrRunTenant,
		reaction.ErrRunProject, reaction.ErrRunClosed, reaction.ErrRunExpired, reaction.ErrRunExpiry, reaction.ErrClock,
	}
}

// TestEligibleOnlyDeterministicAndConfirmed: of every source and verdict the
// contract names, the zero and a number it does not name among them, only
// source 1 (DETERMINISTIC) with verdict 1 (CONFIRMED) is eligible.
func TestEligibleOnlyDeterministicAndConfirmed(t *testing.T) {
	// A value the contract adds fails here, so its eligibility is decided on
	// purpose rather than by default.
	if len(controlv1.FindingSource_name) != 4 || len(controlv1.FindingVerdict_name) != 4 {
		t.Fatalf("the contract names %d sources and %d verdicts, this test knows 4 and 4",
			len(controlv1.FindingSource_name), len(controlv1.FindingVerdict_name))
	}
	values := []int32{0, 1, 2, 3, 4, -1, 1 << 30}
	for _, source := range values {
		for _, verdict := range values {
			f, r := eligibleFacts()
			f.Source, f.Verdict = controlv1.FindingSource(source), controlv1.FindingVerdict(verdict)
			err := reaction.Eligible(f, r, now)
			what := fmt.Sprintf("source %d, verdict %d", source, verdict)
			switch {
			case source == 1 && verdict == 1:
				if err != nil {
					t.Errorf("%s: %v", what, err)
				}
			case source != 1:
				expectOnly(t, what, err, reaction.ErrFindingSource, eligibleRefusals())
			default:
				expectOnly(t, what, err, reaction.ErrFindingVerdict, eligibleRefusals())
			}
		}
	}
}

func TestEligibleRefusesARunItCannotStop(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*reaction.FindingFacts, *reaction.RunFacts)
		at   time.Time
		want error
	}{
		{"no run found", func(_ *reaction.FindingFacts, r *reaction.RunFacts) { *r = reaction.RunFacts{} }, now, reaction.ErrRunUnknown},
		{"another run's record", func(_ *reaction.FindingFacts, r *reaction.RunFacts) { r.RunID = "run-ffffffffffffffffffffffffffffffff" }, now, reaction.ErrRunUnknown},
		{"a finding naming no run", func(f *reaction.FindingFacts, r *reaction.RunFacts) { f.RunID, r.RunID = "", "" }, now, reaction.ErrRunUnknown},
		{"another tenant's run", func(_ *reaction.FindingFacts, r *reaction.RunFacts) { r.TenantID = "other" }, now, reaction.ErrRunTenant},
		{"no tenant on either", func(f *reaction.FindingFacts, r *reaction.RunFacts) { f.TenantID, r.TenantID = "", "" }, now, reaction.ErrRunTenant},
		{"another project's run", func(_ *reaction.FindingFacts, r *reaction.RunFacts) { r.ProjectID = "billing" }, now, reaction.ErrRunProject},
		{"a finding of another project", func(f *reaction.FindingFacts, _ *reaction.RunFacts) { f.ProjectID = "billing" }, now, reaction.ErrRunProject},
		{"no project on either", func(f *reaction.FindingFacts, r *reaction.RunFacts) { f.ProjectID, r.ProjectID = "", "" }, now, reaction.ErrRunProject},
		{"a closed run", func(_ *reaction.FindingFacts, r *reaction.RunFacts) { r.Open = false }, now, reaction.ErrRunClosed},
		{"a run expiring now", func(_ *reaction.FindingFacts, r *reaction.RunFacts) { r.ExpiresAt = now }, now, reaction.ErrRunExpired},
		{"a run with no expiry copied", func(_ *reaction.FindingFacts, r *reaction.RunFacts) { r.ExpiresAt = time.Time{} }, now, reaction.ErrRunExpiry},
		{"a run expiring past what a record holds", func(_ *reaction.FindingFacts, r *reaction.RunFacts) {
			r.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}, now, reaction.ErrRunExpiry},
		{"the zero time", func(*reaction.FindingFacts, *reaction.RunFacts) {}, time.Time{}, reaction.ErrClock},
		{"a time past what a record holds", func(*reaction.FindingFacts, *reaction.RunFacts) {}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), reaction.ErrClock},
	} {
		f, r := eligibleFacts()
		c.edit(&f, &r)
		expectOnly(t, c.name, reaction.Eligible(f, r, c.at), c.want, eligibleRefusals())
	}
	f, r := eligibleFacts()
	r.ExpiresAt = now.Add(time.Nanosecond)
	if err := reaction.Eligible(f, r, now); err != nil {
		t.Errorf("a run expiring a nanosecond after now: %v", err)
	}
}
