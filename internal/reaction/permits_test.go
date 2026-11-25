package reaction_test

import (
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

var created = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// claimOf is a claim of the route's first rule, STEP_OUTSIDE_PROCEDURE with
// a lifetime of an hour, lasting span.
func claimOf(span time.Duration) reaction.StopClaim {
	return reaction.StopClaim{
		TenantID: "acme", ProcedureID: "refund", ProcedureVersion: "3", ProcedureDigest: procDigest,
		RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1", CreatedAt: created, ExpiresAt: created.Add(span),
	}
}

func permitRefusals() []error {
	return []error{reaction.ErrClaimTenant, reaction.ErrClaimRule, reaction.ErrClaimTimes, reaction.ErrClaimLifetime}
}

func TestPermits(t *testing.T) {
	r := validRoute(t)
	if err := r.Permits(claimOf(time.Hour)); err != nil {
		t.Fatalf("a stop of the rule's whole lifetime: %v", err)
	}
	if err := r.Permits(claimOf(time.Second)); err != nil {
		t.Fatalf("a stop of a second: %v", err)
	}
	// A rule with no lifetime of its own is bounded by the longest a run
	// lives, 720 hours.
	noLifetime := claimOf(720 * time.Hour)
	noLifetime.RuleID = "RESOURCE_OUTSIDE_RUN"
	if err := r.Permits(noLifetime); err != nil {
		t.Fatalf("a stop of 720 hours under a rule with no lifetime: %v", err)
	}
	noLifetime.ExpiresAt = noLifetime.ExpiresAt.Add(time.Nanosecond)
	expectOnly(t, "a stop a nanosecond over 720 hours under a rule with no lifetime", r.Permits(noLifetime), reaction.ErrClaimLifetime, permitRefusals())
	noLifetime.ExpiresAt = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	expectOnly(t, "a stop to the end of what a record holds under a rule with no lifetime", r.Permits(noLifetime), reaction.ErrClaimLifetime, permitRefusals())
	for _, c := range []struct {
		name string
		edit func(*reaction.StopClaim)
		want error
	}{
		{"another tenant", func(c *reaction.StopClaim) { c.TenantID = "other" }, reaction.ErrClaimTenant},
		{"no tenant", func(c *reaction.StopClaim) { c.TenantID = "" }, reaction.ErrClaimTenant},
		{"a tenant in capitals", func(c *reaction.StopClaim) { c.TenantID = "ACME" }, reaction.ErrClaimTenant},
		{"another procedure", func(c *reaction.StopClaim) { c.ProcedureID = "refunds" }, reaction.ErrClaimRule},
		{"another procedure version", func(c *reaction.StopClaim) { c.ProcedureVersion = "4" }, reaction.ErrClaimRule},
		{"another procedure digest", func(c *reaction.StopClaim) { c.ProcedureDigest = strings.Replace(procDigest, "0", "1", 1) }, reaction.ErrClaimRule},
		{"a rule the route lacks", func(c *reaction.StopClaim) { c.RuleID = "REPEATED_DENIAL" }, reaction.ErrClaimRule},
		{"another rule version", func(c *reaction.StopClaim) { c.RuleVersion = "2" }, reaction.ErrClaimRule},
		{"one rule's procedure with another's id", func(c *reaction.StopClaim) { c.RuleID = "RESOURCE_OUTSIDE_RUN"; c.RuleVersion = "2" }, reaction.ErrClaimRule},
		{"a span one second over", func(c *reaction.StopClaim) { c.ExpiresAt = c.CreatedAt.Add(time.Hour + time.Second) }, reaction.ErrClaimLifetime},
		{"a span one nanosecond over", func(c *reaction.StopClaim) { c.ExpiresAt = c.CreatedAt.Add(time.Hour + 1) }, reaction.ErrClaimLifetime},
		{"expiry at creation", func(c *reaction.StopClaim) { c.ExpiresAt = c.CreatedAt }, reaction.ErrClaimTimes},
		{"expiry before creation", func(c *reaction.StopClaim) { c.ExpiresAt = c.CreatedAt.Add(-time.Second) }, reaction.ErrClaimTimes},
		{"no creation", func(c *reaction.StopClaim) { c.CreatedAt = time.Time{} }, reaction.ErrClaimTimes},
		{"no expiry", func(c *reaction.StopClaim) { c.ExpiresAt = time.Time{} }, reaction.ErrClaimTimes},
		{"an expiry past what a record holds", func(c *reaction.StopClaim) { c.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, reaction.ErrClaimTimes},
	} {
		claim := claimOf(time.Hour)
		c.edit(&claim)
		expectOnly(t, c.name, r.Permits(claim), c.want, permitRefusals())
	}
}

func TestTheZeroRoutePermitsNothing(t *testing.T) {
	var zero reaction.Route
	expectOnly(t, "the zero claim", zero.Permits(reaction.StopClaim{}), reaction.ErrClaimTenant, permitRefusals())
	claim := claimOf(time.Minute)
	claim.TenantID = ""
	expectOnly(t, "a claim with no tenant", zero.Permits(claim), reaction.ErrClaimTenant, permitRefusals())
}

// A rule's lifetime binds at both of its bounds: 60 seconds and the longest
// run lifetime, 720 hours.
func TestPermitsAtTheLifetimeBounds(t *testing.T) {
	for _, c := range []struct {
		seconds string
		life    time.Duration
	}{{"60", time.Minute}, {"2592000", 720 * time.Hour}} {
		r, err := reaction.ParseRoute([]byte(strings.Replace(withLift(routeTemplate), "3600", c.seconds, 1)))
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Permits(claimOf(c.life)); err != nil {
			t.Errorf("a stop of exactly %s: %v", c.life, err)
		}
		expectOnly(t, "a stop a second longer than "+c.seconds+"s", r.Permits(claimOf(c.life+time.Second)), reaction.ErrClaimLifetime, permitRefusals())
	}
}
