package supervise_test

import (
	"slices"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/supervise"
	"google.golang.org/protobuf/proto"
)

// askedAgain is a's trail up to its approval's expiry, then a second
// request for approval nobody has answered.
func askedAgain(a act) []*controlv1.Event {
	evs := a.ending("expired").events()[:4]
	ask := proto.CloneOf(evs[2])
	ask.EventId, ask.PrevEventId, ask.OccurredAt = a.req+"-e5", evs[3].GetEventId(), at(a.at+4*time.Second)
	return append(evs, ask)
}

// conflicting is a's trail with one event of other content under its id,
// which puts the request in doubt when both are read.
func conflicting(a act) supervise.Export {
	x := acts(a)
	x.Events[1].OccurredAt = at(time.Hour)
	return x
}

// TestWhatAnApprovalLeavesOfARetry: only an approval the approvals store
// granted, in a trail not in doubt, takes a retry away; a rejection does
// not, a hold that lapsed is no longer waiting, and one asked for again is.
func TestWhatAnApprovalLeavesOfARetry(t *testing.T) {
	rejected, approved, expired := again(), again(), again().ending("expired")
	rejected.approval = controlv1.ApprovalState_APPROVAL_STATE_REJECTED
	approved.approval = controlv1.ApprovalState_APPROVAL_STATE_APPROVED
	for name, c := range map[string]struct {
		exports []supervise.Export
		want    string
	}{
		"rejected":                {[]supervise.Export{acts(denial(), rejected)}, "FINDING_VERDICT_SUSPECTED"},
		"approved, in doubt":      {[]supervise.Export{acts(denial(), approved), conflicting(approved)}, "FINDING_VERDICT_INDETERMINATE"},
		"lapsed and not closed":   {[]supervise.Export{acts(denial()), {Whole: true, Events: expired.events()[:4]}}, "FINDING_VERDICT_SUSPECTED"},
		"asked again":             {[]supervise.Export{acts(denial()), {Whole: true, Events: askedAgain(again())}}, "FINDING_VERDICT_INDETERMINATE"},
		"waiting, beside one ran": {[]supervise.Export{acts(denial()), acts(again().ending("held"), ranLater())}, "FINDING_VERDICT_SUSPECTED"},
	} {
		t.Run(name, func(t *testing.T) {
			res := retrySupervise(t, source(), c.exports...)
			if got := verdicts(res, ruleArgs); !slices.Equal(got, []string{runID + " " + c.want}) {
				t.Fatalf("findings %q, want %s:\n%s", got, c.want, dump(res.Findings))
			}
		})
	}
}

// ranLater is r2, the denied refund with third arguments at thirty seconds.
func ranLater() act {
	r := again()
	r.req, r.at, r.hash = "r2", 30*time.Second, hashOf('c')
	return r
}

// TestOnlyACopyPutsAnEventInAnExport: exports that list a denial and a
// retry both ways still hold both, and the plane's times suggest the retry;
// an event of other content under the retry's id puts nothing beside the
// denial, and leaves the retry in doubt.
func TestOnlyACopyPutsAnEventInAnExport(t *testing.T) {
	forged := again().events()
	forged[0].GetProposed().Arguments.CanonicalHash = hashOf('f')
	for name, c := range map[string]struct {
		exports []supervise.Export
		want    string
	}{
		"both ways": {[]supervise.Export{acts(denial(), again()), acts(again(), denial())}, "FINDING_VERDICT_SUSPECTED"},
		"a conflicting copy before the denial": {[]supervise.Export{acts(denial()), acts(again()),
			{Whole: true, Events: slices.Concat(forged[:1], denial().events())}}, "FINDING_VERDICT_INDETERMINATE"},
	} {
		t.Run(name, func(t *testing.T) {
			res := retrySupervise(t, source(), c.exports...)
			if got := verdicts(res, ruleArgs); !slices.Equal(got, []string{runID + " " + c.want}) {
				t.Fatalf("findings %q:\n%s", got, dump(res.Findings))
			}
		})
	}
}

// TestACallInDoubtBesideTwoResourcesIsNotCited: a run's call in doubt adds
// nothing to two resources its coherent calls show, and is left out of what
// the confirmed finding cites.
func TestACallInDoubtBesideTwoResourcesIsNotCited(t *testing.T) {
	odd := lookupOf("a3", 30*time.Second, orderNo("45")).in(childRun)
	res := supervise02(t, siblings(), acts(lookupOf("a1", 0, orderNo("42")).in(childRun),
		lookupOf("a2", 5*time.Second, orderNo("44")).in(childRun), odd), conflicting(odd))
	got := only(res, ruleResource)
	if len(got) != 1 || got[0].GetFinding().GetVerdict() != confirmed || citedEvents(got[0]) != "a1-e1 a2-e1" {
		t.Fatalf("findings:\n%s", dump(res.Findings))
	}
}

// TestTheOrderExportsAreReadInDecidesNoRetry: two denials, each retried in
// its own export, give the same findings in either reading order.
func TestTheOrderExportsAreReadInDecidesNoRetry(t *testing.T) {
	c1 := manual()
	c1.req, c1.outcome, c1.res = "c1", "deny", orderNo("43")
	c2 := c1
	c2.req, c2.outcome, c2.hash, c2.at = "c2", "", hashOf('b'), 30*time.Second
	a, b := acts(denial(), again()), acts(c1, c2)
	ab := only(retrySupervise(t, source(), a, b), ruleArgs)
	ba := only(retrySupervise(t, source(), b, a), ruleArgs)
	if len(ab) != 2 || len(ba) != 2 {
		t.Fatalf("%d and %d findings", len(ab), len(ba))
	}
	for i := range ab {
		if !proto.Equal(ab[i], ba[i]) || ab[i].GetFinding().GetFindingId() != id02(ruleArgs, []string{"c1", "d1"}[i], runID) {
			t.Fatalf("finding %d:\n%s\n%s", i, dump(ab), dump(ba))
		}
	}
}

// TestADenialIsNoRetryOfItself: a denial whose proposal and decision two
// exports hold with no time, so neither order is told, is still one call.
func TestADenialIsNoRetryOfItself(t *testing.T) {
	d := denial()
	d.hash = ""
	evs := d.events()
	for _, ev := range evs {
		ev.OccurredAt = nil
	}
	res := retrySupervise(t, source(), supervise.Export{Whole: true, Events: evs[:1]}, supervise.Export{Whole: true, Events: evs[1:]})
	if got := verdicts(res, ruleArgs); len(got) != 0 {
		t.Fatalf("findings %q:\n%s", got, dump(res.Findings))
	}
}

// TestTheStrongestRetryDecidesTheFinding: a retry one export holds beside
// the denial suggests no more than one another export holds, and a retry in
// doubt, or a report in doubt, cannot weaken a told one; each finding cites
// what carries its verdict.
func TestTheStrongestRetryDecidesTheFinding(t *testing.T) {
	doubtedReport := source(ob{id: "obs-1", name: "issue_refund", at: 20 * time.Second, stage: observev1.Stage_STAGE_STARTED},
		ob{id: "obs-2", name: "issue_refund", at: 25 * time.Second}, ob{id: "obs-2", name: "issue_refund", at: 26 * time.Second})
	for name, c := range map[string]struct {
		exports              []supervise.Export
		src                  supervise.Source
		rule, verdict, cites string
	}{
		"one export beside another": {[]supervise.Export{acts(denial(), again()), acts(ranLater())}, source(),
			ruleArgs, "FINDING_VERDICT_SUSPECTED", "d1-e2 r1-e1 r2-e1"},
		"told beside in doubt": {[]supervise.Export{acts(denial(), again(), ranLater()), conflicting(ranLater())}, source(),
			ruleArgs, "FINDING_VERDICT_SUSPECTED", "d1-e2 r1-e1"},
		"a report beside one in doubt": {[]supervise.Export{acts(denial())}, doubtedReport,
			ruleAround, "FINDING_VERDICT_SUSPECTED", "d1-e2 obs-1"},
	} {
		t.Run(name, func(t *testing.T) {
			res := retrySupervise(t, c.src, c.exports...)
			got := only(res, c.rule)
			if len(got) != 1 || got[0].GetFinding().GetVerdict().String() != c.verdict || citedEvents(got[0]) != c.cites {
				t.Fatalf("want one %s citing %q:\n%s", c.verdict, c.cites, dump(res.Findings))
			}
		})
	}
}
