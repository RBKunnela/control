package policycompare

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
)

// Run is one comparison's input.
type Run struct {
	Current, Candidate Policy
	Cases              []Case
	// Labels is nil when no labels file was given.
	Labels     *Labels
	Provenance Provenance
	Build      string
}

// Compare evaluates every case on both sides and builds the report. It
// refuses a run with no case, with more than MaxCases, with one id twice or
// with a label naming a case the run does not hold.
func Compare(r Run) (*Report, error) {
	if err := checkRun(r); err != nil {
		return nil, err
	}
	rep := &Report{
		Kind:       ReportKind,
		Simulated:  true,
		Build:      r.Build,
		Current:    policyRef(r.Current),
		Candidate:  policyRef(r.Candidate),
		Provenance: r.Provenance,
		Scope:      scope(r.Labels != nil, r.Provenance.Evidence != nil && !r.Provenance.Evidence.Whole),
		Cases:      make([]CaseRow, 0, len(r.Cases)),
	}
	current, candidate := newLoader(r.Current), newLoader(r.Candidate)
	for _, c := range r.Cases {
		row := compareCase(current, candidate, c)
		if r.Labels != nil {
			if l, ok := r.Labels.ByCase[c.ID]; ok {
				row.Label = &l
			}
		}
		rep.Cases = append(rep.Cases, row)
	}
	rep.Counts = count(rep.Cases)
	return rep, nil
}

func checkRun(r Run) error {
	switch n := len(r.Cases); {
	case n == 0:
		return fmt.Errorf("%w: no case to compare", ErrInput)
	case n > MaxCases:
		return fmt.Errorf("%w: %d cases, at most %d", ErrInput, n, MaxCases)
	}
	ids := make(map[string]bool, len(r.Cases))
	for _, c := range r.Cases {
		if ids[c.ID] {
			return fmt.Errorf("%w: case %s is in the run twice", ErrInput, strconv.Quote(c.ID))
		}
		ids[c.ID] = true
	}
	if r.Labels != nil {
		for _, id := range slices.Sorted(maps.Keys(r.Labels.ByCase)) {
			if !ids[id] {
				return fmt.Errorf("%w: the labels name case %s, which is not in this run", ErrInput, strconv.Quote(id))
			}
		}
	}
	return nil
}

func policyRef(p Policy) PolicyRef {
	ref := p.Bundle.GetRef()
	return PolicyRef{ID: ref.GetBundleId(), Version: ref.GetVersion(), Digest: ref.GetDigest()}
}

// compareCase evaluates one case on both sides, unless it is unknown already,
// and judges what the two decisions can support.
func compareCase(current, candidate *loader, c Case) CaseRow {
	row := CaseRow{ID: c.ID, Source: c.Source, Simulated: true}
	if c.Unknown != "" {
		return unknownRow(row, side{}, side{}, c.Unknown, c.Detail)
	}
	before, after := evaluate(current, c.Input), evaluate(candidate, c.Input)
	if reason, detail := judge(c, before, after); reason != "" {
		return unknownRow(row, before, after, reason, detail)
	}
	row.Before, row.After = decisionRow(before), decisionRow(after)
	row.Change = classify(before, after)
	if row.Change == Unknown {
		return unknownRow(row, before, after, ReasonNotEvaluated, "an action this build does not order")
	}
	return row
}

// judge is why a case both sides decided says nothing about the change, in
// the order of Reasons, or nothing.
func judge(c Case, before, after side) (Reason, string) {
	switch {
	case !before.evaluated:
		return ReasonNotEvaluated, "current: " + before.err
	case !after.evaluated:
		return ReasonNotEvaluated, "candidate: " + after.err
	case before.stale || after.stale:
		return ReasonFreshnessNotHeld, staleDetail(before.stale, after.stale)
	case before.external || after.external:
		return ReasonExternalAnswerNeeded, "a rule reads the external decision point's answer and stays undetermined on what the case gives it"
	case len(before.missing) > 0 || len(after.missing) > 0:
		return ReasonMissingFacts, "the decision reads " + strings.Join(union(before.missing, after.missing), ", ") + ", which the case does not hold"
	case c.Source == SourceEvidence:
		return crossCheck(c.recorded, before, after)
	}
	return "", ""
}

func staleDetail(before, after bool) string {
	which := "both policies are"
	switch {
	case !after:
		which = "the current policy is"
	case !before:
		which = "the candidate policy is"
	}
	return which + " stale at the case's decided_at, so a stale side's decision shows its staleness, not its rules"
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// unknownRow is a row with its reason and both sides' missing facts, and no
// verdict on either side.
func unknownRow(row CaseRow, before, after side, reason Reason, detail string) CaseRow {
	row.Before, row.After = withheldRow(before), withheldRow(after)
	row.Change = Unknown
	row.UnknownReason, row.UnknownDetail = &reason, &detail
	return row
}

func withheldRow(s side) SideRow {
	return SideRow{Evaluated: s.evaluated, MissingFacts: nonNil(s.missing)}
}

func decisionRow(s side) SideRow {
	verdict, action := verdictName(s.verdict), actionName(s.action)
	obligations := make([]ObligationRow, 0, len(s.obligations))
	for _, o := range s.obligations {
		params := maps.Clone(o.GetParams())
		if params == nil {
			params = map[string]string{}
		}
		obligations = append(obligations, ObligationRow{Type: o.GetType(), Params: params, Advisory: o.GetAdvisory()})
	}
	return SideRow{Evaluated: true, Verdict: &verdict, Action: &action, Codes: nonNil(s.codes), Obligations: obligations,
		MissingFacts: nonNil(s.missing)}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
}

func verdictName(v controlv1.Verdict) string {
	if name, ok := controlv1.Verdict_name[int32(v)]; ok {
		return strings.TrimPrefix(name, "VERDICT_")
	}
	return fmt.Sprintf("VERDICT(%d)", v)
}

// actionNames spell the enforcement actions as a policy test case does.
var actionNames = map[core.EnforcementAction]string{
	core.Block:                  "Block",
	core.Execute:                "Execute",
	core.ExecuteWithObligations: "ExecuteWithObligations",
	core.AwaitApproval:          "AwaitApproval",
}

func actionName(a core.EnforcementAction) string {
	if name, ok := actionNames[a]; ok {
		return name
	}
	return fmt.Sprintf("EnforcementAction(%d)", a)
}

// notSeen is what no case of a comparison can show.
var notSeen = []string{
	"live traffic: every result is the kernel's evaluation of a case, not a call that ran",
	"the arguments of an evidence case: the evidence holds their hash, so the case holds {}",
	"the flow of the run behind an evidence case",
	"an external decision point's answer, unless a case file states one",
	"approvals: none is read, asked for or consumed",
	"the plane's own settings behind an evidence case: its staleness budget, fail_open_read and the obligations it applies",
}

// notSeenAfterAGap is what an export that is not whole cannot show.
const notSeenAfterAGap = "events after a gap: in an export that is not whole, a request that looks whole may have lost later events"

func scope(labelled, notWhole bool) Scope {
	independence := "no labels"
	if labelled {
		independence = "declared, not verified"
	}
	seen := slices.Clone(notSeen)
	if notWhole {
		seen = append(seen, notSeenAfterAGap)
	}
	return Scope{
		Evaluation:           "the kernel's own evaluation, Kernel.Explain, in ENFORCE mode, on each policy signed in memory",
		NotSeen:              seen,
		LabellerIndependence: independence,
	}
}
