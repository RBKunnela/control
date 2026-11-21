package policycompare

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy/rules"
)

// Export is an evidence export as the caller read it.
type Export struct {
	Events   []*controlv1.Event
	Whole    bool
	NotWhole string
}

// evidenceArguments are the authorized arguments of every evidence case:
// the evidence holds a hash of the arguments, never the arguments.
const evidenceArguments = "{}"

const codePolicyStale = "POLICY_STALE"

// request is what an export holds of one request.
type request struct {
	proposals []*controlv1.ActionEnvelope
	decisions []*controlv1.Decision
	// proposedAt and decidedAt are the export positions of the last
	// proposal and decision.
	proposedAt, decidedAt int
}

// EvidenceCases is one case per request the export names, in the order the
// export first names each. A request becomes a case to evaluate only with
// exactly one ACTION_PROPOSED and exactly one POLICY_DECIDED, both of a major
// this build reads and naming the request, the proposal first, a decision
// made on currentDigest and recorded FRESH, and both of its times recorded;
// any other is unknown with its reason. Events naming no request, and findings and
// policy reloads, make no request.
func EvidenceCases(x Export, currentDigest string) []Case {
	var order []string
	requests := map[string]*request{}
	for at, ev := range x.Events {
		id := ev.GetRequestId()
		if id == "" || ev.GetKind() == controlv1.EventKind_EVENT_KIND_FINDING_RAISED ||
			ev.GetKind() == controlv1.EventKind_EVENT_KIND_POLICY_RELOADED {
			continue
		}
		r, seen := requests[id]
		if !seen {
			r = &request{}
			requests[id] = r
			order = append(order, id)
		}
		// An event of either kind without its payload names the request and
		// holds nothing to decide it on, so it leaves the request incomplete.
		switch ev.GetKind() {
		case controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED:
			if env := ev.GetProposed(); env != nil {
				r.proposals, r.proposedAt = append(r.proposals, env), at
			}
		case controlv1.EventKind_EVENT_KIND_POLICY_DECIDED:
			if d := ev.GetDecision(); d != nil {
				r.decisions, r.decidedAt = append(r.decisions, d), at
			}
		}
	}
	cases := make([]Case, 0, len(order))
	for _, id := range order {
		cases = append(cases, evidenceCase(id, requests[id], x, currentDigest))
	}
	return cases
}

func evidenceCase(id string, r *request, x Export, currentDigest string) Case {
	c := Case{ID: "request:" + id, Source: SourceEvidence}
	unknown := func(reason Reason, detail string) Case {
		c.Unknown, c.Detail = reason, detail
		return c
	}
	if reason, detail := requestShape(r, x); reason != "" {
		return unknown(reason, detail)
	}
	if reason, detail := heldTogether(id, r); reason != "" {
		return unknown(reason, detail)
	}
	d := r.decisions[0]
	if reason, detail := recordedDecision(d, currentDigest); reason != "" {
		return unknown(reason, detail)
	}
	hash, err := canon.ArgumentsHashV1([]byte(evidenceArguments))
	if err != nil {
		return unknown(ReasonNotEvaluated, "the arguments hash of {}: "+err.Error())
	}
	env := proto.CloneOf(r.proposals[0])
	env.Arguments = &controlv1.Arguments{CanonicalHash: hash}
	c.Input = Input{
		Envelope:       env,
		AuthorizedArgs: []byte(evidenceArguments),
		Options:        evidenceOptions(),
		LoadedAt:       d.GetPolicyLoadedAt().AsTime(),
		DecidedAt:      d.GetDecidedAt().AsTime(),
	}
	c.recorded = d
	return c
}

// requestShape names why a request's events cannot be one case, or nothing
// when they hold exactly one proposal and one decision.
func requestShape(r *request, x Export) (Reason, string) {
	switch {
	case len(r.decisions) > 1:
		return ReasonSeveralDecisions, fmt.Sprintf("%d POLICY_DECIDED events", len(r.decisions))
	case (len(r.proposals) == 0 || len(r.decisions) == 0) && !x.Whole:
		return ReasonExportNotWhole, fmt.Sprintf("%d ACTION_PROPOSED and %d POLICY_DECIDED events in an export that is not whole: %s",
			len(r.proposals), len(r.decisions), x.NotWhole)
	case len(r.proposals) != 1 || len(r.decisions) != 1:
		return ReasonIncompleteRequest, fmt.Sprintf("%d ACTION_PROPOSED and %d POLICY_DECIDED events, want one each",
			len(r.proposals), len(r.decisions))
	}
	return "", ""
}

// heldTogether names why a request's one proposal and one decision are not
// one request's, or nothing: both of a major this build reads, read before
// anything else of them, both naming the request their events name, and the
// proposal before the decision.
func heldTogether(id string, r *request) (Reason, string) {
	env, d := r.proposals[0], r.decisions[0]
	switch {
	case !readable(env.GetSchemaVersion()):
		return ReasonVersionNotRead, fmt.Sprintf("the proposal's schema_version %s: this build reads major %s",
			strconv.Quote(env.GetSchemaVersion()), readMajor())
	case !readable(d.GetSchemaVersion()):
		return ReasonVersionNotRead, fmt.Sprintf("the decision's schema_version %s: this build reads major %s",
			strconv.Quote(d.GetSchemaVersion()), readMajor())
	case env.GetRequestId() != id || d.GetRequestId() != id:
		return ReasonIncompleteRequest, fmt.Sprintf("the proposal names request %s and the decision %s",
			strconv.Quote(env.GetRequestId()), strconv.Quote(d.GetRequestId()))
	case r.decidedAt < r.proposedAt:
		return ReasonIncompleteRequest, "the decision comes before the proposal"
	}
	return "", ""
}

// readable holds for a MAJOR.MINOR version in decimal on the major of the
// generated contract this build carries; a higher minor is read.
func readable(version string) bool {
	major, minor, ok := strings.Cut(version, ".")
	return ok && decimal(major) && decimal(minor) && major == readMajor()
}

func decimal(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

func readMajor() string {
	pkg := string((&controlv1.Decision{}).ProtoReflect().Descriptor().ParentFile().Package())
	return strings.TrimPrefix(pkg[strings.LastIndex(pkg, ".")+1:], "v")
}

// recordedDecision names why a recorded decision cannot be replayed on the
// current policy, or nothing when it can. Only a decision recorded FRESH is
// taken as fresh.
func recordedDecision(d *controlv1.Decision, currentDigest string) (Reason, string) {
	switch {
	case d.GetPolicyBundleDigest() != currentDigest:
		return ReasonHistoricPolicyMissing, "the decision names policy " + d.GetPolicyBundleDigest()
	case d.GetPolicyFreshness() == controlv1.PolicyFreshness_POLICY_FRESHNESS_STALE || slices.Contains(d.GetReasonCodes(), codePolicyStale):
		return ReasonRecordedStale, "the decision was made on a stale policy"
	case d.GetPolicyFreshness() != controlv1.PolicyFreshness_POLICY_FRESHNESS_FRESH:
		return ReasonIncompleteRequest, "the decision records its policy's freshness as " + d.GetPolicyFreshness().String() + ", not FRESH"
	case !recordedTime(d.GetPolicyLoadedAt()) || !recordedTime(d.GetDecidedAt()):
		return ReasonIncompleteRequest, "the decision records no policy_loaded_at or no decided_at"
	}
	return "", ""
}

func recordedTime(ts *timestamppb.Timestamp) bool {
	return ts != nil && ts.CheckValid() == nil
}

// evidenceOptions configure the kernel for an evidence case. The plane's own
// settings are not in the evidence: no staleness budget of the operator's
// narrows the author's, so the age of the case decides freshness alone; no
// read runs open; and every obligation type is applicable, so a decision
// naming one the plane may not apply is judged unknown, not denied.
func evidenceOptions() core.Options {
	types := make([]string, 0, len(rules.Obligations()))
	for _, spec := range rules.Obligations() {
		types = append(types, spec.Type)
	}
	return core.Options{
		Mode:       controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
		MaxStale:   time.Duration(math.MaxInt64),
		Applicable: types,
	}
}

// crossCheck judges an evaluated evidence case against what the evidence can
// support: an obligation the recorded decision does not show the plane could
// apply, and a current side that does not decide as the plane recorded.
func crossCheck(recorded *controlv1.Decision, before, after side) (Reason, string) {
	switch {
	case !applicable(recorded, before) || !applicable(recorded, after):
		return ReasonObligationApplicability, "a side names an obligation type the recorded decision does not show the plane applying"
	case before.verdict != recorded.GetVerdict() || !slices.Equal(before.codes, recorded.GetReasonCodes()):
		return ReasonDisagreesWithRecord, fmt.Sprintf("recorded %s %v, today's kernel on the current policy %s %v",
			verdictName(recorded.GetVerdict()), recorded.GetReasonCodes(), verdictName(before.verdict), before.codes)
	}
	return "", ""
}

// applicable reports whether every obligation s must apply is of a type the
// recorded decision carried.
func applicable(recorded *controlv1.Decision, s side) bool {
	for _, o := range s.obligations {
		if o.GetAdvisory() {
			continue
		}
		if !slices.ContainsFunc(recorded.GetObligations(), func(r *controlv1.Obligation) bool { return r.GetType() == o.GetType() }) {
			return false
		}
	}
	return true
}
