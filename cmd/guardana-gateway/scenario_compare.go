package main

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/internal/scenario"
	"github.com/guardana/control/internal/trailchain"
)

// The flow state a fresh run starts from, as its first proposal records it.
var freshRun = []string{"flow.v1.untrusted=false", "flow.v1.max_read=PUBLIC"}

const flowTags = "flow.v1."

// difference is one member of one step that is not what the scenario says.
type difference struct {
	step      int
	member    string
	want, got string
}

func (d difference) String() string {
	return fmt.Sprintf("step[%d].%s: want %s, got %s", d.step, d.member, oneLine(d.want), oneLine(d.got))
}

// callSeen is what the plane showed for one call step: the answer, the
// events of the trail it names in link order, and which request that trail
// is, as "new", "step[k]" or a request the file held before the scenario.
// others is every other request whose trail grew during the step.
type callSeen struct {
	answer  answered
	trail   []*controlv1.Event
	others  []string
	request string
}

// planeFacts is what every trail must show of the plane and, for the call
// that must prove a fresh run, that it does.
type planeFacts struct {
	mode, digest string
	fresh        bool
	// sentHash is canon's hash of the arguments sent, empty where canon
	// cannot hash them.
	sentHash string
}

// judgeCall compares every member of call c, step i, with what the plane
// showed, in the order the members are written, then holds the trail to the
// plane's mode and bundle, the answer's decision id to the trail and, where
// asked, the first proposal to a fresh run. An error is a trail that cannot
// be compared.
func judgeCall(i int, c *scenario.Call, seen callSeen, plane planeFacts) ([]difference, error) {
	var out []difference
	add := func(member, want, got string) {
		if want != got {
			out = append(out, difference{i, member, want, got})
		}
	}
	add("answer.kind", string(c.Answer.Kind), string(seen.answer.kind))
	addList := func(member string, want, got []string) {
		if !slices.Equal(want, got) {
			w, g := list(want), list(got)
			if w == g {
				w, g = quotedList(want), quotedList(got)
			}
			out = append(out, difference{i, member, w, g})
		}
	}
	addList("answer.codes", c.Answer.Codes, seen.answer.codes)
	decided, err := decidedOf(seen.trail)
	if err != nil {
		return nil, err
	}
	switch {
	case c.Decided.None || len(decided) == 0:
		add("decided", decidedName(c.Decided.None, c.Decided.Verdict), decidedName(len(decided) == 0, firstDecision(decided).GetVerdict()))
	default:
		d := decided[0].GetDecision()
		add("decided.verdict", verdictName(c.Decided.Verdict), verdictName(d.GetVerdict()))
		addList("decided.codes", c.Decided.Codes, d.GetReasonCodes())
		want, err := wantObligations(c.Decided.Obligations)
		if err != nil {
			return nil, err
		}
		got, err := gotObligations(d.GetObligations())
		if err != nil {
			return nil, err
		}
		add("decided.obligations", want, got)
	}
	add("trail.request", requestName(c.Trail.Request), seen.request)
	add("trail.kinds", kindList(c.Trail.Kinds), kindList(kindsOf(seen.trail)))
	if len(seen.others) > 0 {
		add("trail.others", "none", list(seen.others))
	}
	if err := judgePlane(seen, plane, add); err != nil {
		return nil, err
	}
	return out, nil
}

// decidedOf is the trail's POLICY_DECIDED, none or one, whose decision is of
// the major this build reads; anything else cannot be compared.
func decidedOf(trail []*controlv1.Event) ([]*controlv1.Event, error) {
	decided := withKind(trail, controlv1.EventKind_EVENT_KIND_POLICY_DECIDED)
	if len(decided) > 1 {
		return nil, fmt.Errorf("the trail holds %d POLICY_DECIDED events", len(decided))
	}
	if len(decided) == 1 {
		if err := checkDecisionVersion(decided[0].GetDecision()); err != nil {
			return nil, err
		}
	}
	return decided, nil
}

// judgePlane holds a trail to what the plane is. The decision id is checked
// against a trail that records a decision; a trail that records none shows
// that in its kinds. A pending answer's approval id must be the one the
// trail last requested, since an operator step answers that id. The
// arguments sent are held to the trail's first proposal, which for a retry
// is the held call's.
func judgePlane(seen callSeen, plane planeFacts, add func(member, want, got string)) error {
	if plane.digest == "" {
		return errors.New("the plane reported no policy bundle digest to hold the trail to")
	}
	var modes, digests, recorded []string
	for _, ev := range seen.trail {
		modes = append(modes, modeName(ev.GetEnforcementMode()))
		if d := ev.GetDecision(); d != nil && !slices.Contains(recorded, d.GetDecisionId()) {
			recorded = append(recorded, d.GetDecisionId())
		}
		if ev.GetKind() == controlv1.EventKind_EVENT_KIND_POLICY_DECIDED {
			digests = append(digests, ev.GetDecision().GetPolicyBundleDigest())
		}
	}
	add("plane.mode", plane.mode, firstOther(modes, plane.mode))
	add("plane.bundle.digest", plane.digest, firstOther(digests, plane.digest))
	if len(recorded) > 0 && !slices.Contains(recorded, seen.answer.decisionID) {
		add("answer.decision_id", "one of "+list(recorded), seen.answer.decisionID)
	}
	if seen.answer.kind == scenario.AnswerPending {
		add("answer.approval_id", requestedApproval(seen.trail), seen.answer.approvalID)
	}
	proposed := withKind(seen.trail, controlv1.EventKind_EVENT_KIND_ACTION_PROPOSED)
	if len(proposed) > 0 {
		add("args", hashName(plane.sentHash), hashName(proposed[0].GetProposed().GetArguments().GetCanonicalHash()))
	}
	if plane.fresh {
		return judgeFresh(proposed, add)
	}
	return nil
}

func hashName(hash string) string {
	if hash == "" {
		return "none"
	}
	return hash
}

// judgeFresh holds the first proposal of a scenario to the flow state of a
// run nothing has touched.
func judgeFresh(proposed []*controlv1.Event, add func(member, want, got string)) error {
	if len(proposed) == 0 {
		return errors.New("the first call's trail holds no ACTION_PROPOSED to show a fresh run by")
	}
	var tags []string
	for _, tag := range proposed[0].GetProposed().GetContext().GetTags() {
		if strings.HasPrefix(tag, flowTags) {
			tags = append(tags, tag)
		}
	}
	if !slices.Equal(tags, freshRun) {
		add("run", "fresh ("+strings.Join(freshRun, ", ")+")", strings.Join(tags, ", "))
	}
	return nil
}

// requestedApproval is the approval id of the trail's last
// APPROVAL_REQUESTED, or says the trail requested none.
func requestedApproval(trail []*controlv1.Event) string {
	requested := withKind(trail, controlv1.EventKind_EVENT_KIND_APPROVAL_REQUESTED)
	if len(requested) == 0 {
		return "the id of an APPROVAL_REQUESTED, and the trail holds none"
	}
	return requested[len(requested)-1].GetApproval().GetApprovalId()
}

// firstOther is the first of values that is not want, or want when every
// one is.
func firstOther(values []string, want string) string {
	if i := slices.IndexFunc(values, func(v string) bool { return v != want }); i >= 0 {
		return values[i]
	}
	return want
}

// requestOf names the request a call's answer names: a request the file held
// before the scenario, an earlier call step's by the first step that named
// it, or a new one. want is the step the scenario names, or
// scenario.NewRequest; a step's own request is what step[n] means even when
// an earlier step named it first.
func requestOf(id string, want int, earlier []string, before map[string]bool) string {
	if want >= 0 && want < len(earlier) && earlier[want] == id {
		return requestName(want)
	}
	if before[id] {
		return "a request the trail file held before this scenario"
	}
	if k := slices.Index(earlier, id); k >= 0 {
		return requestName(k)
	}
	return requestName(scenario.NewRequest)
}

func requestName(step int) string {
	if step == scenario.NewRequest {
		return "new"
	}
	return fmt.Sprintf("step[%d]", step)
}

func withKind(trail []*controlv1.Event, kind controlv1.EventKind) []*controlv1.Event {
	var out []*controlv1.Event
	for _, ev := range trail {
		if ev.GetKind() == kind {
			out = append(out, ev)
		}
	}
	return out
}

func firstDecision(decided []*controlv1.Event) *controlv1.Decision {
	if len(decided) == 0 {
		return nil
	}
	return decided[0].GetDecision()
}

func decidedName(none bool, v controlv1.Verdict) string {
	if none {
		return "none"
	}
	return "a decision of " + verdictName(v)
}

func kindsOf(trail []*controlv1.Event) []controlv1.EventKind {
	out := make([]controlv1.EventKind, len(trail))
	for i, ev := range trail {
		out[i] = ev.GetKind()
	}
	return out
}

func kindList(kinds []controlv1.EventKind) string {
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = kindName(k)
	}
	return list(names)
}

func kindName(k controlv1.EventKind) string { return strings.TrimPrefix(k.String(), "EVENT_KIND_") }

func verdictName(v controlv1.Verdict) string { return strings.TrimPrefix(v.String(), "VERDICT_") }

func modeName(m controlv1.EnforcementMode) string {
	return strings.TrimPrefix(m.String(), "ENFORCEMENT_MODE_")
}

func list(items []string) string { return "[" + strings.Join(items, ", ") + "]" }

// quotedList renders items each quoted, for two lists that list renders alike.
func quotedList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = strconv.Quote(s)
	}
	return list(quoted)
}

// maxQuotedVersionBytes bounds how much of a refused version an error quotes.
const maxQuotedVersionBytes = 32

// checkDecisionVersion refuses a decision whose schema_version is not
// MAJOR.MINOR on the major the generated Decision carries; a later minor is
// read.
func checkDecisionVersion(d *controlv1.Decision) error {
	pkg := string((&controlv1.Decision{}).ProtoReflect().Descriptor().ParentFile().Package())
	want := strings.TrimPrefix(pkg[strings.LastIndex(pkg, ".")+1:], "v")
	if !strictjson.IsVersion(d.GetSchemaVersion(), want) {
		return fmt.Errorf("the trail's POLICY_DECIDED carries a decision of schema_version %s, and this build reads major %s",
			trailchain.Quoted(d.GetSchemaVersion(), maxQuotedVersionBytes), want)
	}
	return nil
}

// wantObligations renders the scenario's obligations as canonical JSON, the
// parameters as written and canonicalized.
func wantObligations(obligations []scenario.Obligation) (string, error) {
	out := make([]string, len(obligations))
	for i, o := range obligations {
		params, err := canon.CanonicalizeJSON(o.Params)
		if err != nil {
			return "", fmt.Errorf("the obligation %s's parameters: %w", o.Type, err)
		}
		out[i], err = obligationText(o.Type, string(params), o.Advisory)
		if err != nil {
			return "", err
		}
	}
	return "[" + strings.Join(out, ",") + "]", nil
}

// gotObligations renders a decision's obligations as wantObligations does.
func gotObligations(obligations []*controlv1.Obligation) (string, error) {
	out := make([]string, len(obligations))
	for i, o := range obligations {
		params := make(map[string]any, len(o.GetParams()))
		for k, v := range o.GetParams() {
			params[k] = v
		}
		raw, err := canon.Canonicalize(params)
		if err != nil {
			return "", fmt.Errorf("the recorded obligation %s's parameters: %w", o.GetType(), err)
		}
		if out[i], err = obligationText(o.GetType(), string(raw), o.GetAdvisory()); err != nil {
			return "", err
		}
	}
	return "[" + strings.Join(out, ",") + "]", nil
}

func obligationText(kind, params string, advisory bool) (string, error) {
	name, err := canon.Canonicalize(kind)
	if err != nil {
		return "", fmt.Errorf("the obligation type %q: %w", kind, err)
	}
	return fmt.Sprintf(`{"advisory":%t,"params":%s,"type":%s}`, advisory, params, name), nil
}
