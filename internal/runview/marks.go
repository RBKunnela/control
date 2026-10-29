package runview

import (
	"strings"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/supervise"
)

// mark is what the page says of one call or one thing not seen. Each is a
// shape and a line style of its own as well as a colour; page.tmpl draws
// them.
type mark int

const (
	markEnforced mark = iota + 1
	markDecided
	markObserved
	markExcepted
	markBlocked
	markNotSeen
)

// markCell is a mark with its label and what it rests on: Pre, then a
// string an input chose if any, then Post.
type markCell struct {
	Mark      mark
	Label     string
	Pre, Post string
	Code      *text
}

var labels = map[mark]string{
	markEnforced: "enforced", markDecided: "decided, not enforced", markObserved: "observed",
	markExcepted: "exception or approval", markBlocked: "blocked", markNotSeen: "not seen",
}

func cell(m mark, pre string) markCell { return markCell{Mark: m, Label: labels[m], Pre: pre} }

// legendRow is one mark and what it means.
type legendRow struct {
	Mark    markCell
	Meaning string
}

var legend = []legendRow{
	{cell(markEnforced, ""), "A plane decided the call and enforced its decision."},
	{cell(markDecided, ""), "A plane decided the call and did not enforce the decision, or nothing read shows it did."},
	{cell(markObserved, ""), "Only a source reported the call, with the trust its source declared; no plane decided it."},
	{cell(markExcepted, ""), "An exception the procedure states was taken on the call, or the approvals store granted it."},
	{cell(markBlocked, ""), "The policy denied the call, or the plane blocked it: a pause, a stop, an approval refused or expired."},
	{cell(markNotSeen, ""), "An expected step with no call, or a source that was silent, never heard or not read."},
}

// enforcing are the modes in which a plane acts on its decision.
var enforcing = map[controlv1.EnforcementMode]bool{
	controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE:  true,
	controlv1.EnforcementMode_ENFORCEMENT_MODE_APPROVE:  true,
	controlv1.EnforcementMode_ENFORCEMENT_MODE_LOCKDOWN: true,
}

var trustWords = map[observev1.Trust]string{
	observev1.Trust_TRUST_SELF_REPORTED: "self-reported",
	observev1.Trust_TRUST_PLATFORM:      "reported by the platform",
	observev1.Trust_TRUST_INDEPENDENT:   "reported independently",
}

// markOf marks a call from what supervise returned of it alone. Enforced
// rests on a coherent trail whose decision a plane recorded in a mode that
// acts on it, for a call of a protocol the plane holds inline; anything less
// is decided, not enforced. An enforcement API call is run by the client the
// plane answers, and a call of no protocol, or of one this build does not
// know, by nothing the plane holds.
func markOf(in supervise.Instance) markCell {
	switch {
	case in.Observation != "":
		return reportMark(in)
	case in.Outcome == supervise.OutcomeDenied:
		return cell(markBlocked, "denied by the policy")
	case in.Outcome == supervise.OutcomeBlocked:
		return cell(markBlocked, "blocked by the plane")
	case in.Doubt:
		return cell(markDecided, "trail in doubt")
	case in.Excepted && in.Approval == supervise.ApprovalGranted:
		return cell(markExcepted, "an exception taken, approval granted")
	case in.Excepted:
		return cell(markExcepted, "an exception taken")
	case in.Approval == supervise.ApprovalGranted:
		return cell(markExcepted, "approval granted")
	case channel.StrengthOf(in.Protocol) != channel.StrengthInline:
		return unheldMark(channel.StrengthOf(in.Protocol))
	case in.Mode == controlv1.EnforcementMode_ENFORCEMENT_MODE_UNSPECIFIED:
		return cell(markDecided, "no mode recorded")
	case enforcing[in.Mode]:
		return cell(markEnforced, "mode "+modeWord(in.Mode))
	}
	return cell(markDecided, "mode "+modeWord(in.Mode))
}

// unheldMark is the mark of a call whose protocol the plane does not hold
// inline: a cooperating client's, or nothing's.
func unheldMark(s channel.Strength) markCell {
	if s == channel.StrengthCooperative {
		return cell(markDecided, "a cooperating client enforces it")
	}
	return cell(markDecided, "no enforcement point holds the path")
}

func modeWord(m controlv1.EnforcementMode) string {
	return strings.TrimPrefix(m.String(), "ENFORCEMENT_MODE_")
}

// reportMark marks a source's report with the trust its source declared.
func reportMark(in supervise.Instance) markCell {
	trust := trustWords[in.Trust]
	if trust == "" {
		trust = "reported, trust unknown,"
	}
	src := textOf(in.Source)
	c := markCell{Mark: markObserved, Label: labels[markObserved], Pre: trust + " by source ", Code: &src}
	if in.Doubt {
		c.Post = ", in doubt"
	}
	return c
}
