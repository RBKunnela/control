package scenario

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policykey"
)

func (st *steps) approval(n *node, at path) (*Approval, *Refusal) {
	f, r := closed(n, at, []string{"step", "approver"}, "reason")
	if r != nil {
		return nil, r
	}
	a := &Approval{}
	if a.Step, r = stepIndex(f["step"], at.key("step")); r != nil {
		return nil, r
	}
	if r := st.pendingCall(a.Step, at.key("step")); r != nil {
		return nil, r
	}
	// The approval a pending call names is answered once; a second answer
	// the store refuses would make the step fail on the store's word.
	if st.answered[a.Step] {
		return nil, refuse(at.key("step"), ErrStep, fmt.Sprintf("step %d is answered already", a.Step))
	}
	st.answered[a.Step] = true
	if a.Approver, r = identifier(f["approver"], at.key("approver"), approvals.MaxApproverIDBytes); r != nil {
		return nil, r
	}
	if err := approval.CheckClaimedApproverID(a.Approver); err != nil {
		return nil, refuse(at.key("approver"), ErrValue, err.Error())
	}
	if r := noKeyText(a.Approver, at.key("approver")); r != nil {
		return nil, r
	}
	if n, ok := f["reason"]; ok {
		if a.Reason, r = reason(n, at.key("reason")); r != nil {
			return nil, r
		}
		if len(a.Reason) > approvals.MaxReasonBytes {
			return nil, refuse(at.key("reason"), ErrBound, fmt.Sprintf("%d bytes, the bound is %d", len(a.Reason), approvals.MaxReasonBytes))
		}
		if r := noControl(a.Reason, at.key("reason")); r != nil {
			return nil, r
		}
	}
	return a, nil
}

// reason reads an optional reason that is present: an empty one would be a
// second spelling of none.
func reason(n *node, at path) (string, *Refusal) {
	s, r := text(n, at)
	if r != nil {
		return "", r
	}
	if s == "" {
		return "", refuse(at, ErrBound, "empty; leave the member out instead")
	}
	return s, noKeyText(s, at)
}

// noKeyText refuses key text in a value that reaches the approver's binary's
// command line, where the process table shows it before that binary refuses
// it. The refusal never quotes the value.
func noKeyText(s string, at path) *Refusal {
	if policykey.HoldsKeyText(s) {
		return refuse(at, ErrValue, "it holds key text, which would reach a command line")
	}
	return nil
}

// readPause reads one scope the way the pause command takes it and holds it,
// and its reason, to the pause file's own entry check.
func readPause(n *node, at path) (*Pause, *Refusal) {
	f, r := closed(n, at, nil, "global", "provider", "action", "name", "reason")
	if r != nil {
		return nil, r
	}
	p := &Pause{}
	if p.Scope, r = readScope(f, at); r != nil {
		return nil, r
	}
	if v, ok := f["reason"]; ok {
		if p.Reason, r = reason(v, at.key("reason")); r != nil {
			return nil, r
		}
	}
	// The entry check also holds an id and a creation time, which the tool
	// that adds the entry chooses; these stand in for them.
	entry := pause.Entry{ID: "scenario", CreatedAt: time.Unix(1, 0).UTC(), Scope: p.Scope, Reason: p.Reason}
	if err := entry.Check(); err != nil {
		return nil, refuse(at.key("reason"), ErrValue, err.Error())
	}
	if bound := pause.MaxReasonBytes - PauseMarkerBytes; len(p.Reason) > bound {
		return nil, refuse(at.key("reason"), ErrBound, fmt.Sprintf("%d bytes, the bound is %d, which leaves the runner room for its marker", len(p.Reason), bound))
	}
	return p, nil
}

// readScope takes the scope's kind from the members present, as the pause
// command takes it from its flags, and leaves every rule about which members
// a kind may carry to the pause file's scope check.
func readScope(f map[string]*node, at path) (pause.Scope, *Refusal) {
	s := pause.Scope{Kind: pause.ScopeProvider}
	if g, ok := f["global"]; ok {
		if g.kind != kindBool {
			return pause.Scope{}, wrongType(at.key("global"), "true")
		}
		if !g.truth {
			return pause.Scope{}, refuse(at.key("global"), ErrValue, "set it true, or leave it out")
		}
		s.Kind = pause.ScopeGlobal
	} else if _, ok := f["action"]; ok {
		s.Kind = pause.ScopeAction
	}
	for _, m := range []struct {
		name string
		to   *string
	}{{"provider", &s.Provider}, {"action", &s.Action}, {"name", &s.Name}} {
		if v, ok := f[m.name]; ok {
			var r *Refusal
			if *m.to, r = text(v, at.key(m.name)); r != nil {
				return pause.Scope{}, r
			}
			if r := noKeyText(*m.to, at.key(m.name)); r != nil {
				return pause.Scope{}, r
			}
		}
	}
	if err := s.Check(); err != nil {
		return pause.Scope{}, refuse(at, ErrValue, err.Error())
	}
	return s, nil
}

func (st *steps) unpause(n *node, at path) (*Unpause, *Refusal) {
	f, r := closed(n, at, []string{"step"})
	if r != nil {
		return nil, r
	}
	i, r := stepIndex(f["step"], at.key("step"))
	if r != nil {
		return nil, r
	}
	switch {
	case i >= len(st.read) || st.read[i].Pause == nil:
		return nil, refuse(at.key("step"), ErrStep, fmt.Sprintf("step %d is not an earlier pause step", i))
	case st.unpaused[i]:
		return nil, refuse(at.key("step"), ErrStep, fmt.Sprintf("step %d is unpaused already", i))
	}
	st.unpaused[i] = true
	return &Unpause{Step: i}, nil
}

// stepIndex reads a step's index: a whole number written without sign,
// fraction or exponent. One too long to be any step's reads as MaxSteps,
// which no step has.
func stepIndex(n *node, at path) (int, *Refusal) {
	if n.kind != kindNumber {
		return 0, wrongType(at, "a step index")
	}
	i, ok := decimal(n.text)
	if !ok {
		return 0, refuseQuoting(at, ErrValue, "a step index is a whole number from 0", []byte(n.text))
	}
	return i, nil
}

// stepName reads "step[n]".
func stepName(s string) (int, bool) {
	digits, ok := strings.CutPrefix(s, "step[")
	if !ok {
		return 0, false
	}
	if digits, ok = strings.CutSuffix(digits, "]"); !ok {
		return 0, false
	}
	return decimal(digits)
}

// decimal reads digits written without a sign or a leading zero.
func decimal(s string) (int, bool) {
	if s == "" || (s[0] == '0' && len(s) > 1) {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	if len(s) > len(strconv.Itoa(MaxSteps)) {
		return MaxSteps, true
	}
	i, err := strconv.Atoi(s)
	return i, err == nil
}
