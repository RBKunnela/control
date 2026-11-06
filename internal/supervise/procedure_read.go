package supervise

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/pkg/contract"
)

var severities = map[string]controlv1.FindingSeverity{
	"info":     controlv1.FindingSeverity_FINDING_SEVERITY_INFO,
	"low":      controlv1.FindingSeverity_FINDING_SEVERITY_LOW,
	"medium":   controlv1.FindingSeverity_FINDING_SEVERITY_MEDIUM,
	"high":     controlv1.FindingSeverity_FINDING_SEVERITY_HIGH,
	"critical": controlv1.FindingSeverity_FINDING_SEVERITY_CRITICAL,
}

var escalations = map[string]findingv1alpha1.Escalation{
	"inform": findingv1alpha1.Escalation_ESCALATION_INFORM,
	"alert":  findingv1alpha1.Escalation_ESCALATION_ALERT,
}

// object reads raw as one JSON object holding only known members and every
// one of required.
func object(raw []byte, known, required []string) (strictjson.Object, error) {
	o, err := strictjson.ReadObject(raw)
	if err != nil {
		return nil, err
	}
	if err := o.Only(known...); err != nil {
		return nil, err
	}
	if err := o.Require(required...); err != nil {
		return nil, err
	}
	return o, nil
}

// reader keeps the first refusal of a read, so a document's members are read
// in a line without a check after each.
type reader struct{ err error }

func (r *reader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *reader) object(raw []byte, where string, members ...string) strictjson.Object {
	return r.objectOf(raw, where, members, members)
}

// objectOf reads raw as an object holding only known members and every one
// of required.
func (r *reader) objectOf(raw []byte, where string, known, required []string) strictjson.Object {
	if r.err != nil {
		return nil
	}
	o, err := object(raw, known, required)
	if err != nil {
		r.fail(fmt.Errorf("%s: %w", where, err))
	}
	return o
}

// ident reads member name of o as a contract identifier, not empty and no
// longer than contract.MaxStringBytes.
func (r *reader) ident(o strictjson.Object, name string) string {
	return r.identOf(o[name], name)
}

func (r *reader) identOf(raw json.RawMessage, where string) string {
	if r.err != nil {
		return ""
	}
	s, ok := strictjson.String(raw)
	if !ok {
		r.fail(fmt.Errorf("%s is not a string", where))
		return s
	}
	return r.identText(s, where)
}

// identText checks s as a contract identifier.
func (r *reader) identText(s, where string) string {
	if r.err != nil {
		return s
	}
	if err := contract.CheckID(s); err != nil {
		r.fail(fmt.Errorf("%s: %w", where, err))
	}
	return s
}

// array reads raw as a JSON array, never null.
func (r *reader) array(raw json.RawMessage, where string) []json.RawMessage {
	var items []json.RawMessage
	if r.err != nil {
		return nil
	}
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil {
		r.fail(fmt.Errorf("%s is not an array", where))
	}
	return items
}

// names reads an array of identifiers, none named twice.
func (r *reader) names(raw json.RawMessage, where string) []string {
	items := r.array(raw, where)
	out := make([]string, 0, len(items))
	for _, item := range items {
		s := r.identOf(item, where)
		if slices.Contains(out, s) {
			r.fail(fmt.Errorf("%s names one entry twice", where))
		}
		out = append(out, s)
	}
	return out
}

// steps reads the steps and, in 0.2, the binding each binds.
func (r *reader) steps(raw json.RawMessage, v02 bool) ([]Step, []string) {
	items := r.array(raw, "steps")
	out := make([]Step, 0, len(items))
	var binds []string
	members := []string{"id", "tool", "upstream", "observed_as", "required"}
	if v02 {
		members = append(members, "binds")
	}
	for i, item := range items {
		where := "step " + strconv.Itoa(i+1)
		o := r.object(item, where, members...)
		s := Step{ID: r.ident(o, "id"), Tool: r.ident(o, "tool"), Upstream: r.ident(o, "upstream"),
			ObservedAs: r.names(o["observed_as"], where+" observed_as")}
		switch string(o["required"]) {
		case "true":
			s.Required = true
		case "false":
		default:
			r.fail(errors.New(where + ": required is not true or false"))
		}
		out = append(out, s)
		if v02 {
			binds = append(binds, r.binds(o, where))
		}
	}
	return out, binds
}

// allowed reads the allowed tools and, in 0.2, the binding each binds.
func (r *reader) allowed(raw json.RawMessage, v02 bool) ([]Allowed, []string) {
	items := r.array(raw, "allow")
	out := make([]Allowed, 0, len(items))
	var binds []string
	members := []string{"tool", "upstream", "observed_as"}
	if v02 {
		members = append(members, "binds")
	}
	for i, item := range items {
		where := "allow " + strconv.Itoa(i+1)
		o := r.object(item, where, members...)
		out = append(out, Allowed{Tool: r.ident(o, "tool"), Upstream: r.ident(o, "upstream"),
			ObservedAs: r.names(o["observed_as"], where+" observed_as")})
		if v02 {
			binds = append(binds, r.binds(o, where))
		}
	}
	return out, binds
}

// order reads each step's predecessors; a step listed with none is refused,
// so one order has one spelling.
func (r *reader) order(raw json.RawMessage) map[string][]string {
	if r.err != nil {
		return nil
	}
	o, err := strictjson.ReadObject(raw)
	if err != nil {
		r.fail(fmt.Errorf("order: %w", err))
		return nil
	}
	out := make(map[string][]string, len(o))
	for step, list := range o {
		after := r.names(list, "order")
		if len(after) == 0 {
			r.fail(errors.New("order: an entry lists no step"))
		}
		out[step] = after
	}
	return out
}

// count reads an optional member as an integer from 1 to 2^32-1, written
// without sign, fraction or exponent; absent is 0, the rule off. JSON itself
// refuses a leading zero.
func (r *reader) count(o strictjson.Object, name string) uint32 {
	raw, ok := o[name]
	if !ok || r.err != nil {
		return 0
	}
	n, err := strconv.ParseUint(string(raw), 10, 32)
	if err != nil || n == 0 {
		r.fail(fmt.Errorf("%s is not an integer from 1 to %d", name, uint32(1<<32-1)))
	}
	return uint32(n)
}

// rules reads the severity and escalation of each of ids, which are every
// rule the document's schema knows.
func (r *reader) rules(raw json.RawMessage, ids []string) map[string]RuleSpec {
	o := r.object(raw, "rules", ids...)
	out := make(map[string]RuleSpec, len(ids))
	for _, id := range ids {
		spec := r.object(o[id], "rule "+id, "severity", "escalation")
		sev, sevOK := severities[r.ident(spec, "severity")]
		esc, escOK := escalations[r.ident(spec, "escalation")]
		if r.err == nil && (!sevOK || !escOK) {
			r.fail(errors.New("rule " + id + ": an unknown severity or escalation"))
		}
		out[id] = RuleSpec{Severity: sev, Escalation: esc}
	}
	return out
}
