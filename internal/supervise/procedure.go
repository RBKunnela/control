package supervise

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/strictjson"
)

// MaxProcedureBytes bounds a procedure document.
const MaxProcedureBytes = 65536

// Step is one step of a procedure: the tool and upstream a plane sees it as,
// and the names a source reports it under.
type Step struct {
	ID         string
	Tool       string
	Upstream   string
	ObservedAs []string
	Required   bool
}

// Allowed is a tool the run may call besides its steps.
type Allowed struct {
	Tool       string
	Upstream   string
	ObservedAs []string
}

// RuleSpec is what a finding of one rule carries.
type RuleSpec struct {
	Severity   controlv1.FindingSeverity
	Escalation findingv1alpha1.Escalation
}

// Procedure is a procedure document as ReadProcedure accepted it. Only
// ReadProcedure makes one Evaluate takes.
type Procedure struct {
	id, version string
	steps       []Step
	// after maps a step's id to the ids of the steps it must follow.
	after           map[string][]string
	allow           []Allowed
	maxDenials      uint32
	deadlineSeconds uint32
	rules           map[string]RuleSpec
	digest          string

	schema   string
	children Children
	// bindings is sorted by name.
	bindings []Binding
	// stepBinds and allowBinds are the binding of steps[i] and allow[i],
	// "" for none.
	stepBinds, allowBinds []string
	exceptions            []Exception
}

// ID is the procedure's id.
func (p *Procedure) ID() string { return p.id }

// Version is the procedure's version.
func (p *Procedure) Version() string { return p.version }

// Digest is the lowercase hex SHA-256 of the document's RFC 8785 canonical
// form: member order and white space do not change it, an edit does.
func (p *Procedure) Digest() string { return p.digest }

// Steps are the procedure's steps in document order. The slice and each
// step's ObservedAs are copies.
func (p *Procedure) Steps() []Step {
	out := slices.Clone(p.steps)
	for i := range out {
		out[i].ObservedAs = slices.Clone(out[i].ObservedAs)
	}
	return out
}

// Schema is the document's schema_version.
func (p *Procedure) Schema() string { return p.schema }

// Children is how the procedure judges a run's children; a 0.1 document
// states none.
func (p *Procedure) Children() Children { return p.children }

// Bindings are the procedure's bindings sorted by name. The slice is a copy.
func (p *Procedure) Bindings() []Binding { return slices.Clone(p.bindings) }

// Exceptions are the procedure's exceptions in document order. The slice is
// a copy.
func (p *Procedure) Exceptions() []Exception { return slices.Clone(p.exceptions) }

// BindingOf is the binding of the step or allowed tool on upstream, and
// false when that entry binds none or no entry names the tool.
func (p *Procedure) BindingOf(tool, upstream string) (string, bool) {
	binding, _ := p.entry(tool, upstream)
	return binding, binding != ""
}

// entry is the binding of the step or allowed tool on upstream, and whether
// the procedure names that tool at all.
func (p *Procedure) entry(tool, upstream string) (string, bool) {
	for i, s := range p.steps {
		if s.Tool == tool && s.Upstream == upstream {
			return bindingAt(p.stepBinds, i), true
		}
	}
	for i, a := range p.allow {
		if a.Tool == tool && a.Upstream == upstream {
			return bindingAt(p.allowBinds, i), true
		}
	}
	return "", false
}

// bindingAt is binds[i], or "" where a 0.1 document has no binds.
func bindingAt(binds []string, i int) string {
	if i < len(binds) {
		return binds[i]
	}
	return ""
}

// ReadProcedure reads a procedure document of schema 0.1 or 0.2 strictly:
// one JSON object of at most MaxProcedureBytes, every member of its schema
// required and none unknown or named twice, except max_denials and
// deadline_seconds, whose absence turns their rule off. A cycle in the
// order, a step it names that the steps lack, and a tool, upstream or
// reported name that two entries share are refused; so, in 0.2, are a binds
// naming no binding, a tool in two bindings, and an exception on a rule, a
// step or a tool it cannot cover, or on a condition the rule refuses.
func ReadProcedure(b []byte) (*Procedure, error) {
	p, err := readProcedure(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProcedure, err)
	}
	return p, nil
}

var (
	procedureMembers = map[string][]string{
		ProcedureSchema01: {"schema_version", "procedure_id", "version", "steps", "order", "allow", "rules"},
		ProcedureSchema02: {"schema_version", "procedure_id", "version", "bindings", "steps", "order", "allow",
			"exceptions", "children", "rules"},
	}
	procedureOptional = []string{"max_denials", "deadline_seconds"}
)

func readProcedure(b []byte) (*Procedure, error) {
	if len(b) > MaxProcedureBytes {
		return nil, fmt.Errorf("%d bytes, bound %d", len(b), MaxProcedureBytes)
	}
	canonical, err := canon.CanonicalizeJSON(b)
	if err != nil {
		return nil, err
	}
	o, err := strictjson.ReadObject(b)
	if err != nil {
		return nil, err
	}
	r := &reader{}
	schema := r.ident(o, "schema_version")
	members, known := procedureMembers[schema]
	switch {
	case r.err != nil:
		return nil, r.err
	case !known:
		return nil, errors.New("schema_version is neither " + ProcedureSchema01 + " nor " + ProcedureSchema02)
	}
	if err := o.Only(slices.Concat(members, procedureOptional)...); err != nil {
		return nil, err
	}
	if err := o.Require(members...); err != nil {
		return nil, err
	}
	p := r.procedure(o, schema)
	if r.err != nil {
		return nil, r.err
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	p.digest = hex.EncodeToString(sum[:])
	return p, nil
}

// procedure reads the members of o, a document of schema.
func (r *reader) procedure(o strictjson.Object, schema string) *Procedure {
	v02 := schema == ProcedureSchema02
	p := &Procedure{schema: schema, id: r.ident(o, "procedure_id"), version: r.ident(o, "version")}
	if v02 {
		p.bindings = r.bindings(o["bindings"])
	}
	p.steps, p.stepBinds = r.steps(o["steps"], v02)
	p.allow, p.allowBinds = r.allowed(o["allow"], v02)
	p.after = r.order(o["order"])
	p.maxDenials = r.count(o, "max_denials")
	p.deadlineSeconds = r.count(o, "deadline_seconds")
	p.rules = r.rules(o["rules"], RuleIDsOf(schema))
	if v02 {
		p.exceptions = r.exceptions(o["exceptions"])
		p.children = r.children(o["children"])
	}
	return p
}
