// Package match compiles a policy document into a program and evaluates an
// envelope against it: three-valued constraints under deny-overrides, as
// ADR-0012 states them.
//
// Nothing here reads the reason registry. The codes this package emits are
// literals in codes.go, and a test holds each one to its registry entry.
package match

import (
	"slices"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/policy/rules"
	"github.com/guardana/control/pkg/contract"
)

// External is the external decision point's answer as the external
// constraint reads it. The zero value is unknown, so an answer nobody handed
// in never reads as one that did not deny, which would lift a veto.
type External uint8

const (
	// ExternalUnknown is no answer: none was asked for, or none came back.
	ExternalUnknown External = iota
	// ExternalAllows is an answer that does not deny the call.
	ExternalAllows
	// ExternalDenies is an answer that denies the call.
	ExternalDenies
)

// Inputs are what Evaluate reads beside the envelope, computed by the kernel.
type Inputs struct {
	Flow contract.FlowState
	// Delegated is true when a chain was present and passed the kernel's
	// delegation check.
	Delegated bool
	// Scopes are that chain's effective scopes; an empty list grants nothing.
	Scopes []string
	// External is the external decision point's answer. A value this build
	// does not declare reads as unknown.
	External External
}

// Result is what a program concluded about one envelope.
type Result struct {
	// Verdict is one of the five, never VERDICT_UNSPECIFIED.
	Verdict controlv1.Verdict
	// Determinate is the combination of the determinate rules alone: DENY when
	// nothing matched.
	Determinate controlv1.Verdict
	// RuleIDs are the matched rules, in document order.
	RuleIDs []string
	// Indeterminate are the restrictive rules whose match is unknown, in
	// document order.
	Indeterminate []string
	ReasonCodes   []string
	// Obligations are fresh clones; nothing here aliases the program.
	Obligations []*controlv1.Obligation
	// ReadExternal are the rules whose value turns on the external answer, in
	// document order: each reads it and has no other constraint that is
	// false. The list is the same whatever the answer, so a caller that
	// evaluated without one learns whether an answer could change the result.
	ReadExternal []string
	// UnknownAllows are the ALLOW rules whose match is unknown, in document
	// order. Such a rule is no match and changes no other field; a caller
	// that decided without some inputs learns which of them a rule lacked.
	UnknownAllows []UnknownAllow
}

// UnknownAllow is an ALLOW rule whose match is unknown and the inputs its
// unknown constraints lacked, in wire spelling as Unread names them, once
// each in the rule's order.
type UnknownAllow struct {
	ID    string
	Needs []string
}

// Program is a compiled document. It is immutable and safe to share: Compile
// copies everything it keeps, and Evaluate writes to nothing the program holds.
type Program struct {
	rules []rule
	// compiled is set by Compile alone, so that a Program nobody compiled, the
	// zero value included, is never read as a policy in which nothing matched.
	compiled bool
}

// Compile turns a parsed document into a program. It refuses a document the
// program could not carry as its author wrote it; see compileRule.
func Compile(doc *rules.Document) (*Program, error) {
	if doc == nil {
		return nil, &compileError{rule: -1, err: errNoDocument}
	}
	compiled := make([]rule, 0, len(doc.Rules))
	seen := make(map[string]bool, len(doc.Rules))
	for i := range doc.Rules {
		r, err := compileRule(i, &doc.Rules[i])
		if err != nil {
			return nil, err
		}
		// An id names the rule in the decision, so two rules may not share one.
		if seen[r.id] {
			return nil, &compileError{rule: i, field: "id", err: errRuleID}
		}
		seen[r.id] = true
		compiled = append(compiled, r)
	}
	return &Program{rules: compiled, compiled: true}, nil
}

// ReadsExternal reports whether a rule of the program reads the external
// answer.
func (p *Program) ReadsExternal() bool {
	return p != nil && slices.ContainsFunc(p.rules, func(r rule) bool { return r.external })
}

// Evaluate decides one envelope against the program. It has no error to
// return: an input it cannot read makes a constraint unknown, never false.
func (p *Program) Evaluate(env *controlv1.ActionEnvelope, in Inputs) Result {
	return p.evaluate(env, in, nil)
}

// evaluate is the one evaluation Evaluate and Explain share, so that an
// explanation never describes a result the decision path did not reach. A
// rule's trace is taken after its value and changes nothing the tally reads.
func (p *Program) evaluate(env *controlv1.ActionEnvelope, in Inputs, traces *[]RuleTrace) Result {
	if p == nil || !p.compiled {
		return unavailable()
	}
	var t tally
	for i := range p.rules {
		r := &p.rules[i]
		v, turns := r.holds(env, &in)
		t.record(r, v, turns, env, &in)
		if traces != nil {
			*traces = append(*traces, r.trace(env, &in, v))
		}
	}
	return t.result()
}
