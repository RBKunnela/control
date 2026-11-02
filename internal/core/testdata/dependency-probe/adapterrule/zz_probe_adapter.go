// Package ioprobe is the adapter rule's negative fixture.
// scripts/check-imports-probe.sh plants it as a new package under adapters/,
// beside an import of each tree adapter_denied names, and requires each
// Decision composed here to be refused.
package ioprobe

import controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"

// Literal composes a Decision by a composite literal.
func Literal() *controlv1.Decision { return &controlv1.Decision{DecisionId: "probe"} }

// Made composes a Decision by new.
func Made() *controlv1.Decision { return new(controlv1.Decision) }

// D is an alias, which a syntactic check cannot see through.
type D = controlv1.Decision

// Aliased composes a Decision through the alias.
func Aliased() *D { return &D{} }
