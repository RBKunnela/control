package policy

import "github.com/guardana/control/pkg/contract"

// MaxSerial is the largest serial a signed document can carry, a bundle's, a
// statement's or a route's: its body is canonical JSON, which holds an
// integer to the JSON-safe range.
const MaxSerial = 1<<53 - 1

// ValidID reports whether id is an id a bundle, a statement or a route can
// carry: one contract.CheckID takes, the rule a policy document holds its own
// id to.
func ValidID(id string) bool {
	return contract.CheckID(id) == nil
}
