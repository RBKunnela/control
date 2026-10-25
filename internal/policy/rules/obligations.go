package rules

import (
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/pkg/contract"
)

// Grammar is the spelling an obligation parameter's value must have: the
// values its applier acts on as written. The zero Grammar is no grammar, and
// no catalogue entry carries it. Each applier's package holds its grammars to
// what it applies with a property test.
type Grammar uint8

const (
	// GrammarMemberNames is comma-separated top-level member names, each
	// non-empty and without ".", "/" or white space, which the applier would
	// have to read as a path or a pattern it does not follow.
	GrammarMemberNames Grammar = iota + 1
	// GrammarMemberName is the exact name of one top-level member. The applier
	// looks the name up as written, so every string names a member some
	// arguments can hold.
	GrammarMemberName
	// GrammarInteger is a base-10 integer from the smallest integer canon
	// writes to the largest int64, with an optional sign, as strconv.ParseInt
	// reads it. cap_amount writes it into arguments that are canonicalized
	// after the rewrite, and a larger one never replaces an amount canon read.
	GrammarInteger
	// GrammarIdentifiers is comma-separated resource ids, none empty and each
	// one the identifier rule admits: an entry no envelope can carry as its
	// resource id never matches one.
	GrammarIdentifiers
	// GrammarResourcePrefix is an identifier, as a resource id is one, whose
	// last "/"-separated segment is printable ASCII without "%", ";", "?",
	// "#" or "\": every resource id under such a prefix starts its unchecked
	// rest with that segment, so one holding those bytes admits no id.
	GrammarResourcePrefix
	// GrammarMilliseconds is a base-10 integer from 1 to the largest count of
	// milliseconds a time.Duration holds.
	GrammarMilliseconds
)

// maxMilliseconds is the largest timeout a duration in nanoseconds holds.
const maxMilliseconds = int64(math.MaxInt64 / time.Millisecond)

// Describe is the grammar as the reference page and a refusal state it, or ""
// for a value that is no grammar.
func (g Grammar) Describe() string {
	switch g {
	case GrammarMemberNames:
		return "comma-separated top-level member names, each non-empty and without `.`, `/` or white space"
	case GrammarMemberName:
		return "the exact name of one top-level member"
	case GrammarInteger:
		return "a base-10 integer from " + strconv.FormatInt(canon.MinSafeInteger, 10) + " to " + strconv.FormatInt(math.MaxInt64, 10) + ", with an optional sign"
	case GrammarIdentifiers:
		return "comma-separated resource ids, none empty and each one the identifier rule admits"
	case GrammarResourcePrefix:
		return "an identifier whose last `/`-separated segment is printable ASCII without `%`, `;`, `?`, `#` or `\\`"
	case GrammarMilliseconds:
		return "a base-10 integer from 1 to " + strconv.FormatInt(maxMilliseconds, 10)
	}
	return ""
}

// accepts reports whether s is spelled in g. A value that is no grammar
// accepts nothing.
func (g Grammar) accepts(s string) bool {
	switch g {
	case GrammarMemberNames:
		return everyEntry(s, func(name string) bool {
			return !strings.ContainsAny(name, "./") && strings.IndexFunc(name, unicode.IsSpace) < 0
		})
	case GrammarMemberName:
		return true
	case GrammarInteger:
		n, err := strconv.ParseInt(s, 10, 64)
		return err == nil && n >= canon.MinSafeInteger
	case GrammarIdentifiers:
		return everyEntry(s, func(id string) bool {
			return len(id) <= contract.MaxStringBytes && contract.CheckIdentifier(id) == nil
		})
	case GrammarResourcePrefix:
		return resourcePrefix(s)
	case GrammarMilliseconds:
		n, err := strconv.ParseInt(s, 10, 64)
		return err == nil && n >= 1 && n <= maxMilliseconds
	}
	return false
}

// everyEntry reports whether s is a comma-separated list whose every entry is
// non-empty and passes ok.
func everyEntry(s string, ok func(string) bool) bool {
	for entry := range strings.SplitSeq(s, ",") {
		if entry == "" || !ok(entry) {
			return false
		}
	}
	return true
}

// resourcePrefix reports whether some resource id an envelope can carry
// passes under prefix s. It mirrors plainBelow and plainByte in adapters/mcp,
// which judge the id from the start of the prefix's last segment on. A prefix
// at the byte bound admits only itself, whose last segment must then not be
// all dots and spaces.
func resourcePrefix(s string) bool {
	if s == "" || len(s) > contract.MaxStringBytes || contract.CheckIdentifier(s) != nil {
		return false
	}
	last := s[strings.LastIndex(s, "/")+1:]
	for i := range len(last) {
		switch b := last[i]; {
		case b == '%', b == ';', b == '?', b == '#', b == '\\', b < 0x20, b > 0x7e:
			return false
		}
	}
	if len(s) == contract.MaxStringBytes && last != "" && strings.Trim(last, ". ") == "" {
		return false
	}
	return true
}

// CheckObligations holds every obligation of doc to its type's entry in the
// catalogue: no parameter the type does not declare, every required one
// present, one of a OneOf set present, and each value in its grammar. It
// returns the first refusal in document order, a parameter named by its
// position in sorted key order. Parse and Load do not call it, so a bundle
// signed without the check still loads and its applier still refuses what it
// cannot apply; Sign and policy lint do.
func CheckObligations(doc *Document) error {
	if doc == nil {
		return &Error{Err: fmt.Errorf("%w: no document", ErrEmpty)}
	}
	for i, rule := range doc.Rules {
		a := at{}.key("rules").index(i)
		a.rule = rule.ID
		for j, o := range rule.Obligations {
			if err := checkObligation(o, a.key("obligations").index(j)); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkObligation(o Obligation, a at) error {
	spec, ok := obligationSpec(o.Type)
	if !ok {
		return a.key("type").refuse(ErrObligationType)
	}
	p := a.key("params")
	for k, key := range slices.Sorted(maps.Keys(o.Params)) {
		i := slices.IndexFunc(spec.Params, func(param Param) bool { return param.Name == key })
		if i < 0 {
			return p.index(k).key("key").refuse(undeclared(spec))
		}
		if g := spec.Params[i].Grammar; !g.accepts(o.Params[key]) {
			return p.index(k).refuse(fmt.Errorf("%w: want %s", ErrObligationValue, g.Describe()))
		}
	}
	for _, param := range spec.Params {
		if _, present := o.Params[param.Name]; param.Required && !present {
			return p.refuse(fmt.Errorf("%w: %s requires %q", ErrObligationParam, spec.Type, param.Name))
		}
	}
	if len(spec.OneOf) > 0 && !slices.ContainsFunc(spec.OneOf, func(name string) bool {
		_, present := o.Params[name]
		return present
	}) {
		return p.refuse(fmt.Errorf("%w: %s requires one of %s", ErrObligationParam, spec.Type, quoted(spec.OneOf)))
	}
	return nil
}

func undeclared(spec ObligationSpec) error {
	if len(spec.Params) == 0 {
		return fmt.Errorf("%w: %s takes no parameters", ErrObligationParam, spec.Type)
	}
	names := make([]string, len(spec.Params))
	for i, p := range spec.Params {
		names[i] = p.Name
	}
	return fmt.Errorf("%w: %s declares only %s", ErrObligationParam, spec.Type, quoted(names))
}

func quoted(names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strconv.Quote(n)
	}
	return strings.Join(out, ", ")
}
