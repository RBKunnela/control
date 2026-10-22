package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
)

// The obligations the pipeline applies to the argument bytes itself; every
// other obligation is the adapter's to declare and to honour.
const (
	obligationRedactFields = "redact_fields"
	obligationCapAmount    = "cap_amount"
)

const (
	paramFields = "fields"
	paramMax    = "max"
	paramField  = "field"
)

// rewriting is the pipeline's own applicable set, in the order New declares
// it to the kernel.
var rewriting = []string{obligationRedactFields, obligationCapAmount}

// rewritingParams is the parameters each rewriting type reads. The catalogue
// holds no parameter schema, so this table is both what onlyParams checks
// and what the obligation reference page renders.
var rewritingParams = map[string][]string{
	obligationRedactFields: {paramFields},
	obligationCapAmount:    {paramMax, paramField},
}

// RewritingObligations returns the obligation types the pipeline applies
// itself, by rewriting the arguments before the decision it records.
func RewritingObligations() []string {
	return slices.Clone(rewriting)
}

// ObligationParams returns, for each type the pipeline rewrites, the
// parameters it reads; an obligation carrying any other is refused.
func ObligationParams() map[string][]string {
	out := make(map[string][]string, len(rewritingParams))
	for typ, params := range rewritingParams {
		out[typ] = slices.Clone(params)
	}
	return out
}

// errRewrite is an obligation of a rewriting type the pipeline cannot apply as
// written: a parameter it does not read, a value it cannot parse, or a member
// the arguments do not hold. The call is denied with OBLIGATION_NOT_UNDERSTOOD,
// which is what an obligation nobody applied is.
var errRewrite = errors.New("gateway: a rewriting obligation cannot be applied")

// rewrite applies the non-advisory rewriting obligations among obligations to
// args and returns the bytes to send and the obligations left for the
// adapter, advisory ones included. With nothing to apply the bytes are
// returned untouched, so an allowed call reaches the upstream with the exact
// bytes the agent sent; otherwise they are the canonical form of the
// rewritten document.
func rewrite(args []byte, obligations []*controlv1.Obligation) ([]byte, []*controlv1.Obligation, error) {
	var apply, rest []*controlv1.Obligation
	for _, o := range obligations {
		if !o.GetAdvisory() && slices.Contains(rewriting, o.GetType()) {
			apply = append(apply, o)
		} else {
			rest = append(rest, o)
		}
	}
	if len(apply) == 0 {
		return args, rest, nil
	}
	doc, err := argumentObject(args)
	if err != nil {
		return nil, nil, err
	}
	for _, o := range apply {
		switch o.GetType() {
		case obligationRedactFields:
			err = redactFields(doc, o.GetParams())
		case obligationCapAmount:
			err = capAmount(doc, o.GetParams())
		default:
			err = errors.New("no handler applies this type")
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %s: %w", errRewrite, o.GetType(), err)
		}
	}
	out, err := canon.Canonicalize(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errRewrite, err)
	}
	return out, rest, nil
}

// argumentObject reads args as the object the rewriting obligations work on.
// The bytes go through canon first, so a duplicate key, a number canon
// refuses or an oversized integer is refused there with canon's own pointer,
// and what comes back is a tree canon.Canonicalize takes.
func argumentObject(args []byte) (map[string]any, error) {
	if len(args) == 0 {
		return map[string]any{}, nil
	}
	canonical, err := canon.CanonicalizeJSON(args)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errRewrite, err)
	}
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: %w", errRewrite, err)
	}
	v, err = integers(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errRewrite, err)
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: the arguments are not an object", errRewrite)
	}
	return doc, nil
}

// integers turns every integer in v into the int64 cap_amount compares, and
// leaves every fraction the json.Number canon wrote, which canon.Canonicalize
// writes back unchanged. canon writes an integer inside the JSON-safe range
// as bare digits and a fraction always with a point or an exponent, so a
// failure here is a defect, not an input.
func integers(v any) (any, error) {
	switch t := v.(type) {
	case json.Number:
		if strings.ContainsAny(t.String(), ".e") {
			return t, nil
		}
		return strconv.ParseInt(t.String(), 10, 64)
	case []any:
		for i, item := range t {
			converted, err := integers(item)
			if err != nil {
				return nil, err
			}
			t[i] = converted
		}
	case map[string]any:
		for key, item := range t {
			converted, err := integers(item)
			if err != nil {
				return nil, err
			}
			t[key] = converted
		}
	}
	return v, nil
}

// redactFields removes the top-level members "fields" names, comma
// separated, under every spelling canon treats as one name: two member names
// that fold together are the same name to a consumer that matches without
// regard to case, so the fold canon refuses duplicates under is the one
// matched here. A member the arguments do not hold is not sent either way. An
// empty list, a name that is empty or holds whitespace, "." or "/", which
// would read as a path or a pattern this plane does not follow, and a
// parameter this plane does not read are refused: an obligation that asks for
// something else than what is applied is not applied. So is a document that
// still holds a top-level member name outside ASCII, for the reason below.
func redactFields(doc map[string]any, params map[string]string) error {
	if err := onlyParams(obligationRedactFields, params); err != nil {
		return err
	}
	if params[paramFields] == "" {
		return errors.New(`"fields" names no member`)
	}
	names := strings.Split(params[paramFields], ",")
	for i, name := range names {
		if name == "" || strings.ContainsAny(name, "./") || strings.IndexFunc(name, unicode.IsSpace) >= 0 {
			return fmt.Errorf(`"fields" entry %d is not a member name`, i)
		}
	}
	for _, name := range names {
		fold := canon.FoldKey(name)
		for key := range doc {
			if canon.FoldKey(key) == fold {
				delete(doc, key)
			}
		}
	}
	// The fold is simple folding, while an upstream that matches member names
	// under full case folding, or under its own normalization, can read a name
	// outside ASCII as one of the redacted ones. The plane cannot prove what
	// such a name means there, so a document that still holds one is refused.
	for key := range doc {
		if !isASCII(key) {
			return fmt.Errorf("member %q is outside ASCII and is not removed", key)
		}
	}
	return nil
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// capAmount lowers the integer member "field", "amount" unless named, to
// "max" when it is above it. A member that is absent or not an integer, a
// fraction among them, cannot be capped and is refused rather than passed
// through. 5000.0 is the integer 5000 by then, as it is to the digest.
func capAmount(doc map[string]any, params map[string]string) error {
	if err := onlyParams(obligationCapAmount, params); err != nil {
		return err
	}
	limit, err := strconv.ParseInt(params[paramMax], 10, 64)
	if err != nil {
		return fmt.Errorf(`"max" is not an integer: %w`, err)
	}
	field := "amount"
	if named, ok := params[paramField]; ok {
		field = named
	}
	value, ok := doc[field].(int64)
	if !ok {
		return fmt.Errorf("member %q is absent or not an integer", field)
	}
	if value > limit {
		doc[field] = limit
	}
	return nil
}

// onlyParams refuses a parameter outside the ones typ reads in
// rewritingParams: a parameter nobody read would be an instruction nobody
// followed.
func onlyParams(typ string, params map[string]string) error {
	known, ok := rewritingParams[typ]
	if !ok {
		return fmt.Errorf("%s declares no parameters", typ)
	}
	for key := range params {
		if !slices.Contains(known, key) {
			return fmt.Errorf("parameter %q is not one this plane applies", key)
		}
	}
	return nil
}
