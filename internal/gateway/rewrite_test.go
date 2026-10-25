package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/canon"
)

func obligation(kind string, advisory bool, params ...string) *controlv1.Obligation {
	o := &controlv1.Obligation{Type: kind, Advisory: advisory, Params: map[string]string{}}
	for i := 0; i+1 < len(params); i += 2 {
		o.Params[params[i]] = params[i+1]
	}
	return o
}

func TestRewriteLeavesBytesAloneWithNothingToApply(t *testing.T) {
	args := []byte(`{ "b" : 1 }`)
	rest := []*controlv1.Obligation{
		obligation("cap_rate", false, "per_minute", "60"),
		obligation("redact_fields", true, "fields", "b"),
	}
	out, left, err := rewrite(args, rest)
	if err != nil || !bytes.Equal(out, args) || len(left) != 2 {
		t.Errorf("rewrite with nothing to apply = %q, %d left, %v; want the same bytes and both obligations", out, len(left), err)
	}
}

func TestRewriteAppliesEachObligation(t *testing.T) {
	cases := []struct {
		name string
		args string
		obs  []*controlv1.Obligation
		want string
	}{
		{"redact one member", `{"ssn":"x","a":1}`, []*controlv1.Obligation{obligation("redact_fields", false, "fields", "ssn")}, `{"a":1}`},
		{"redact two members, one absent", `{"ssn":"x","a":1}`, []*controlv1.Obligation{obligation("redact_fields", false, "fields", "ssn,card")}, `{"a":1}`},
		{"cap above the limit", `{"amount":5000}`, []*controlv1.Obligation{obligation("cap_amount", false, "max", "1000")}, `{"amount":1000}`},
		{"cap at the limit", `{"amount":1000}`, []*controlv1.Obligation{obligation("cap_amount", false, "max", "1000")}, `{"amount":1000}`},
		{"cap below the limit", `{"amount":999}`, []*controlv1.Obligation{obligation("cap_amount", false, "max", "1000")}, `{"amount":999}`},
		{"cap a named member", `{"total":-5,"amount":9}`, []*controlv1.Obligation{obligation("cap_amount", false, "max", "-10", "field", "total")}, `{"amount":9,"total":-10}`},
		{"both, nested left alone", `{"amount":2,"ssn":"x","n":{"amount":99}}`, []*controlv1.Obligation{
			obligation("redact_fields", false, "fields", "ssn"), obligation("cap_amount", false, "max", "1"),
		}, `{"amount":1,"n":{"amount":99}}`},
		{"empty arguments redacted", ``, []*controlv1.Obligation{obligation("redact_fields", false, "fields", "ssn")}, `{}`},
		{"redact in capitals", `{"SSN":"x","a":1}`, []*controlv1.Obligation{obligation("redact_fields", false, "fields", "ssn")}, `{"a":1}`},
		{"redact capitalised", `{"Ssn":"x","a":1}`, []*controlv1.Obligation{obligation("redact_fields", false, "fields", "ssn")}, `{"a":1}`},
		{"redact with a long s", `{"\u017fsn":"x","a":1}`, []*controlv1.Obligation{obligation("redact_fields", false, "fields", "ssn")}, `{"a":1}`},
		{"redact with a kelvin sign", `{"\u212aey":"x","a":1}`, []*controlv1.Obligation{obligation("redact_fields", false, "fields", "KEY")}, `{"a":1}`},
		{"redact a name that is a prefix of another", `{"ssn":"x","ssnx":1}`, []*controlv1.Obligation{obligation("redact_fields", false, "fields", "SSN")}, `{"ssnx":1}`},
		{"redact keeps fractions canonical", `{"ssn":"x","t":0.70,"u":1E-7,"v":[2.0,-0.0,5e-324],"w":{"x":1.5}}`, []*controlv1.Obligation{obligation("redact_fields", false, "fields", "ssn")}, `{"t":0.7,"u":1e-7,"v":[2,0,5e-324],"w":{"x":1.5}}`},
		{"cap an amount written as an integral fraction", `{"amount":5000.0}`, []*controlv1.Obligation{obligation("cap_amount", false, "max", "1000")}, `{"amount":1000}`},
		{"cap leaves a fraction beside the amount", `{"amount":5,"rate":0.25}`, []*controlv1.Obligation{obligation("cap_amount", false, "max", "1")}, `{"amount":1,"rate":0.25}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, left, err := rewrite([]byte(tc.args), tc.obs)
			if err != nil || string(out) != tc.want || len(left) != 0 {
				t.Errorf("rewrite = %s, %d left, %v; want %s", out, len(left), err, tc.want)
			}
		})
	}
}

// TestReproducesHoldsTheSecondDecisionToTheBytes: the second decision's
// obligations have to give exactly the bytes it was asked about. The kernel
// reads no argument value, so no decision it makes today reaches the refusing
// cases through Admit; they are held here.
func TestReproducesHoldsTheSecondDecisionToTheBytes(t *testing.T) {
	proposed := []byte(`{"amount": 5000, "ssn": "x"}`)
	capped := []byte(`{"amount":1000,"ssn":"x"}`)
	advisory := obligation("cap_rate", true, "per_minute", "60")
	rest, ok := reproduces(proposed, capped, []*controlv1.Obligation{obligation("cap_amount", false, "max", "1000"), advisory})
	if !ok || len(rest) != 1 || rest[0] != advisory {
		t.Errorf("the same cap: %v, %v; want it reproduced with the advisory obligation left", rest, ok)
	}
	for name, obs := range map[string][]*controlv1.Obligation{
		"no obligation":           nil,
		"another cap":             {obligation("cap_amount", false, "max", "999")},
		"a cap it cannot apply":   {obligation("cap_amount", false, "max", "x")},
		"the cap and a redaction": {obligation("cap_amount", false, "max", "1000"), obligation("redact_fields", false, "fields", "ssn")},
		"the cap made advisory":   {obligation("cap_amount", true, "max", "1000")},
	} {
		if rest, ok := reproduces(proposed, capped, obs); ok || rest != nil {
			t.Errorf("%s: reproduces = %v, %v; want false", name, rest, ok)
		}
	}
}

// TestRewriteRefusesWhatItCannotApply: every refusal has the input at which
// it changes the result, and each is errRewrite.
func TestRewriteRefusesWhatItCannotApply(t *testing.T) {
	cases := []struct {
		name string
		args string
		ob   *controlv1.Obligation
	}{
		{"cap with no such member", `{"total":5}`, obligation("cap_amount", false, "max", "1")},
		{"cap of a string", `{"amount":"5"}`, obligation("cap_amount", false, "max", "1")},
		{"cap with no max", `{"amount":5}`, obligation("cap_amount", false)},
		{"cap with a max that is not an integer", `{"amount":5}`, obligation("cap_amount", false, "max", "1.5")},
		{"cap with a parameter this plane does not read", `{"amount":5}`, obligation("cap_amount", false, "max", "1", "currency", "EUR")},
		{"redact with no fields", `{"a":1}`, obligation("redact_fields", false)},
		{"redact with an empty name", `{"a":1}`, obligation("redact_fields", false, "fields", "a,")},
		{"redact with a space in a name", `{"a b":1}`, obligation("redact_fields", false, "fields", "a b")},
		{"redact with a leading space", `{"a":1}`, obligation("redact_fields", false, "fields", "a, b")},
		{"redact with a tab", `{"a":1}`, obligation("redact_fields", false, "fields", "a\t")},
		{"redact with a no-break space", `{"a":1}`, obligation("redact_fields", false, "fields", "a\u00a0")},
		{"redact with a dot", `{"a":{"b":1}}`, obligation("redact_fields", false, "fields", "a.b")},
		{"redact with a slash", `{"a":{"b":1}}`, obligation("redact_fields", false, "fields", "/a/b")},
		{"redact with a parameter this plane does not read", `{"a":1}`, obligation("redact_fields", false, "fields", "a", "mode", "hash")},
		{"cap with the parameter redact reads", `{"amount":5}`, obligation("cap_amount", false, "max", "1", "fields", "amount")},
		{"redact with a parameter cap reads", `{"a":1}`, obligation("redact_fields", false, "fields", "a", "max", "1")},
		{"redact leaving a member name outside ASCII", `{"ßn":1}`, obligation("redact_fields", false, "fields", "ssn")},
		{"redact leaving a member name in another script", `{"a":1,"ключ":2}`, obligation("redact_fields", false, "fields", "a")},
		{"arguments that are an array", `[1]`, obligation("redact_fields", false, "fields", "a")},
		{"arguments that are null", `null`, obligation("redact_fields", false, "fields", "a")},
		{"cap of a fractional amount", `{"amount":1.5}`, obligation("cap_amount", false, "max", "1")},
		{"cap of a fractional amount below the limit", `{"amount":0.5}`, obligation("cap_amount", false, "max", "1")},
		{"arguments with a number past a double", `{"amount":1,"n":1e400}`, obligation("cap_amount", false, "max", "1")},
		{"arguments with an inexact fraction", `{"amount":1,"n":0.30000000000000001}`, obligation("redact_fields", false, "fields", "amount")},
		{"arguments with a duplicate key", `{"amount":1,"amount":2}`, obligation("cap_amount", false, "max", "1")},
		{"arguments that are not JSON", `{`, obligation("cap_amount", false, "max", "1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, left, err := rewrite([]byte(tc.args), []*controlv1.Obligation{tc.ob})
			if !errors.Is(err, errRewrite) || out != nil || left != nil {
				t.Errorf("rewrite = %q, %v, %v; want nil, nil, errRewrite", out, left, err)
			}
		})
	}
}

// TestRewriteRefusesAListedTypeWithNoHandler: a type in the applicable set
// that rewrite has no case for is refused, never taken from the adapter with
// nothing applied.
func TestRewriteRefusesAListedTypeWithNoHandler(t *testing.T) {
	saved := rewriting
	rewriting = append(slices.Clone(rewriting), "emit_alert")
	t.Cleanup(func() { rewriting = saved })

	out, left, err := rewrite([]byte(`{"a":1}`), []*controlv1.Obligation{obligation("emit_alert", false, "severity", "high")})
	if !errors.Is(err, errRewrite) || out != nil || left != nil {
		t.Fatalf("rewrite = %q, %v, %v; want nil, nil, errRewrite", out, left, err)
	}
	if !strings.Contains(err.Error(), "emit_alert") {
		t.Errorf("the refusal %q does not name the type", err)
	}
}

// TestRewriteChecksParametersAgainstTheCatalogue: the names paramNames gives
// are the ones the handlers check, so a parameter they gain is accepted and
// one they lose is refused.
func TestRewriteChecksParametersAgainstTheCatalogue(t *testing.T) {
	saved := paramNames
	t.Cleanup(func() { paramNames = saved })
	ob := obligation("cap_amount", false, "max", "1", "currency", "EUR")

	paramNames = func(typ string) ([]string, bool) {
		names, ok := saved(typ)
		return append(names, "currency"), ok
	}
	if out, _, err := rewrite([]byte(`{"amount":5}`), []*controlv1.Obligation{ob}); err != nil || string(out) != `{"amount":1}` {
		t.Errorf("with currency declared: %q, %v", out, err)
	}
	paramNames = func(typ string) ([]string, bool) {
		names, ok := saved(typ)
		return slices.DeleteFunc(names, func(n string) bool { return n == paramMax }), ok
	}
	if _, _, err := rewrite([]byte(`{"amount":5}`), []*controlv1.Obligation{obligation("cap_amount", false, "max", "1")}); !errors.Is(err, errRewrite) {
		t.Errorf("with max no longer declared: %v, want errRewrite", err)
	}
}

// FuzzRewrite: for any document and parameters, rewrite either refuses or
// returns a canonical object in which the redacted members are absent, the
// capped member is at most the limit, and every other member is what the
// canonical form of the input holds.
func FuzzRewrite(f *testing.F) {
	f.Add([]byte(`{"amount":5000,"ssn":"x","keep":[1,2]}`), "ssn", "1000")
	f.Add([]byte(`{"amount":-1,"a":{"b":null}}`), "a,b", "-5")
	f.Add([]byte(``), "x", "0")
	f.Add([]byte(`{"amount":9007199254740991}`), "", "9007199254740990")
	f.Add([]byte(`{"amount":1,"amount":2}`), "amount", "1")
	f.Add([]byte(`{"amount":7.0,"t":0.70,"u":[1e-7,-0.0]}`), "ssn", "5")
	f.Add([]byte(`{"amount":2.5}`), "x", "1")
	f.Fuzz(func(t *testing.T, args []byte, fields, limit string) {
		obs := []*controlv1.Obligation{
			obligation("redact_fields", false, "fields", fields),
			obligation("cap_amount", false, "max", limit),
		}
		out, left, err := rewrite(args, obs)
		if err != nil {
			if !errors.Is(err, errRewrite) || out != nil || left != nil {
				t.Fatalf("a refusal that is not errRewrite, or one with a result: %q, %v, %v", out, left, err)
			}
			return
		}
		if len(left) != 0 {
			t.Fatalf("%d obligation(s) left after applying both", len(left))
		}
		doc := canonicalObject(t, out)
		checkRedacted(t, doc, fields, out)
		checkCapped(t, doc, limit, out)
		checkUntouched(t, args, doc, fields)
	})
}

// canonicalObject fails unless out is its own canonical form and an object.
func canonicalObject(t *testing.T, out []byte) map[string]any {
	t.Helper()
	again, err := canon.CanonicalizeJSON(out)
	if err != nil || !bytes.Equal(again, out) {
		t.Fatalf("the output is not canonical: %q (%v)", out, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("the output is not an object: %v", err)
	}
	return doc
}

func checkRedacted(t *testing.T, doc map[string]any, fields string, out []byte) {
	t.Helper()
	for key := range doc {
		if redacted(key, fields) {
			t.Fatalf("member %q, which folds with a redacted name, is still present in %s", key, out)
		}
	}
}

// redacted reports whether key folds with a name in fields, by
// strings.EqualFold, which compares under the same simple folding.
func redacted(key, fields string) bool {
	for _, name := range strings.Split(fields, ",") {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func checkCapped(t *testing.T, doc map[string]any, limit string, out []byte) {
	t.Helper()
	bound, err := strconv.ParseInt(limit, 10, 64)
	if err != nil {
		t.Fatalf("rewrite accepted a max it cannot parse: %q", limit)
	}
	amount, ok := doc["amount"].(float64)
	if !ok {
		t.Fatalf("the capped member is absent or not a number in %s", out)
	}
	if int64(amount) > bound {
		t.Fatalf("amount %v is above the limit %d in %s", amount, bound, out)
	}
}

// checkUntouched: every member that was neither redacted nor capped is what
// the canonical form of the input holds.
func checkUntouched(t *testing.T, args []byte, doc map[string]any, fields string) {
	t.Helper()
	canonicalIn, err := canon.CanonicalizeJSON(args)
	if len(args) == 0 {
		canonicalIn, err = []byte("{}"), nil
	}
	if err != nil {
		t.Fatalf("rewrite accepted a document canon refuses: %v", err)
	}
	var in map[string]any
	if err := json.Unmarshal(canonicalIn, &in); err != nil {
		t.Fatalf("the input is not an object: %v", err)
	}
	for name, value := range in {
		if name == "amount" || redacted(name, fields) {
			continue
		}
		got, _ := json.Marshal(doc[name])
		want, _ := json.Marshal(value)
		if !bytes.Equal(got, want) {
			t.Fatalf("member %q changed from %s to %s", name, want, got)
		}
	}
}
