package gateway

import (
	"testing"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/classify"
)

// TestSameResourceHoldsTheAuthorizedBytesToTheDecidedMember: rewritten bytes
// keep the resource only when the member reads as the decided id and is the
// proposed member in canonical form; an object, a list or a boolean there
// reads as no id on either side, so a rewrite inside it is caught by the
// second test alone.
func TestSameResourceHoldsTheAuthorizedBytesToTheDecidedMember(t *testing.T) {
	for _, tc := range []struct {
		name, proposed, authorized, pointer, decided string
		same                                         bool
	}{
		{"a string kept", `{"path":"a","x":1}`, `{"path":"a"}`, "/path", "a", true},
		{"a string moved", `{"path":"a"}`, `{"path":"b"}`, "/path", "a", false},
		{"a member kept that is not the decided id", `{"path":"a"}`, `{"path":"a"}`, "/path", "b", false},
		{"a string redacted away", `{"path":"a","x":1}`, `{"x":1}`, "/path", "a", false},
		{"a number respelled", `{"n":42}`, `{"n":4.2e1}`, "/n", "42", true},
		{"a number moved", `{"n":42}`, `{"n":43}`, "/n", "42", false},
		{"a number turned string", `{"n":42}`, `{"n":"42"}`, "/n", "42", false},
		{"an object rewritten inside", `{"path":{"a":"/x"}}`, `{"path":{"a":"/etc/shadow"}}`, "/path", "", false},
		{"an object kept and respelled", `{"path":{"a":"/x","b":2}}`, `{"path":{"b":2.0,"a":"/x"},"extra":1}`, "/path", "", true},
		{"a boolean flipped", `{"path":true}`, `{"path":false}`, "/path", "", false},
		{"a list rewritten", `{"path":["/x"]}`, `{"path":["/etc/shadow"]}`, "/path", "", false},
		{"an absent member made present", `{"other":1}`, `{"path":{"a":"/etc/shadow"}}`, "/path", "", false},
		{"an absent member left absent", `{"other":1}`, `{"other":2}`, "/path", "", true},
		{"a null member removed", `{"path":null}`, `{}`, "/path", "", false},
		{"authorized bytes that are not JSON", `{"path":"a"}`, `not json`, "/path", "a", false},
		{"proposed bytes that are not JSON", `not json`, `{"path":"a"}`, "/path", "a", false},
		{"no pointer, no id", `{"a":1}`, `{"a":2}`, "", "", true},
		{"no pointer, an id", `{"a":1}`, `{"a":1}`, "", "a", false},
	} {
		if got := sameResource([]byte(tc.proposed), []byte(tc.authorized), tc.pointer, tc.decided); got != tc.same {
			t.Errorf("%s: sameResource = %v, want %v", tc.name, got, tc.same)
		}
	}
}

// FuzzSameResource holds the moved-resource check to the canonical form:
// bytes that respell the proposed ones canonically name the same member, so
// they are never a moved resource.
func FuzzSameResource(f *testing.F) {
	for _, seed := range []struct{ args, pointer string }{
		{`{"n":42}`, "/n"},
		{`{"n":4.2e1,"m":"x"}`, "/n"},
		{`{"a":{"b/c":["x",7.0]}}`, "/a/b~1c/1"},
		{`{"path":{"a":"/x","b":2}}`, "/path"},
		{`{"n":-0.0}`, "/n"},
		{`[1,2]`, "/0"},
		{`not json`, "/a"},
	} {
		f.Add([]byte(seed.args), seed.pointer)
	}
	f.Fuzz(func(t *testing.T, args []byte, pointer string) {
		if classify.CheckPointer(pointer) != nil {
			return
		}
		id := ResourceID(args, pointer)
		canonical, err := canon.CanonicalizeJSON(args)
		if err != nil {
			return
		}
		if id != "" && !sameResource(args, canonical, pointer, id) {
			t.Fatalf("the canonical form of %q moved the resource %q at %q", args, id, pointer)
		}
	})
}
