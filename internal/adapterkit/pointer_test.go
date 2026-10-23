package adapterkit_test

import (
	"testing"

	"github.com/guardana/control/internal/adapterkit"
)

// TestResourceIDOfANumberIsItsCanonicalText: a number at the pointer becomes
// the text the digest writes for it, so 42.0 names the resource 42 names and
// a rule on that id matches both spellings.
func TestResourceIDOfANumberIsItsCanonicalText(t *testing.T) {
	for args, want := range map[string]string{
		`{"n":42}`:                  "42",
		`{"n":42.0}`:                "42",
		`{"n":4.2e1}`:               "42",
		`{"n":-0.0}`:                "0",
		`{"n":0.70}`:                "0.7",
		`{"n":1e-7}`:                "1e-7",
		`{"n":"42.0"}`:              "42.0",
		`{"n":9007199254740992}`:    "",
		`{"n":0.30000000000000001}`: "",
		`{"n":1e400}`:               "",
		`{"n":[42]}`:                "",
	} {
		if got := adapterkit.ResourceID([]byte(args), "/n"); got != want {
			t.Errorf("ResourceID(%s) = %q, want %q", args, got, want)
		}
	}
}

func TestResourceIDFollowsThePointer(t *testing.T) {
	args := []byte(`{"a":{"b/c":["x","y"],"d~e":"z","":"empty","f~1":"tilde-one","f/":"slash"},"t":true,"z":null}`)
	for p, want := range map[string]string{
		"":            "",
		"/a/b~1c/1":   "y",
		"/a/b~1c/0":   "x",
		"/a/d~0e":     "z",
		"/a/f~01":     "tilde-one",
		"/a/f~1":      "slash",
		"/a/":         "empty",
		"/a/b~1c/2":   "",
		"/a/b~1c/01":  "",
		"/a/b~1c/-1":  "",
		"/a/b~1c/+1":  "",
		"/a/b~1c/-0":  "",
		"/a/b~1c/+0":  "",
		"/a/b~1c/+01": "",
		"/a/b~1c/ 1":  "",
		"/a/missing":  "",
		"/t":          "",
		"/z":          "",
		"/a":          "",
	} {
		if got := adapterkit.ResourceID(args, p); got != want {
			t.Errorf("ResourceID(%q) = %q, want %q", p, got, want)
		}
	}
	for _, bad := range []string{``, `not json`, `{"a":`} {
		if got := adapterkit.ResourceID([]byte(bad), "/a"); got != "" {
			t.Errorf("ResourceID of %q = %q, want no id", bad, got)
		}
	}
}

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
		if got := adapterkit.SameResource([]byte(tc.proposed), []byte(tc.authorized), tc.pointer, tc.decided); got != tc.same {
			t.Errorf("%s: SameResource = %v, want %v", tc.name, got, tc.same)
		}
	}
}

func TestAPlaceholderTiesTheRecordToTheOriginal(t *testing.T) {
	if got := adapterkit.Placeholder(""); got != "" {
		t.Errorf("Placeholder of nothing = %q", got)
	}
	const abc = "overlong:sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := adapterkit.Placeholder("abc"); got != abc {
		t.Errorf("Placeholder(abc) = %q, want %q", got, abc)
	}
}
