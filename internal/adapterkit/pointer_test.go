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

func TestAPlaceholderTiesTheRecordToTheOriginal(t *testing.T) {
	if got := adapterkit.Placeholder(""); got != "" {
		t.Errorf("Placeholder of nothing = %q", got)
	}
	const abc = "overlong:sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := adapterkit.Placeholder("abc"); got != abc {
		t.Errorf("Placeholder(abc) = %q, want %q", got, abc)
	}
}
