package adapterkit_test

import (
	"testing"

	"github.com/guardana/control/internal/adapterkit"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/classify"
)

// FuzzResourceID holds the reading of a resource id to the canonical form:
// a document and its canonical spelling name one resource, and bytes that
// name the same member as the proposed ones are never a moved resource.
func FuzzResourceID(f *testing.F) {
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
		id := adapterkit.ResourceID(args, pointer)
		canonical, err := canon.CanonicalizeJSON(args)
		if err != nil {
			return
		}
		if got := adapterkit.ResourceID(canonical, pointer); got != id {
			t.Fatalf("ResourceID(%q, %q) = %q, of its canonical form %q = %q", args, pointer, id, canonical, got)
		}
		if id != "" && !adapterkit.SameResource(args, canonical, pointer, id) {
			t.Fatalf("the canonical form of %q moved the resource %q at %q", args, id, pointer)
		}
	})
}
