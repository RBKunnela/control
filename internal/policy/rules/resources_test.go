package rules

import (
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/guardana/control/pkg/contract"
)

// resourceCases is restrict_resources' table: an id passes as one of the exact
// ids or under the literal prefix, and under the prefix a segment or a byte a
// resolver could read as leaving it refuses the id while an exact id stays
// text.
var resourceCases = []struct {
	name   string
	params map[string]string
	id     string
	allow  bool
}{
	{"exact id", map[string]string{"ids": "/a,/b"}, "/b", true},
	{"id outside", map[string]string{"ids": "/a,/b"}, "/c", false},
	{"exact ids only, a longer id", map[string]string{"ids": "/a,/b"}, "/b/c", false},
	{"exact ids only, a shorter id", map[string]string{"ids": "/a,/bc"}, "/b", false},
	{"prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/x", true},
	{"prefix is literal", map[string]string{"prefix": "/srv/data/"}, "/srv/data-evil/x", false},
	{"prefix is not a string prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/database", false},
	{"deeper path under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a/b.c/..d", true},
	{"dot-dot under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/../../etc/passwd", false},
	{"dot-dot mid-path", map[string]string{"prefix": "a/"}, "a/../b", false},
	{"dot segment under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/./x", false},
	{"empty segment under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a//x", false},
	{"empty segment right after the prefix", map[string]string{"prefix": "a/"}, "a//b", false},
	{"backslash under the prefix", map[string]string{"prefix": "/srv/data/"}, `/srv/data/..\..\etc\passwd`, false},
	{"trailing dot-dot under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a/..", false},
	{"trailing slash under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a/", true},
	{"prefix without a slash", map[string]string{"prefix": "/srv/data"}, "/srv/data/x", true},
	{"dot-dot after a prefix without a slash", map[string]string{"prefix": "/srv/data"}, "/srv/data/../x", false},
	{"exact id is text", map[string]string{"ids": "/srv/data/../x"}, "/srv/data/../x", true},
	{"id equal to the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/", true},
	{"hyphen, underscore and tilde under the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a-b_c~d.txt", true},
	{"url prefix", map[string]string{"prefix": "https://api.example/v1/users/"}, "https://api.example/v1/users/42", true},
	{"encoded dot-dot", map[string]string{"prefix": "/srv/data/"}, "/srv/data/%2e%2e/%2e%2e/etc/passwd", false},
	{"encoded dot-dot right after the prefix", map[string]string{"prefix": "a/"}, "a/%2e%2e", false},
	{"encoded slash", map[string]string{"prefix": "/srv/data/"}, "/srv/data/..%2f..%2fetc%2fpasswd", false},
	{"encoded backslash", map[string]string{"prefix": "/srv/data/"}, "/srv/data/..%5c..%5cetc", false},
	{"fullwidth dots", map[string]string{"prefix": "/srv/data/"}, "/srv/data/．．/．．/etc/passwd", false},
	{"path parameter", map[string]string{"prefix": "/srv/data/"}, "/srv/data/..;/..;/etc/passwd", false},
	{"nul after dot-dot", map[string]string{"prefix": "/srv/data/"}, "/srv/data/..\x00", false},
	{"nul in a name", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a\x00b", false},
	{"control character", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a\tb", false},
	{"delete character", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a\x7fb", false},
	{"dot-dot and a space", map[string]string{"prefix": "/srv/data/"}, "/srv/data/.. ", false},
	{"dot-dot and a space mid-path", map[string]string{"prefix": "/srv/data/"}, "/srv/data/.. /etc/passwd", false},
	{"space segment", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a/ /b", false},
	{"space inside a name", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a b", true},
	{"three dots", map[string]string{"prefix": "/srv/data/"}, "/srv/data/.../x", false},
	{"file url encoded dot-dot", map[string]string{"prefix": "file:///srv/data/"}, "file:///srv/data/%2E%2E/%2E%2E/etc/passwd", false},
	{"https url encoded dot-dot", map[string]string{"prefix": "https://api.example/v1/users/"}, "https://api.example/v1/users/%2e%2e/admin", false},
	{"prefix ending in dot-dot", map[string]string{"prefix": "/srv/data/.."}, "/srv/data/../etc", false},
	{"id equal to a prefix ending in dot-dot", map[string]string{"prefix": "/srv/data/.."}, "/srv/data/..", false},
	{"percent in an exact id is text", map[string]string{"ids": "/srv/data/%2e%2e"}, "/srv/data/%2e%2e", true},
	{"https dot-dot before a query", map[string]string{"prefix": "https://api.example/pub/"}, "https://api.example/pub/..?x", false},
	{"https dot-dot before a fragment", map[string]string{"prefix": "https://api.example/pub/"}, "https://api.example/pub/..#x", false},
	{"file url dot-dot before an empty query", map[string]string{"prefix": "file:///srv/data/"}, "file:///srv/data/..?", false},
	{"query below the prefix", map[string]string{"prefix": "/srv/data/"}, "/srv/data/a?b", false},
	{"query in an exact id is text", map[string]string{"ids": "https://api.example/pub/a?x"}, "https://api.example/pub/a?x", true},
	{"either parameter matches", map[string]string{"ids": "/a", "prefix": "/srv/"}, "/srv/x", true},
	{"no parameter", nil, "/a", false},
	{"an unread parameter alone", map[string]string{"ms": "/"}, "/a", false},
	{"empty ids", map[string]string{"ids": ""}, "", false},
	{"empty id under ids with an empty entry", map[string]string{"ids": "/a,"}, "", false},
	{"empty prefix", map[string]string{"prefix": ""}, "/a", false},
	{"empty id under a prefix", map[string]string{"prefix": "/srv/"}, "", false},
}

func TestResourceAllowed(t *testing.T) {
	t.Parallel()
	for _, tc := range resourceCases {
		if got := ResourceAllowed(tc.id, tc.params); got != tc.allow {
			t.Errorf("%s: ResourceAllowed(%q, %v) = %v, want %v", tc.name, tc.id, tc.params, got, tc.allow)
		}
	}
}

// TestUnderPrefixJudgesFromTheLastSegment: the prefix's own last segment is
// held to the rule as the id's rest is, and the part before it is not.
func TestUnderPrefixJudgesFromTheLastSegment(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		id, prefix string
		want       bool
	}{
		{"a%2F/b/c", "a%2F/b/", true},
		{"a%2F/b/c", "a%2F/", true},
		{"a%2F/b/c", "a%2", false},
		{"x/../y/z", "x/../y/", true},
		{"x/..", "x/..", false},
		{"x/", "x/", true},
		{"x", "", false},
	} {
		if got := UnderPrefix(tc.id, tc.prefix); got != tc.want {
			t.Errorf("UnderPrefix(%q, %q) = %v, want %v", tc.id, tc.prefix, got, tc.want)
		}
	}
}

// FuzzResourceAllowed holds an id that passes under the prefix to what a path
// resolver reads it as: it starts with the prefix, carries no escape after
// it, and, below a prefix that ends in a slash, does not resolve outside that
// directory.
func FuzzResourceAllowed(f *testing.F) {
	for _, tc := range resourceCases {
		f.Add(tc.id, tc.params["ids"], tc.params["prefix"])
	}
	f.Fuzz(func(t *testing.T, id, ids, prefix string) {
		params := map[string]string{"ids": ids, "prefix": prefix}
		allowed := ResourceAllowed(id, params)
		if allowed != (ResourceAllowed(id, map[string]string{"ids": ids}) || UnderPrefix(id, prefix)) {
			t.Fatalf("ResourceAllowed(%q, %v) = %v is not the ids or the prefix", id, params, allowed)
		}
		if !UnderPrefix(id, prefix) {
			return
		}
		if !strings.HasPrefix(id, prefix) {
			t.Fatalf("%q passed under %q without starting with it", id, prefix)
		}
		rest := id[strings.LastIndex(prefix, "/")+1:]
		if strings.Contains(rest, "%") {
			t.Fatalf("%q passed under %q with an escape in %q", id, prefix, rest)
		}
		if strings.HasSuffix(prefix, "/") && !strings.HasPrefix(resolved(id), resolved(prefix)) {
			t.Fatalf("%q passed under %q and resolves to %q", id, prefix, resolved(id))
		}
	})
}

// resolved is s as a directory after a resolver removed its dot and empty
// segments, with one trailing slash.
func resolved(s string) string {
	var kept []string
	for _, segment := range strings.Split(s, "/") {
		switch segment {
		case "", ".":
		case "..":
			if len(kept) > 0 {
				kept = kept[:len(kept)-1]
			}
		default:
			kept = append(kept, segment)
		}
	}
	if len(kept) == 0 {
		return "/"
	}
	return "/" + strings.Join(kept, "/") + "/"
}

// TestResourceGrammarsAdmitWhatTheApplierLetsThrough: every entry of an ids
// value the grammar accepts is an id an envelope can carry and passes, and a
// prefix the grammar accepts lets some id an envelope can carry through.
func TestResourceGrammarsAdmitWhatTheApplierLetsThrough(t *testing.T) {
	piece := rapid.SampledFrom([]string{"a", "ord-1", "/", ".", "..", " ", ",", "%", "%2F", ";", "?", "#", "\\", "é", "\x7f", "x"})
	value := rapid.OneOf(
		rapid.String(),
		rapid.SampledFrom([]string{strings.Repeat("x", 1023) + "/", strings.Repeat("x", 1020) + "/..", strings.Repeat("x", 1024), "a/" + strings.Repeat("x", 1019) + "/.."}),
		rapid.Custom(func(t *rapid.T) string { return strings.Join(rapid.SliceOfN(piece, 0, 8).Draw(t, "pieces"), "") }),
	)
	rapid.Check(t, func(t *rapid.T) {
		ids := value.Draw(t, "ids")
		if GrammarIdentifiers.accepts(ids) {
			for id := range strings.SplitSeq(ids, ",") {
				if carriable(id) != nil || !ResourceAllowed(id, map[string]string{"ids": ids}) {
					t.Fatalf("ids %q: entry %q is accepted and never let through", ids, id)
				}
			}
		}
		prefix := value.Draw(t, "prefix")
		if !GrammarResourcePrefix.accepts(prefix) {
			return
		}
		id := prefix + "x"
		if len(prefix) >= contract.MaxStringBytes {
			id = prefix
		}
		if carriable(id) != nil || !ResourceAllowed(id, map[string]string{"prefix": prefix}) {
			t.Fatalf("prefix %q is accepted and does not let %q through", prefix, id)
		}
	})
}

// carriable is what the contract requires of an envelope's resource id.
func carriable(id string) error {
	if len(id) > contract.MaxStringBytes {
		return contract.ErrInvalidValue
	}
	return contract.CheckIdentifier(id)
}
