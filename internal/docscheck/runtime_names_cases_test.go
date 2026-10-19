package docscheck

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/guardana/control/internal/docscheck/sitedoc/docsite"
)

const (
	acmeSummary = "What the acme-cli profile covers."
	acmeProfile = `{"id": "acme-cli", "claims": {"page": "docs/reference/acme-cli-hooks.md"}}`
)

// acmeTree is a tree with one profile whose runtime is Acme, every place the
// rule lets the name stand, and extra, the files a case adds.
func acmeTree(extra map[string]string) (fstest.MapFS, []string) {
	files := map[string]string{
		profilesDir + "acme-cli/profile.json":       acmeProfile,
		profilesDir + "acme-cli/fixtures/pre.json":  `{"tool":"Acme"}`,
		"docs/reference/acme-cli-hooks.md":          "---\ntitle: Acme hooks\nsummary: " + acmeSummary + "\n---\n\n# Acme hooks\n",
		"site/docs/reference/acme-cli-hooks.html":   "<h1>Acme hooks</h1>",
		"docs/status.md":                            "| [Acme hooks](reference/acme-cli-hooks.md#settings) | `experimental` |",
		"docs/reference/cli.md":                     "See [the page](acme-cli-hooks.md) and [Acme hooks](/docs/reference/acme-cli-hooks).",
		"docs/index.md":                             "- [Acme hooks](reference/acme-cli-hooks.md): " + acmeSummary,
		"site/docs/index.html":                      `<li><a href="/docs/reference/acme-cli-hooks">Acme hooks</a>: ` + acmeSummary + `</li>`,
		"site/docs/reference/cli.html":              `<li><a href="/docs/reference/acme-cli-hooks">Acme hooks</a></li>`,
		"site/sitemap.xml":                          "<url><loc>" + docsite.Origin + "/docs/reference/acme-cli-hooks</loc></url>",
		"docs/guides/a-runtime.md":                  "Read [the page](" + docsite.Origin + "/docs/reference/acme-cli-hooks.html#gaps).",
		"internal/hookbridge/bridge.go":             "package hookbridge",
		profilesDir + "neutral-runner/profile.json": `{"id": "neutral-runner", "claims": {"page": "docs/reference/neutral.md"}}`,
		"docs/reference/neutral.md":                 "---\ntitle: Neutral\nsummary: A neutral runner.\n---\n",
	}
	for name, body := range extra {
		files[name] = body
	}
	fsys := fstest.MapFS{}
	var names []string
	for name, body := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(body)}
		names = append(names, name)
	}
	slices.Sort(names)
	return fsys, names
}

func TestEveryPlaceTheRuleAllowsPasses(t *testing.T) {
	fsys, files := acmeTree(nil)
	problems, err := runtimeNameProblems(fsys, files)
	if err != nil || len(problems) != 0 {
		t.Fatalf("problems %v, %v", problems, err)
	}
}

func TestANameOutsideTheRuleIsCaught(t *testing.T) {
	for _, tc := range []struct{ name, file, body, want string }{
		{"a sentence of another page", "docs/concepts/x.md", "Hooks\n\nThe acme runtime calls a hook.", "docs/concepts/x.md:3:"},
		{"a code file", "internal/hookbridge/bridge.go", "package hookbridge\n\n// For ACME.", "internal/hookbridge/bridge.go:3:"},
		{"a test outside the profile", "internal/hookbridge/x_test.go", `LoadProfile("acme-cli")`, "internal/hookbridge/x_test.go:1:"},
		{"a link to another page", "docs/reference/cli.md", "See [Acme hooks](policy-format.md).", "docs/reference/cli.md:1:"},
		{"a link to the page and the name beside it", "docs/reference/cli.md", "See [the page](acme-cli-hooks.md) for Acme.", "docs/reference/cli.md:1:"},
		{"a link elsewhere whose path has the page's name", "docs/reference/cli.md", "[x](../guides/acme-cli-hooks.md)", "docs/reference/cli.md:1:"},
		{"an index row that links another page", "docs/index.md", "- [Acme hooks](reference/cli.md): " + acmeSummary, "docs/index.md:1:"},
		{"an index row with another summary", "docs/index.md", "- [Acme hooks](reference/acme-cli-hooks.md): Acme is fast.", "docs/index.md:1:"},
		{"a site index row with another summary", "site/docs/index.html", `<li><a href="/docs/reference/acme-cli-hooks">Acme hooks</a>: Acme is fast.</li>`, "site/docs/index.html:1:"},
		{"a site link to another page", "site/docs/reference/cli.html", `<a href="/docs/reference/cli">Acme</a>`, "site/docs/reference/cli.html:1:"},
		{"a sitemap entry of another page", "site/sitemap.xml", "<loc>https://example.org/docs/acme</loc>", "site/sitemap.xml:1:"},
		{"a path that names it", "scripts/acme.sh", "#!/bin/sh", "scripts/acme.sh: the path"},
		{"prose as the text of a link to the page", "docs/guides/x.md", "Use [Acme, the only runtime we support](../reference/acme-cli-hooks.md).", "docs/guides/x.md:1:"},
		{"a Go string holding a link to the page", "internal/x/x.go", "package x\n\nconst s = \"[Acme hooks](../../docs/reference/acme-cli-hooks.md)\"", "internal/x/x.go:3:"},
		{"a link to the page's path on another host", "docs/guides/x.md", "See [the page](https://acme.example/docs/reference/acme-cli-hooks).", "docs/guides/x.md:1:"},
		{"a link on a host that starts like the site's", "docs/guides/x.md", "See [the page](" + docsite.Origin + ".acme.example/docs/reference/acme-cli-hooks).", "docs/guides/x.md:1:"},
		{"a link to the page with another attribute", "site/docs/reference/cli.html", `<a data-vendor="acme" href="/docs/reference/acme-cli-hooks">Acme recommends this</a>`, "site/docs/reference/cli.html:1:"},
		{"an attribute beside the page's title", "site/docs/reference/cli.html", `<a data-vendor="acme" href="/docs/reference/acme-cli-hooks">Acme hooks</a>`, "site/docs/reference/cli.html:1:"},
		{"a site link to the page with other text", "site/docs/reference/cli.html", `<a href="/docs/reference/acme-cli-hooks">Acme recommends this</a>`, "site/docs/reference/cli.html:1:"},
		{"an index row with another title", "docs/index.md", "- [Acme, the best](reference/acme-cli-hooks.md): " + acmeSummary, "docs/index.md:1:"},
		{"a link to the page in a file nothing generates", "site/notes.txt", `<a href="/docs/reference/acme-cli-hooks">Acme hooks</a>`, "site/notes.txt:1:"},
		{"another profile's directory", profilesDir + "neutral-runner/fixtures/a.json", `{"tool":"Acme"}`, profilesDir + "neutral-runner/fixtures/a.json:1:"},
	} {
		fsys, files := acmeTree(map[string]string{tc.file: tc.body})
		problems, err := runtimeNameProblems(fsys, files)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(problems) != 1 || !strings.HasPrefix(problems[0], tc.want) {
			t.Errorf("%s: problems %v, want one at %s", tc.name, problems, tc.want)
		}
	}
}

func TestATreeWithoutAProfileOrPageIsRefused(t *testing.T) {
	for name, drop := range map[string]string{
		"no profile": profilesDir + "acme-cli/profile.json",
		"no page":    "docs/reference/acme-cli-hooks.md",
	} {
		fsys, files := acmeTree(nil)
		delete(fsys, drop)
		files = slices.DeleteFunc(files, func(f string) bool { return f == drop })
		if name == "no profile" {
			delete(fsys, profilesDir+"neutral-runner/profile.json")
			files = slices.DeleteFunc(files, func(f string) bool { return strings.HasSuffix(f, "/profile.json") })
		}
		if _, err := runtimeNameProblems(fsys, files); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
