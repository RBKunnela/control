package docsite

import (
	"bufio"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/renderer"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/docscheck/impact"
)

// released is older than the fixture changelog's newest dated section, as
// while the next release is being prepared.
const released = "0.1.0"

const pageHead = "---\ntitle: A page\nsummary: What the page is for.\ntype: explanation\ncovers: [x/**]\n---\n\n"

// fixture is a repository with the pages Build requires, a code file, a
// directory and one page whose body the case supplies.
func fixture(body string) fstest.MapFS {
	return fstest.MapFS{
		"docs/index.md":          {Data: []byte("---\ntitle: Documentation\nsummary: Every page.\ntype: project\ncovers: [docs/**]\n---\n\n# Documentation\n\n## Decision records\n")},
		"docs/concepts/a.md":     {Data: []byte(pageHead + body)},
		"docs/concepts/b.md":     {Data: []byte(pageHead + "# B\n\n## Part\n\n## Part\n")},
		"docs/adr/0001-first.md": {Data: []byte("# ADR-0001: First\n\nStatus: accepted\n")},
		"ROADMAP.md":             {Data: []byte("# Roadmap\n\nPlanned.\n")},
		"CHANGELOG.md":           {Data: []byte("# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2026-01-02\n\n## [0.1.0] - 2026-01-01\n")},
		"cmd/tool/main.go":       {Data: []byte("package main\n")},
		"examples/demo/x.txt":    {Data: []byte("x\n")},
		"README.md":              {Data: []byte("# Product\n\n**Watch every call.**\n\nIt decides each call\nbefore it runs.\n\n## More\n")},
	}
}

func build(t *testing.T, body string) (map[string][]byte, error) {
	t.Helper()
	return buildAll(fixture(body))
}

// buildAll builds fsys with every file it holds listed and none excluded.
func buildAll(fsys fstest.MapFS) (map[string][]byte, error) {
	return Build(fsys, listingOf(fsys), released)
}

func listingOf(fsys fstest.MapFS, unlisted ...string) impact.Listing {
	paths := slices.DeleteFunc(slices.Collect(maps.Keys(fsys)), func(rel string) bool { return slices.Contains(unlisted, rel) })
	return impact.LeftOut(paths, func(string) bool { return false })
}

func renderA(t *testing.T, body string) string {
	t.Helper()
	files, err := build(t, body)
	if err != nil {
		t.Fatal(err)
	}
	out, ok := files[Dir+"/concepts/a.html"]
	if !ok {
		t.Fatalf("no %s/concepts/a.html among %d files", Dir, len(files))
	}
	return string(out)
}

func TestLinksPointAtThePageOrItsSource(t *testing.T) {
	out := renderA(t, "# A\n\n[b](b.md), [part](b.md#part-1), [here](#a), [code](../../cmd/tool/main.go), "+
		"[dir](../../examples/demo/), [roadmap](../../ROADMAP.md), [record](../adr/0001-first.md), [web](https://example.invalid/x)\n")
	for _, want := range []string{
		`href="/docs/concepts/b"`,
		`href="/docs/concepts/b#part-1"`,
		`href="#a"`,
		`href="https://github.com/guardana/control/blob/main/cmd/tool/main.go"`,
		`href="https://github.com/guardana/control/tree/main/examples/demo"`,
		`href="/docs/roadmap"`,
		`href="/docs/adr/0001-first"`,
		`href="https://example.invalid/x"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the page lacks %s", want)
		}
	}
}

func TestHeadingsTakeGitHubsAnchors(t *testing.T) {
	files, err := build(t, "# A\n")
	if err != nil {
		t.Fatal(err)
	}
	out := string(files[Dir+"/concepts/b.html"])
	for _, want := range []string{`<h1 id="b">B</h1>`, `<h2 id="part">Part</h2>`, `<h2 id="part-1">Part</h2>`} {
		if !strings.Contains(out, want) {
			t.Errorf("the page lacks %s", want)
		}
	}
}

func TestRefusalsNameTheFileLine(t *testing.T) {
	// The body starts on line 8 of the file, after the frontmatter and a blank line.
	cases := map[string]struct{ body, want string }{
		"a link to a path the repository lacks": {"# A\n\n[gone](../../nowhere.md)\n", "line 10: link \"../../nowhere.md\" names nowhere.md, which the repository does not hold"},
		"a link out of the repository":          {"# A\n\n[out](../../../x.md)\n", "line 10: link \"../../../x.md\" escapes the repository"},
		"an empty link":                         {"# A\n\n[empty]()\n", "line 10: an empty link"},
		"raw HTML as a block":                   {"# A\n\n<div>x</div>\n", "line 10: raw HTML"},
		"raw HTML inline":                       {"# A\n\ntext <b>bold</b> text\n", "line 10: raw HTML"},
		"an image":                              {"# A\n\n![alt](b.md)\n", "line 10: an image"},
		"a diagram with no text alternative":    {"# A\n\n```mermaid\nflowchart LR\n    A --> B\n```\n", "line 10: diagram: a Mermaid block needs"},
		"a javascript: link":                    {"# A\n\n[x](javascript:alert(1))\n", "line 10: link \"javascript:alert(1)\": only http, https and mailto"},
		"a data: link by reference":             {"# A\n\n[x][r]\n\n[r]: data:text/html,x\n", "line 10: link \"data:text/html,x\": only http, https and mailto"},
		"a javascript: autolink":                {"# A\n\n<javascript:alert(1)>\n", "line 10: link \"javascript:alert(1)\": only http, https and mailto"},
		"text after a comment block":            {"# A\n\n<!-- c --><b>x</b>\n", "line 10: raw HTML"},
		"a heading that takes the layout's id":  {"# A\n\n## Main\n", `the id "main" is used twice`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := build(t, c.body)
			if err == nil {
				t.Fatal("rendered; want a refusal")
			}
			if !errors.Is(err, ErrSite) || !strings.Contains(err.Error(), "docs/concepts/a.md: "+c.want) {
				t.Errorf("err = %v, want it to name docs/concepts/a.md and %q", err, c.want)
			}
		})
	}
}

func TestAnHTMLCommentRendersAsNothing(t *testing.T) {
	out := renderA(t, "# A\n\n<!-- generated: x -->\n\ntext <!-- inline --> text\n")
	if strings.Contains(out, "generated: x") || strings.Contains(out, "inline") || strings.Contains(out, "omitted") {
		t.Errorf("a comment reached the page:\n%s", out)
	}
}

func TestADiagramIsDrawnOrDescribedNeverDropped(t *testing.T) {
	drawn := renderA(t, "# A\n\n```mermaid\nflowchart LR\n    accTitle: Two steps\n    accDescr: A leads to B.\n    A[One] --> B[Two]\n```\n")
	if !strings.Contains(drawn, "<svg") || strings.Contains(drawn, `class="dg-text"`) {
		t.Errorf("a flowchart in the subset was not drawn:\n%s", drawn)
	}
	described := renderA(t, "# A\n\n```mermaid\nsequenceDiagram\n    accTitle: One message\n    accDescr: A asks B.\n    A->>B: one & two\n```\n")
	for _, want := range []string{
		`class="dg-text"`, "<figcaption>One message</figcaption>",
		`<p>A asks B. <a href="https://github.com/guardana/control/blob/main/docs/concepts/a.md">Drawn on GitHub</a>.</p>`,
		"A-&gt;&gt;B: one &amp; two",
	} {
		if !strings.Contains(described, want) {
			t.Errorf("the described diagram lacks %s:\n%s", want, described)
		}
	}
}

func TestCodeIsEscaped(t *testing.T) {
	out := renderA(t, "# A\n\n```sh\necho '<script>' && x\n```\n")
	if !strings.Contains(out, `<pre><code class="language-sh">echo &#39;&lt;script&gt;&#39; &amp;&amp; x`) {
		t.Errorf("the code block is not escaped:\n%s", out)
	}
}

// Each table sits in a box of its own, which scrolls it when it is wider
// than the page, and keeps the table renderer's XHTML alignment.
func TestATableSitsInABoxOfItsOwn(t *testing.T) {
	out := renderA(t, "# A\n\n| Name | Size |\n| --- | ---: |\n| `a` | 1 B |\n\nAfter.\n\n| One |\n| --- |\n| x |\n")
	if n := strings.Count(out, "<div class=\"tbl\">\n<table>"); n != 2 || strings.Count(out, "</table>\n</div>") != 2 {
		t.Errorf("%d tables boxed, want 2:\n%s", n, out)
	}
	if !strings.Contains(out, `<td align="right">1 B</td>`) {
		t.Errorf("the right-aligned cell lost its XHTML alignment:\n%s", out)
	}
}

type caught map[ast.NodeKind]renderer.NodeRendererFunc

func (c caught) Register(kind ast.NodeKind, f renderer.NodeRendererFunc) { c[kind] = f }

type refusingWriter struct{}

func (refusingWriter) Write([]byte) (int, error) { return 0, errors.New("refused") }

// A box that cannot be written stops the render instead of leaving a table
// without its box.
func TestATableBoxThatCannotBeWrittenStops(t *testing.T) {
	funcs := caught{}
	extension.NewTableHTMLRenderer().RegisterFuncs(boxedTables{funcs})
	table := funcs[east.KindTable]
	if table == nil || funcs[east.KindTableCell] == nil {
		t.Fatalf("the table functions were not passed on: %v", funcs)
	}
	for _, entering := range []bool{true, false} {
		w := bufio.NewWriterSize(refusingWriter{}, 16)
		if _, err := w.WriteString(strings.Repeat("x", 17)); err == nil {
			t.Fatal("the writer did not refuse")
		}
		if status, err := table(w, nil, east.NewTable(), entering); err == nil || status != ast.WalkStop {
			t.Errorf("entering=%v: status %v, err %v; want the render stopped", entering, status, err)
		}
	}
}

// A record the repository does not list, such as a local draft git ignores,
// is neither rendered nor in the sitemap; once listed, it is both.
func TestOnlyAListedRecordIsRendered(t *testing.T) {
	fsys := fixture("# A\n")
	fsys["docs/adr/0002-draft.md"] = &fstest.MapFile{Data: []byte("# ADR-0002: Draft\n\nStatus: proposed\n")}
	files, err := Build(fsys, listingOf(fsys, "docs/adr/0002-draft.md"), released)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files[Dir+"/adr/0002-draft.html"]; ok || strings.Contains(string(files[Sitemap]), "/docs/adr/0002-draft") {
		t.Errorf("the unlisted record was rendered: %d files, sitemap\n%s", len(files), files[Sitemap])
	}
	if files, err = buildAll(fsys); err != nil {
		t.Fatal(err)
	}
	if _, ok := files[Dir+"/adr/0002-draft.html"]; !ok || !strings.Contains(string(files[Sitemap]), "<loc>"+Origin+"/docs/adr/0002-draft</loc>") {
		t.Errorf("the listed record was not rendered: %d files, sitemap\n%s", len(files), files[Sitemap])
	}
}

func TestEveryPageIsWrittenAndListed(t *testing.T) {
	files, err := build(t, "# A\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"index.html", "concepts/a.html", "concepts/b.html", "adr/0001-first.html", "roadmap.html", "changelog.html"}
	if len(files) != len(want)+2 {
		t.Errorf("Build wrote %d files, want %d pages, the sitemap and llms.txt", len(files), len(want))
	}
	sitemap := string(files[Sitemap])
	for _, name := range want {
		if _, ok := files[Dir+"/"+name]; !ok {
			t.Errorf("no %s/%s", Dir, name)
		}
	}
	for _, loc := range []string{Origin + "/", Origin + "/docs/", Origin + "/docs/concepts/a", Origin + "/docs/roadmap"} {
		if !strings.Contains(sitemap, "<loc>"+loc+"</loc>") {
			t.Errorf("the sitemap lacks %s", loc)
		}
	}
	a := string(files[Dir+"/concepts/a.html"])
	for _, want := range []string{
		`<link rel="canonical" href="` + Origin + `/docs/concepts/a"/>`,
		`<a href="/docs/concepts/a" aria-current="page">A page</a>`,
		`<h2>Concepts</h2>`,
		`<a href="/docs/#decision-records">Decision records</a>`,
	} {
		if !strings.Contains(a, want) {
			t.Errorf("the page lacks %s", want)
		}
	}
}

// Every page wears the one header, with the released version's pill, and
// carries the section list twice: the sidebar and the menu a narrow screen
// shows above the content, both marking the current page.
func TestThePageCarriesTheHeaderAndTheMenu(t *testing.T) {
	a := renderA(t, "# A\n")
	for _, want := range []string{
		`<a class="vlink" href="https://github.com/guardana/control/releases/tag/v0.1.0"><span class="ver">v0.1.0</span></a>`,
		`<nav class="links" aria-label="Primary"><a href="/#how">How it works</a>`,
		`<a href="/docs/">Docs</a></nav>`,
		`<input type="checkbox" id="theme" aria-label="Switch between light and dark"/><label class="tgl" for="theme"`,
		`<a class="btn s sm" href="https://github.com/guardana/control">Star on GitHub</a>`,
		`<footer class="ft">`,
		`<a href="https://github.com/guardana/control/blob/main/SECURITY.md">Security</a>`,
		`<link rel="stylesheet" href="/assets/control/v2/tokens.css"/>`,
		"<details class=\"mnav\">\n<summary>Menu · <b>A page</b></summary>\n<nav class=\"inner\" aria-label=\"Documentation\">",
	} {
		if !strings.Contains(a, want) {
			t.Errorf("the page lacks %s", want)
		}
	}
	if n := strings.Count(a, `<a href="/docs/concepts/a" aria-current="page">A page</a>`); n != 2 {
		t.Errorf("the current page is marked %d times, want twice: in the sidebar and in the menu", n)
	}
	if menu, main := strings.Index(a, `<details class="mnav">`), strings.Index(a, `<main id="main"`); menu < 0 || main < 0 || menu > main {
		t.Errorf("the menu opens at byte %d and the content at %d; the menu must come first", menu, main)
	}
}

// Every rendered page names the released version, not the newest dated
// section above it, in its header and in its foot, which links the
// documentation at that version's tag.
func TestEveryPageNamesTheReleasedVersion(t *testing.T) {
	files, err := build(t, "# A\n")
	if err != nil {
		t.Fatal(err)
	}
	pill := `<a class="vlink" href="https://github.com/guardana/control/releases/tag/v0.1.0"><span class="ver">v0.1.0</span></a>`
	foot := ` on <code>main</code>. It describes the tree as it is now; a release's notes say what a tag holds. ` +
		`The latest release is v0.1.0, and <a href="https://github.com/guardana/control/tree/v0.1.0/docs">its documentation</a> is in its tag.</p>`
	pages := 0
	for name, data := range files {
		if name == Sitemap || name == LLMs {
			continue
		}
		pages++
		out := string(data)
		if n := strings.Count(out, `class="vlink"`); n != 1 || !strings.Contains(out, pill) {
			t.Errorf("%s: holds %d release pills, want one: %s", name, n, pill)
		}
		if n := strings.Count(out, `<p class="src">`); n != 1 || !strings.Contains(out, foot) {
			t.Errorf("%s: holds %d source lines, want one ending %s", name, n, foot)
		}
		if strings.Contains(out, "v0.2.0") {
			t.Errorf("%s: names v0.2.0, a section that is dated and not released", name)
		}
	}
	if pages != 6 {
		t.Errorf("checked %d pages, want the fixture's 6", pages)
	}
}

// A released version the changelog does not date stops the render: a header
// naming a release that has no notes is never written.
func TestAReleasedVersionWithNoDatedSectionIsRefused(t *testing.T) {
	for name, c := range map[string]struct{ changelog, released, want string }{
		"a version with no section": {"# Changelog\n\n## [0.1.0] - 2026-01-01\n", "0.3.0", "CHANGELOG.md holds no section for 0.3.0"},
		"an undated section":        {"# Changelog\n\n## [0.3.0]\n\n## [0.1.0] - 2026-01-01\n", "0.3.0", `CHANGELOG.md line 3: "## [0.3.0]" is not`},
		"no released section":       {"# Changelog\n\n## [Unreleased]\n", released, "CHANGELOG.md holds no section for 0.1.0"},
		"a malformed version":       {"# Changelog\n\n## [0.1.0] - 2026-01-01\n", "v0.1.0", `the released version "v0.1.0" is not a version`},
	} {
		fsys := fixture("# A\n")
		fsys["CHANGELOG.md"] = &fstest.MapFile{Data: []byte(c.changelog)}
		if _, err := Build(fsys, listingOf(fsys), c.released); !errors.Is(err, ErrSite) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

func TestARootPageNeedsItsTitle(t *testing.T) {
	fsys := fixture("# A\n")
	fsys["ROADMAP.md"] = &fstest.MapFile{Data: []byte("Planned.\n")}
	if _, err := buildAll(fsys); err == nil || !strings.Contains(err.Error(), "ROADMAP.md: the first line is not the page's title") {
		t.Errorf("err = %v, want the roadmap's missing title named", err)
	}
}

func TestTextXHTMLCannotCarryIsRefused(t *testing.T) {
	for body, want := range map[string]string{
		"# A\n\n\xa3\n":      "the page is not valid UTF-8",
		"# A\n\nbell \x07\n": "line 10: the character U+0007",
		"# A\n\n￿ here\n":    "line 10: the character U+FFFF",
	} {
		if _, err := build(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("body %q: err = %v, want %q", body, err, want)
		}
	}
}

// llms.txt names the product, quotes the README's lede, says the status, and
// lists every page under its type's heading and every record as optional,
// each with its address and summary, and the index itself nowhere.
func TestLLMsListsEveryPageUnderItsType(t *testing.T) {
	files, err := build(t, "# A\n")
	if err != nil {
		t.Fatal(err)
	}
	got := string(files[LLMs])
	want := "# " + brand.Name + "\n\n" +
		"> It decides each call before it runs.\n\n" +
		llmsStatus + " " + Origin + "/docs/status\n" +
		"\n## Concepts\n\n" +
		"- [A page](" + Origin + "/docs/concepts/a): What the page is for.\n" +
		"- [A page](" + Origin + "/docs/concepts/b): What the page is for.\n" +
		"\n## Project\n\n" +
		"- [Changelog](" + Origin + "/docs/changelog): What each release changed, and what is unreleased on main.\n" +
		"- [Roadmap](" + Origin + "/docs/roadmap): What has to become true, in the order it is planned.\n" +
		"\n## Optional\n\n" +
		"- [ADR-0001: First](" + Origin + "/docs/adr/0001-first): Decision record, accepted.\n"
	if got != want {
		t.Errorf("llms.txt =\n%s\nwant\n%s", got, want)
	}
}

// The map quotes the README's lede; a README with no tagline, or none
// followed by a paragraph, stops the render rather than leaving it out.
func TestLLMsNeedsTheReadmesLede(t *testing.T) {
	for name, c := range map[string]struct{ readme, want string }{
		"no tagline":         {"# Product\n\nIt decides each call.\n", "no line is set wholly in bold"},
		"nothing after it":   {"# Product\n\n**Watch every call.**\n\n", "no paragraph follows the tagline on line 3"},
		"no README":          {"", "README.md"},
		"a lede to the end":  {"**Watch.**\nIt decides.", ""},
		"a tagline in words": {"# Product\n\nWatch **every** call.\n\nIt decides.\n", "no line is set wholly in bold"},
	} {
		fsys := fixture("# A\n")
		if c.readme == "" {
			delete(fsys, "README.md")
		} else {
			fsys["README.md"] = &fstest.MapFile{Data: []byte(c.readme)}
		}
		_, err := buildAll(fsys)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.want != "" && (!errors.Is(err, ErrSite) || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}
