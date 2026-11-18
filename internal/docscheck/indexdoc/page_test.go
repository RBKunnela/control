package indexdoc_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/guardana/control/internal/docscheck/docsconfig"
	"github.com/guardana/control/internal/docscheck/impact"
	"github.com/guardana/control/internal/docscheck/indexdoc"
)

func page(title, typ string) []byte {
	return []byte("---\ntitle: " + title + "\nsummary: About " + title + ".\ntype: " + typ + "\ncovers: [pkg/**]\n---\n\n# " + title + "\n")
}

func record(title, status string) []byte {
	return []byte("# " + title + "\n\nStatus: " + status + "\nDate: 2026-01-01\n")
}

func tree() fstest.MapFS {
	return fstest.MapFS{
		"docs/index.md":             {Data: page("Documentation", "project")},
		"docs/status.md":            {Data: page("Status", "project")},
		"docs/guides/run.md":        {Data: page("Run it", "how-to")},
		"docs/guides/a-first.md":    {Data: page("A first", "how-to")},
		"docs/concepts/x.md":        {Data: page("X", "explanation")},
		"docs/adr/0001-first.md":    {Data: record("ADR-0001: First", "accepted")},
		"docs/adr/0002-second.md":   {Data: record("ADR-0002: Second", "proposed")},
		"docs/adr/0000-template.md": {Data: record("ADR-NNNN: Title", "proposed")},
		"docs/adr/README.md":        {Data: []byte("# Records\n")},
		"docs/adr/0003-local.md":    {Data: record("ADR-0003: Local", "proposed")},
		"docs/guides/local.md":      {Data: page("Local", "how-to")},
		"docs/notes/secret.md":      {Data: page("Secret", "project")},
		"docs/.hidden/h.md":         {Data: page("Hidden", "project")},
		"docs/notes.txt":            {Data: []byte("not a page")},
		"internal/x/README.md":      {Data: []byte("# not under docs\n")},
	}
}

func excluded(rel string) bool {
	return strings.HasPrefix(rel, "docs/notes/") || strings.HasPrefix(rel, "docs/adr/")
}

// unlisted lie on disk but not in the repository's list, as a file git
// ignores does.
var unlisted = []string{"docs/adr/0003-local.md", "docs/guides/local.md"}

// listing lists every file of m but the unlisted ones and those of also.
func listing(m fstest.MapFS, also ...string) impact.Listing {
	var paths []string
	for rel := range m {
		if !slices.Contains(unlisted, rel) || slices.Contains(also, rel) {
			paths = append(paths, rel)
		}
	}
	return impact.LeftOut(paths, excluded)
}

func TestCollectListsPagesAndRecordsAndNothingElse(t *testing.T) {
	pages, records, err := indexdoc.Collect(tree(), listing(tree()))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, p := range pages {
		paths = append(paths, p.Path)
	}
	if want := "docs/concepts/x.md docs/guides/a-first.md docs/guides/run.md docs/status.md"; strings.Join(sorted(paths), " ") != want {
		t.Errorf("pages = %q, want %q", paths, want)
	}
	if len(records) != 2 || records[0].Title != "ADR-0001: First" || records[0].Status != "accepted" || records[1].Path != "docs/adr/0002-second.md" {
		t.Errorf("records = %+v", records)
	}
}

func TestCollectReadsARecordOnlyOnceTheRepositoryListsIt(t *testing.T) {
	_, records, err := indexdoc.Collect(tree(), listing(tree(), "docs/adr/0003-local.md"))
	if err != nil || len(records) != 3 || records[2].Path != "docs/adr/0003-local.md" || records[2].Title != "ADR-0003: Local" {
		t.Errorf("records once the new record is listed = %+v, %v", records, err)
	}
	broken := tree()
	broken["docs/adr/0003-local.md"] = &fstest.MapFile{Data: []byte("no title\n")}
	if _, records, err := indexdoc.Collect(broken, listing(broken)); err != nil || len(records) != 2 {
		t.Errorf("an unlisted record that does not parse was read: %+v, %v", records, err)
	}
}

func TestCollectRefusals(t *testing.T) {
	for name, edit := range map[string]func(fstest.MapFS){
		"a page that does not parse": func(m fstest.MapFS) { m["docs/guides/run.md"] = &fstest.MapFile{Data: []byte("# no frontmatter\n")} },
		"a record with no status": func(m fstest.MapFS) {
			m["docs/adr/0001-first.md"] = &fstest.MapFile{Data: []byte("# ADR-0001: First\n\nDate: x\n")}
		},
		"a record with no title": func(m fstest.MapFS) {
			m["docs/adr/0001-first.md"] = &fstest.MapFile{Data: []byte("Status: accepted\n")}
		},
		"no records": func(m fstest.MapFS) {
			delete(m, "docs/adr/0001-first.md")
			delete(m, "docs/adr/0002-second.md")
		},
		"no pages": func(m fstest.MapFS) {
			for _, k := range []string{"docs/status.md", "docs/guides/run.md", "docs/guides/a-first.md", "docs/concepts/x.md"} {
				delete(m, k)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := tree()
			edit(m)
			if pages, records, err := indexdoc.Collect(m, listing(m)); !errors.Is(err, indexdoc.ErrIndex) {
				t.Errorf("Collect = %v, %v, %v", pages, records, err)
			}
		})
	}
}

func TestRenderGroupsByTypeInOrderAndSortsWithin(t *testing.T) {
	pages, records, err := indexdoc.Collect(tree(), listing(tree()))
	if err != nil {
		t.Fatal(err)
	}
	out, err := indexdoc.Render(pages, records, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	want := "## Guides\n\n- [A first](guides/a-first.md): About A first.\n- [Run it](guides/run.md): About Run it.\n\n## Concepts\n\n- [X](concepts/x.md): About X.\n\n## Project\n\n- [Status](status.md): About Status.\n\n## Decision records\n\n- [ADR-0001: First](adr/0001-first.md): accepted\n- [ADR-0002: Second](adr/0002-second.md): proposed\n"
	if !strings.HasSuffix(text, want) {
		t.Errorf("Render =\n%s\nwant the tail\n%s", text, want)
	}
	if !strings.HasPrefix(text, "---\ntitle: Documentation\n") || !strings.Contains(text, "\ngenerated: "+indexdoc.Script+"\n---\n") {
		t.Errorf("the head does not name the generator:\n%s", text)
	}
	if strings.Contains(text, "## Get started") || strings.Contains(text, "Reference") || strings.Contains(text, "## Reading paths") {
		t.Errorf("a section with no page is listed:\n%s", text)
	}
	if _, err := indexdoc.Render(nil, records, nil); !errors.Is(err, indexdoc.ErrIndex) {
		t.Errorf("Render with no page: %v", err)
	}
}

func TestRenderPutsTheReadingPathsAboveTheCatalogue(t *testing.T) {
	pages, records, err := indexdoc.Collect(tree(), listing(tree()))
	if err != nil {
		t.Fatal(err)
	}
	paths := []docsconfig.ReadingPath{
		{Reader: "Operator", Lead: "Run a plane.", Pages: []string{"docs/guides/run.md", "docs/status.md"}},
		{Reader: "Reader", Lead: "Understand it.", Pages: []string{"docs/concepts/x.md"}},
	}
	out, err := indexdoc.Render(pages, records, paths)
	if err != nil {
		t.Fatal(err)
	}
	want := "\n## Reading paths\n\n### Operator\n\nRun a plane.\n\n1. [Run it](guides/run.md)\n2. [Status](status.md)\n\n### Reader\n\nUnderstand it.\n\n1. [X](concepts/x.md)\n\n## Guides\n"
	if !strings.Contains(string(out), want) {
		t.Errorf("Render =\n%s\nwant the paths, in order, right above the catalogue:\n%s", out, want)
	}
}

// A reading path is refused for a page the index does not list: one that is
// not there, one the documentation checks exclude and one the repository
// does not list.
func TestRenderRefusesAPathNamingNoPage(t *testing.T) {
	pages, records, err := indexdoc.Collect(tree(), listing(tree()))
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{"docs/guides/gone.md", "docs/notes/secret.md", "docs/guides/local.md", "docs/adr/0001-first.md"} {
		t.Run(missing, func(t *testing.T) {
			paths := []docsconfig.ReadingPath{{Reader: "Operator", Lead: "Run a plane.", Pages: []string{"docs/guides/run.md", missing}}}
			out, err := indexdoc.Render(pages, records, paths)
			if !errors.Is(err, indexdoc.ErrIndex) || !strings.Contains(err.Error(), missing) || out != nil {
				t.Errorf("Render with a path naming %s = %q, %v; want a refusal naming it", missing, out, err)
			}
		})
	}
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
