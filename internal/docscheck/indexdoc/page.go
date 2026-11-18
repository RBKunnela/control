// Package indexdoc renders docs/index.md, the map of every page, from the
// pages' own frontmatter and the records' first line and status, so the map
// cannot name a page that does not exist or miss one that does.
package indexdoc

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/guardana/control/internal/docscheck/docsconfig"
	"github.com/guardana/control/internal/docscheck/frontmatter"
)

// Script is the generator the index names in its frontmatter.
const Script = "scripts/gen-index.go"

// Index is where the page lives, relative to the repository.
const Index = "docs/index.md"

// Page is one page of the map.
type Page struct {
	Path string // relative to the repository
	Meta frontmatter.Meta
}

// Record is one decision record: its number and title, from its first line,
// and its status.
type Record struct {
	Path, Title, Status string
}

// ErrIndex is wrapped by every refusal.
var ErrIndex = errors.New("indexdoc")

// sections names the heading each page type is listed under, in the order
// frontmatter.Types declares them.
var sections = map[string]string{
	"tutorial": "Get started", "how-to": "Guides", "explanation": "Concepts", "reference": "Reference",
	"spec": "Specification", "extending": "Extending", "project": "Project",
}

// Section is the heading the index lists a page of type typ under.
func Section(typ string) string { return sections[typ] }

// Listing says which files under docs/ the map may read. Lists is whether the
// repository lists rel, a file or a directory spelled with a trailing slash,
// and Skips is also true for what docs.json excludes from the page checks.
type Listing interface {
	Lists(rel string) bool
	Skips(rel string) bool
}

// Collect reads every page under docs/ but the records and the index itself,
// and every record, from fsys, which is rooted at the repository. A file the
// repository does not list is never read. A page that does not parse is a
// refusal, never a page left out.
func Collect(fsys fs.FS, listing Listing) ([]Page, []Record, error) {
	c := &collector{fsys: fsys, listing: listing}
	if err := fs.WalkDir(fsys, "docs", c.visit); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrIndex, err)
	}
	if len(c.pages) == 0 || len(c.records) == 0 {
		return nil, nil, fmt.Errorf("%w: found %d page(s) and %d record(s), so the map would be empty", ErrIndex, len(c.pages), len(c.records))
	}
	return c.pages, c.records, nil
}

type collector struct {
	fsys    fs.FS
	listing Listing
	pages   []Page
	records []Record
}

func (c *collector) visit(rel string, d fs.DirEntry, walkErr error) error {
	if walkErr != nil {
		return walkErr
	}
	if d.IsDir() {
		return dirAction(rel, d.Name(), c.listing)
	}
	if !strings.HasSuffix(rel, ".md") || rel == Index {
		return nil
	}
	if strings.HasPrefix(rel, "docs/adr/") {
		return c.addRecord(rel)
	}
	return c.addPage(rel)
}

func (c *collector) addRecord(rel string) error {
	if !c.listing.Lists(rel) {
		return nil
	}
	record, ok, err := readRecord(c.fsys, rel)
	if ok {
		c.records = append(c.records, record)
	}
	return err
}

func (c *collector) addPage(rel string) error {
	if c.listing.Skips(rel) {
		return nil
	}
	page, err := readPage(c.fsys, rel)
	if err != nil {
		return err
	}
	c.pages = append(c.pages, page)
	return nil
}

// dirAction skips a hidden or skipped directory. The records are excluded
// from the page checks and listed here all the same.
func dirAction(rel, name string, listing Listing) error {
	if rel == "docs" || rel == "docs/adr" {
		return nil
	}
	if listing.Skips(rel+"/") || strings.HasPrefix(name, ".") {
		return fs.SkipDir
	}
	return nil
}

func readPage(fsys fs.FS, rel string) (Page, error) {
	data, err := fs.ReadFile(fsys, rel)
	if err != nil {
		return Page{}, err
	}
	meta, _, err := frontmatter.Parse(data)
	if err != nil {
		return Page{}, fmt.Errorf("%s: %w", rel, err)
	}
	return Page{Path: rel, Meta: meta}, nil
}

func readRecord(fsys fs.FS, rel string) (Record, bool, error) {
	data, err := fs.ReadFile(fsys, rel)
	if err != nil {
		return Record{}, false, err
	}
	return parseRecord(rel, data)
}

// parseRecord reads a record's number and title from its first line and its
// status from the line that names it. The template and the records' own
// README are not records.
func parseRecord(rel string, data []byte) (Record, bool, error) {
	base := path.Base(rel)
	if base == "README.md" || strings.HasPrefix(base, "0000-") {
		return Record{}, false, nil
	}
	lines := strings.Split(string(data), "\n")
	title, ok := strings.CutPrefix(lines[0], "# ")
	if !ok || title == "" {
		return Record{}, false, fmt.Errorf("%s: the first line is not the record's title", rel)
	}
	for _, line := range lines[1:] {
		if status, ok := strings.CutPrefix(line, "Status: "); ok && status != "" {
			return Record{Path: rel, Title: title, Status: status}, true, nil
		}
	}
	return Record{}, false, fmt.Errorf("%s: no line names the record's status", rel)
}

// Render renders the index: the reading paths, each page under its own title,
// then a section per page type that has a page, each page as a link with its
// summary, then every record with its status. A path naming a page that is not
// among pages is a refusal.
func Render(pages []Page, records []Record, paths []docsconfig.ReadingPath) ([]byte, error) {
	if len(pages) == 0 || len(records) == 0 {
		return nil, fmt.Errorf("%w: nothing to list", ErrIndex)
	}
	head, err := frontmatter.Render(frontmatter.Meta{
		Title:     "Documentation",
		Summary:   "Every page, grouped by the question it answers, and every decision record.",
		Type:      "project",
		Covers:    []string{"docs/**"},
		Generated: Script,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIndex, err)
	}
	var b strings.Builder
	b.Write(head)
	b.WriteString("\n# Documentation\n\nRendered from every page's own frontmatter, the records and the reading paths\nin `docs/docs.json`. Rebuild it with `make docs-gen`; an edit made here does\nnot survive the next run.\n")
	if err := renderPaths(&b, pages, paths); err != nil {
		return nil, err
	}
	sorted := slices.Clone(pages)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for _, typ := range frontmatter.Types {
		listed := false
		for _, p := range sorted {
			if p.Meta.Type != typ {
				continue
			}
			if !listed {
				fmt.Fprintf(&b, "\n## %s\n\n", sections[typ])
				listed = true
			}
			link := strings.TrimPrefix(p.Path, "docs/")
			fmt.Fprintf(&b, "- [%s](%s): %s\n", p.Meta.Title, link, p.Meta.Summary)
		}
	}
	b.WriteString("\n## Decision records\n\n")
	sortedRecords := slices.Clone(records)
	sort.Slice(sortedRecords, func(i, j int) bool { return sortedRecords[i].Path < sortedRecords[j].Path })
	for _, r := range sortedRecords {
		fmt.Fprintf(&b, "- [%s](%s): %s\n", r.Title, strings.TrimPrefix(r.Path, "docs/"), r.Status)
	}
	return []byte(b.String()), nil
}

// renderPaths writes one section holding every reading path, each a numbered
// list of its pages by title.
func renderPaths(b *strings.Builder, pages []Page, paths []docsconfig.ReadingPath) error {
	if len(paths) == 0 {
		return nil
	}
	titles := make(map[string]string, len(pages))
	for _, p := range pages {
		titles[p.Path] = p.Meta.Title
	}
	b.WriteString("\n## Reading paths\n")
	for _, path := range paths {
		fmt.Fprintf(b, "\n### %s\n\n%s\n\n", path.Reader, path.Lead)
		for i, rel := range path.Pages {
			title, ok := titles[rel]
			if !ok {
				return fmt.Errorf("%w: the reading path for %q names %s, which is not a page the index lists", ErrIndex, path.Reader, rel)
			}
			fmt.Fprintf(b, "%d. [%s](%s)\n", i+1, title, strings.TrimPrefix(rel, "docs/"))
		}
	}
	return nil
}
