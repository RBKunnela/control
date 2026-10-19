package docscheck

import (
	"encoding/json"
	"fmt"
	"html"
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/guardana/control/internal/docscheck/sitedoc/docsite"
)

// A runtime's name may appear in its profile's directory, on its page and the
// page's generated copy, and, in a Markdown file or a file the site generator
// writes, inside a link to that page: in its target, relative or on the
// site's own origin, and in its text when that text is the page's title, or
// in an index row the title and the page's own summary. The name a profile is
// checked for is its id up to the first hyphen, so this file spells none.
const profilesDir = "internal/hookbridge/profiles/"

var (
	mdLink    = regexp.MustCompile(`\[([^\]]*)\]\(([^)\s]+)\)`)
	mdIndex   = regexp.MustCompile(`^- \[([^\]]*)\]\(([^)\s]+)\): (.*)$`)
	htmlLink  = regexp.MustCompile(`<a href="([^"]*)">([^<]*)</a>`)
	htmlIndex = regexp.MustCompile(`^<li><a href="([^"]*)">([^<]*)</a>: (.*)</li>$`)
	siteLoc   = regexp.MustCompile(`<loc>([^<]*)</loc>`)
)

// runtimeName is one built-in profile as the rule reads it.
type runtimeName struct {
	term, dir, page, site, url, title, summary string
}

// runtimeNames reads every built-in profile among files: the term is its id
// up to the first hyphen, the page is its claims.page.
func runtimeNames(fsys fs.FS, files []string) ([]runtimeName, error) {
	var out []runtimeName
	for _, rel := range files {
		dir, ok := strings.CutSuffix(rel, "/profile.json")
		if !ok || !strings.HasPrefix(dir, profilesDir) || strings.Contains(strings.TrimPrefix(dir, profilesDir), "/") {
			continue
		}
		raw, err := fs.ReadFile(fsys, rel)
		if err != nil {
			return nil, err
		}
		var p struct {
			ID     string `json:"id"`
			Claims struct {
				Page string `json:"page"`
			} `json:"claims"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		term, _, _ := strings.Cut(p.ID, "-")
		stem, isPage := strings.CutSuffix(strings.TrimPrefix(p.Claims.Page, "docs/"), ".md")
		if len(term) < 4 || !isPage || !strings.HasPrefix(p.Claims.Page, "docs/") {
			return nil, fmt.Errorf("%s: no name of four letters or more, or no page under docs/", rel)
		}
		title, summary, err := pageTitleAndSummary(fsys, p.Claims.Page)
		if err != nil {
			return nil, err
		}
		out = append(out, runtimeName{
			term: strings.ToLower(term), dir: dir + "/", page: p.Claims.Page,
			site: "site/docs/" + stem + ".html", url: "/docs/" + stem, title: title, summary: summary,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no profile under %s", profilesDir)
	}
	return out, nil
}

func pageTitleAndSummary(fsys fs.FS, page string) (string, string, error) {
	raw, err := fs.ReadFile(fsys, page)
	if err != nil {
		return "", "", fmt.Errorf("the profile's page: %w", err)
	}
	var title, summary string
	for _, line := range strings.Split(string(raw), "\n") {
		if s, ok := strings.CutPrefix(line, "title: "); ok && title == "" {
			title = s
		}
		if s, ok := strings.CutPrefix(line, "summary: "); ok && summary == "" {
			summary = s
		}
	}
	if title == "" || summary == "" {
		return "", "", fmt.Errorf("%s: no title or no summary", page)
	}
	return title, summary, nil
}

// mdTo reports whether a Markdown link in file with target points at the
// page: a path relative to file, or a URL on the site's own origin.
func (n runtimeName) mdTo(file, target string) bool {
	target, _, _ = strings.Cut(target, "#")
	if uriScheme.MatchString(target) || strings.HasPrefix(target, "/") {
		return n.urlTo(target)
	}
	return path.Join(path.Dir(file), target) == n.page
}

// urlTo reports whether a site path, or a URL on the site's own origin,
// points at the page's copy. Another origin never does.
func (n runtimeName) urlTo(target string) bool {
	target, _, _ = strings.Cut(target, "#")
	target, _, _ = strings.Cut(target, "?")
	if uriScheme.MatchString(target) || strings.HasPrefix(target, "//") {
		rest, ok := strings.CutPrefix(target, docsite.Origin)
		if !ok {
			return false
		}
		target = rest
	}
	return strings.TrimSuffix(target, ".html") == n.url
}

// generated reports whether the site generator writes file.
func generated(file string) bool {
	return file == docsite.Sitemap || strings.HasPrefix(file, docsite.Dir+"/") && strings.HasSuffix(file, ".html")
}

// unlinked returns line without what the rule lets name the runtime: the
// target of each link to the page, its text when that is the page's title,
// and the whole of an index row of the title and summary. Only a Markdown
// file or a generated one has links the rule reads.
func (n runtimeName) unlinked(file, line string) string {
	switch {
	case strings.HasSuffix(file, ".md"):
		return n.unlinkedMarkdown(file, line)
	case generated(file):
		return n.unlinkedSite(line)
	}
	return line
}

func (n runtimeName) unlinkedMarkdown(file, line string) string {
	if m := mdIndex.FindStringSubmatch(line); m != nil && m[1] == n.title && n.mdTo(file, m[2]) && m[3] == n.summary {
		return ""
	}
	return mdLink.ReplaceAllStringFunc(line, func(s string) string {
		m := mdLink.FindStringSubmatch(s)
		switch {
		case !n.mdTo(file, m[2]):
			return s
		case m[1] == n.title:
			return ""
		}
		return "[" + m[1] + "]"
	})
}

func (n runtimeName) unlinkedSite(line string) string {
	if m := htmlIndex.FindStringSubmatch(line); m != nil && n.urlTo(html.UnescapeString(m[1])) &&
		html.UnescapeString(m[2]) == n.title && html.UnescapeString(m[3]) == n.summary {
		return ""
	}
	line = htmlLink.ReplaceAllStringFunc(line, func(s string) string {
		m := htmlLink.FindStringSubmatch(s)
		switch {
		case !n.urlTo(html.UnescapeString(m[1])):
			return s
		case html.UnescapeString(m[2]) == n.title:
			return ""
		}
		return m[2]
	})
	return siteLoc.ReplaceAllStringFunc(line, func(s string) string {
		if n.urlTo(html.UnescapeString(siteLoc.FindStringSubmatch(s)[1])) {
			return ""
		}
		return s
	})
}

// runtimeNameProblems names every file and line among files that names a
// built-in profile's runtime where the rule does not let it.
func runtimeNameProblems(fsys fs.FS, files []string) ([]string, error) {
	names, err := runtimeNames(fsys, files)
	if err != nil {
		return nil, err
	}
	var problems []string
	for _, rel := range files {
		for _, n := range names {
			if strings.HasPrefix(rel, n.dir) || rel == n.page || rel == n.site {
				continue
			}
			if strings.Contains(strings.ToLower(rel), n.term) {
				problems = append(problems, rel+": the path names a runtime")
				continue
			}
			raw, err := fs.ReadFile(fsys, rel)
			if err != nil {
				return nil, err
			}
			if !strings.Contains(strings.ToLower(string(raw)), n.term) {
				continue
			}
			for i, line := range strings.Split(string(raw), "\n") {
				if strings.Contains(strings.ToLower(n.unlinked(rel, line)), n.term) {
					problems = append(problems, fmt.Sprintf("%s:%d: names a runtime outside its profile, its page and a link to the page", rel, i+1))
				}
			}
		}
	}
	return problems, nil
}

func TestARuntimeIsNamedOnlyByItsProfileAndPage(t *testing.T) {
	fsys, files := repoFS(t), repoFiles(t, repoRoot(t))
	names, err := runtimeNames(fsys, files)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if page, err := fs.ReadFile(fsys, n.page); err != nil || !strings.Contains(strings.ToLower(string(page)), n.term) {
			t.Fatalf("%s does not name the runtime the rule looks for: %v", n.page, err)
		}
	}
	problems, err := runtimeNameProblems(fsys, files)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}
