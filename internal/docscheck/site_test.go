// The landing page and its deploy files, read the way the host serves them.
package docscheck

import (
	"bytes"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/docscheck/docsconfig"
	"github.com/guardana/control/internal/docscheck/impact"
	"github.com/guardana/control/internal/docscheck/sitedoc"
	"github.com/guardana/control/internal/docscheck/sitedoc/docsite"
)

const (
	siteDir      = "site"
	themeDir     = "site/assets/control/v2"
	themeCSS     = "/assets/control/v2/tokens.css"
	ogCard       = "scripts/og-card.html"
	siteOrigin   = "https://control.guardana.dev/"
	themeDigest  = "ef3d42d8ef82c2770730f95240cd4aca61923269f467d935574bb01eb6ded4b0"
	themeFiles   = 4
	minSiteLinks = 20
	// minDocsPages is a floor under the rendered set: a render that found
	// no page would otherwise compare nothing with nothing.
	minDocsPages = 60
	// minProseSentences is a floor under the sentences read from the page
	// and from the README, so an extraction that found none fails.
	minProseSentences = 20
)

// siteManifest is every file under site/ that no generator writes; the
// documentation pages, the sitemap and llms.txt are what docsite.Build writes.
var siteManifest = []string{
	".assetsignore",
	"_headers",
	"assets/control/control.css",
	"assets/control/docs.css",
	"assets/control/home.css",
	"assets/control/icon.svg",
	"assets/control/mark-dark.svg",
	"assets/control/mark.svg",
	"assets/control/v2/SHA256SUMS",
	"assets/control/v2/fonts/OFL.txt",
	"assets/control/v2/fonts/geist-mono-variable.woff2",
	"assets/control/v2/fonts/geist-variable.woff2",
	"assets/control/v2/tokens.css",
	"favicon.svg",
	"index.html",
	"og.png",
	"robots.txt",
	"sitemap.xml",
}

func loadSite(t *testing.T) map[string][]byte {
	t.Helper()
	sub, err := fs.Sub(repoFS(t), siteDir)
	if err != nil {
		t.Fatal(err)
	}
	files, err := siteFiles(sub)
	if err != nil {
		t.Fatalf("reading %s: %v", siteDir, err)
	}
	return files
}

func loadPage(t *testing.T, data []byte) *xnode {
	t.Helper()
	doc, err := parseXHTML(data)
	if err != nil {
		t.Fatalf("the page does not parse as XML: %v", err)
	}
	return doc
}

func report(t *testing.T, what string, problems []string) {
	t.Helper()
	for _, p := range problems {
		t.Errorf("%s: %s", what, p)
	}
}

// docsFiles renders the documentation as `make docs-gen` does, keyed by the
// path under site/.
func docsFiles(t *testing.T) map[string][]byte {
	t.Helper()
	fsys := repoFS(t)
	data, err := fs.ReadFile(fsys, "docs/docs.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := docsconfig.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	built, err := docsite.Build(fsys, impact.LeftOut(repoFiles(t, repoRoot(t)), cfg.Excludes), cfg.Released)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(built))
	for name, data := range built {
		files[strings.TrimPrefix(name, siteDir+"/")] = data
	}
	if len(files) < minDocsPages {
		t.Fatalf("the renderer wrote %d files, fewer than the %d pages that exist", len(files), minDocsPages)
	}
	return files
}

func TestSiteHoldsThePinnedManifest(t *testing.T) {
	want := slices.Clone(siteManifest)
	for name := range docsFiles(t) {
		if !slices.Contains(want, name) {
			want = append(want, name)
		}
	}
	report(t, siteDir, manifestProblems(loadSite(t), want))
}

// Every documentation page and the sitemap are what the renderer writes from
// the Markdown now, and site/docs/ holds nothing it does not write.
func TestDocsPagesAreRendered(t *testing.T) {
	want := docsFiles(t)
	site := loadSite(t)
	for _, name := range sortedKeys(want) {
		got, ok := site[name]
		switch {
		case !ok:
			t.Errorf("%s/%s is missing; run `make docs-gen`", siteDir, name)
		case !bytes.Equal(got, want[name]):
			t.Errorf("%s/%s lags its source; run `make docs-gen`\n%s", siteDir, name, firstDifferingLine(want[name], got))
		}
	}
	for _, name := range sortedKeys(site) {
		if _, ok := want[name]; !ok && strings.HasPrefix(name, "docs/") {
			t.Errorf("%s/%s is rendered from no page; run `make docs-gen`", siteDir, name)
		}
	}
}

func TestTokenFilesMatchThePinnedSums(t *testing.T) {
	sub, err := fs.Sub(repoFS(t), themeDir)
	if err != nil {
		t.Fatal(err)
	}
	report(t, themeDir, brandProblems(sub, themeDigest, themeFiles))
}

// The home page draws its own illustrations, each with its text alternative,
// and draws no README block: the README's Mermaid is for GitHub. A re-render
// leaves the page as committed.
func TestTheHomePageDrawsNoReadmeBlock(t *testing.T) {
	fsys := repoFS(t)
	page, err := fs.ReadFile(fsys, sitedoc.Page)
	if err != nil {
		t.Fatal(err)
	}
	readme, err := fs.ReadFile(fsys, readmeName)
	if err != nil {
		t.Fatal(err)
	}
	slots, err := sitedoc.Slots(page)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 0 {
		t.Errorf("slots = %v, want none", slots)
	}
	rendered, err := sitedoc.Render(page, readme)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered, page) {
		t.Errorf("%s changes when rendered; run `make docs-gen`", sitedoc.Page)
	}
	doc := loadPage(t, page)
	problems, drawn := illustrationProblems(doc)
	report(t, sitedoc.Page, problems)
	if drawn < 3 {
		t.Errorf("%s holds %d illustrations, want at least three", sitedoc.Page, drawn)
	}
	report(t, sitedoc.Page, idProblems(doc))
}

func TestSiteLoadsNothingFromAnotherHost(t *testing.T) {
	report(t, siteDir, hostProblems(loadSite(t)))
	data, err := fs.ReadFile(repoFS(t), siteDir+"/_headers")
	if err != nil {
		t.Fatal(err)
	}
	report(t, siteDir+"/_headers", headerProblems(data))
}

// Every page holds each id once, so a fragment or a drawing's reference lands
// on the one element it names.
func TestSitePagesHoldEachIDOnce(t *testing.T) {
	pages := 0
	for name, data := range loadSite(t) {
		if path.Ext(name) == ".html" {
			pages++
			report(t, name, idProblems(loadPage(t, data)))
		}
	}
	if pages < minDocsPages {
		t.Errorf("read %d pages, want at least %d", pages, minDocsPages)
	}
}

func TestSiteLinksResolve(t *testing.T) {
	problems, resolved := linkProblems(loadSite(t), repoFS(t))
	report(t, siteDir, problems)
	if resolved < minSiteLinks {
		t.Errorf("%d links resolved, want at least %d", resolved, minSiteLinks)
	}
}

func TestSiteItemsNameTheirSources(t *testing.T) {
	fsys := repoFS(t)
	status, problems := statusRows(readLines(t, fsys, "docs/status.md"))
	backlog := backlogTitles(readLines(t, fsys, "docs/backlog.md"))
	if len(problems) > 0 || len(backlog) < 5 {
		t.Fatalf("docs/status.md has %d problems (TestStatusComponents names them) and docs/backlog.md %d ids; the sources were not parsed", len(problems), len(backlog))
	}
	doc := loadPage(t, loadSite(t)["index.html"])
	report(t, sitedoc.Page, tagProblems(doc, status, backlog, 12, minLandingTasks))
	report(t, sitedoc.Page, itemListProblems(pageItems(doc), landingItems))
}

// A sentence that calls something planned or promises later work names its
// task, on the page and in README, so neither can promise work the backlog
// does not hold.
func TestSitePlannedSentencesNameTheirTask(t *testing.T) {
	fsys := repoFS(t)
	page, err := fs.ReadFile(fsys, sitedoc.Page)
	if err != nil {
		t.Fatal(err)
	}
	readme, err := fs.ReadFile(fsys, readmeName)
	if err != nil {
		t.Fatal(err)
	}
	segments, err := readmeSegments(readme)
	if err != nil {
		t.Fatalf("%s: %v", readmeName, err)
	}
	tasks := backlogTitles(readLines(t, fsys, "docs/backlog.md"))
	for _, c := range []struct {
		name     string
		segments []proseSegment
		tasks    map[string]string
	}{{sitedoc.Page, pageSegments(loadPage(t, page)), nil}, {readmeName, segments, tasks}} {
		problems, read := plannedOutsideBacklog(c.name, c.segments, c.tasks)
		for _, p := range problems {
			t.Error(p)
		}
		if read == 0 {
			t.Errorf("%s: no sentence calling something planned was read", c.name)
		}
	}
}

// llms.txt quotes README's lede as its description and says what the
// project is not ready for.
func TestLLMsSaysWhatTheProjectIs(t *testing.T) {
	fsys := repoFS(t)
	lede, err := readmeLede(readLines(t, fsys, readmeName))
	if err != nil {
		t.Fatal(err)
	}
	report(t, docsite.LLMs, llmsProblems(string(loadSite(t)["llms.txt"]), lede))
}

// No stylesheet but the tokens sets a token, and none writes words through
// content; the pages' style attributes and elements are held the same way.
func TestStylesheetsSetNoTokenAndWriteNoWords(t *testing.T) {
	site := loadSite(t)
	tokens := tokenNames(string(site["assets/control/v2/tokens.css"]))
	if len(tokens) < 10 {
		t.Fatalf("read %d tokens from tokens.css; it was not parsed", len(tokens))
	}
	sheets, pages := 0, 0
	for _, name := range sortedKeys(site) {
		switch {
		case name == "assets/control/v2/tokens.css":
		case path.Ext(name) == ".css":
			sheets++
			report(t, name, styleProblems(string(site[name]), tokens))
		case path.Ext(name) == ".html":
			pages++
			loadPage(t, site[name]).walk(func(n *xnode) {
				if style, ok := n.attrs["style"]; ok {
					report(t, name, styleProblems("{"+style+"}", tokens))
				}
				if n.name == "style" {
					report(t, name, styleProblems(n.text(), tokens))
				}
			})
		}
	}
	if sheets < 3 || pages < minDocsPages {
		t.Errorf("read %d stylesheets and %d pages, want at least 3 and %d", sheets, pages, minDocsPages)
	}
}

// No page runs script: no script element in any namespace and no event
// handler attribute, read from the parsed page rather than its text.
func TestSitePagesRunNoScript(t *testing.T) {
	site := loadSite(t)
	pages := 0
	for _, name := range sortedKeys(site) {
		if path.Ext(name) != ".html" {
			continue
		}
		pages++
		report(t, name, scriptProblems(loadPage(t, site[name])))
	}
	if pages < minDocsPages {
		t.Errorf("read %d pages, want at least %d", pages, minDocsPages)
	}
}

// Every page switches its theme without script: one checkbox the tokens'
// :has() rules read, a label for it, and the tokens stylesheet loaded; the
// tokens give the switched theme exactly the other scheme's palette.
func TestThemeSwitchNeedsNoScript(t *testing.T) {
	site := loadSite(t)
	report(t, themeDir+"/tokens.css", themeTokenProblems(site["assets/control/v2/tokens.css"]))
	pages := 0
	for _, name := range sortedKeys(site) {
		if path.Ext(name) != ".html" {
			continue
		}
		pages++
		report(t, name, themeSwitchProblems(loadPage(t, site[name]), themeCSS))
	}
	if pages < minDocsPages {
		t.Errorf("read %d pages, want at least %d", pages, minDocsPages)
	}
}

// A free sentence that promises later work lags the moment the work ships;
// only a backlog item, which the test above holds to docs/backlog.md, may.
func TestSiteAndReadmePromiseNoUnlistedWork(t *testing.T) {
	fsys := repoFS(t)
	page, err := fs.ReadFile(fsys, sitedoc.Page)
	if err != nil {
		t.Fatal(err)
	}
	readme, err := fs.ReadFile(fsys, readmeName)
	if err != nil {
		t.Fatal(err)
	}
	segments, err := readmeSegments(readme)
	if err != nil {
		t.Fatalf("%s: %v", readmeName, err)
	}
	for name, segments := range map[string][]proseSegment{sitedoc.Page: pageSegments(loadPage(t, page)), readmeName: segments} {
		problems, read := promiseProblems(name, segments)
		for _, p := range problems {
			t.Error(p)
		}
		if read < minProseSentences {
			t.Errorf("%s: read %d sentences, want at least %d; the prose was not parsed", name, read, minProseSentences)
		}
	}
}

func TestSitePlannedNamesNoDeliveredRow(t *testing.T) {
	fsys := repoFS(t)
	status, problems := statusRows(readLines(t, fsys, "docs/status.md"))
	if len(problems) > 0 {
		t.Fatalf("docs/status.md has %d problems, which TestStatusComponents names; the source was not parsed", len(problems))
	}
	page, err := fs.ReadFile(fsys, sitedoc.Page)
	if err != nil {
		t.Fatal(err)
	}
	problems, read := plannedProblems(sitedoc.Page, pageSegments(loadPage(t, page)), status)
	for _, p := range problems {
		t.Error(p)
	}
	if read == 0 {
		t.Errorf("%s: no `planned` label was read", sitedoc.Page)
	}
}

func TestTaglinesAreTheReadmes(t *testing.T) {
	fsys := repoFS(t)
	want, err := readmeTagline(readLines(t, fsys, readmeName))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{ogCard, sitedoc.Page} {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			t.Fatal(err)
		}
		if problem := taglineProblem(loadPage(t, data), want); problem != "" {
			t.Errorf("%s: %s", name, problem)
		}
	}
	lede, err := readmeLede(readLines(t, fsys, readmeName))
	if err != nil {
		t.Fatal(err)
	}
	if problem := oneTextProblem(loadPage(t, loadSite(t)["index.html"]), "lede", lede); problem != "" {
		t.Errorf("%s: %s", sitedoc.Page, problem)
	}
}

// The README, the landing page and llms.txt never call the project ready
// for production.
func TestNothingClaimsProductionReadiness(t *testing.T) {
	fsys := repoFS(t)
	for _, name := range []string{readmeName, sitedoc.Page, docsite.LLMs} {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			t.Fatal(err)
		}
		report(t, name, readinessProblems(string(data)))
	}
}

func TestWranglerConfigIsExact(t *testing.T) {
	data, err := fs.ReadFile(repoFS(t), "wrangler.json")
	if err != nil {
		t.Fatal(err)
	}
	report(t, "wrangler.json", wranglerProblems(data))
}

var sitemapLoc = regexp.MustCompile(`<loc>([^<]*)</loc>`)

// Each page names the address it is served at, under the site's one origin,
// as canonical; the sitemap lists exactly those; robots.txt points at the
// sitemap.
func TestSiteNamesItsOneAddress(t *testing.T) {
	files := loadSite(t)
	var want []string
	for _, name := range sortedKeys(files) {
		if path.Ext(name) != ".html" {
			continue
		}
		address := siteOrigin + strings.TrimSuffix(strings.TrimSuffix(name, ".html"), "index")
		var canonical []string
		loadPage(t, files[name]).walk(func(n *xnode) {
			if n.name == "link" && n.attrs["rel"] == "canonical" {
				canonical = append(canonical, n.attrs["href"])
			}
		})
		if !slices.Equal(canonical, []string{address}) {
			t.Errorf("%s: canonical links = %q, want [%s]", name, canonical, address)
		}
		want = append(want, address)
	}
	slices.Sort(want)
	var locs []string
	for _, m := range sitemapLoc.FindAllStringSubmatch(string(files["sitemap.xml"]), -1) {
		locs = append(locs, m[1])
	}
	if len(want) < minDocsPages || !slices.Equal(locs, want) {
		t.Errorf("sitemap locations = %q, want the %d page addresses %q", locs, len(want), want)
	}
	if !strings.Contains(string(files["robots.txt"]), "\nSitemap: "+siteOrigin+"sitemap.xml\n") {
		t.Errorf("robots.txt does not name %ssitemap.xml", siteOrigin)
	}
}

// docs-gen writes the page through the registered generator, so a page
// edited by hand around its slots still gets redrawn on the next run.
func TestSiteIsRenderedByDocsGen(t *testing.T) {
	runs, problems := docsGenRuns(readLines(t, repoFS(t), "Makefile"))
	report(t, "Makefile", problems)
	run := genRun{sitedoc.Script, sitedoc.Page}
	if !slices.Contains(runs, run) || !slices.Contains(renderedFiles, run) {
		t.Errorf("docs-gen does not run %s -o %s, or the run is not registered", run.script, run.page)
	}
}
