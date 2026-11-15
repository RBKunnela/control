package docscheck

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/guardana/control/internal/brand"
)

func mustParse(t *testing.T, page string) *xnode {
	t.Helper()
	doc, err := parseXHTML([]byte(page))
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	return doc
}

func TestSiteLinkProblems(t *testing.T) {
	repo := fstest.MapFS{"docs/a.md": {Data: []byte("# A\n")}, "docs/sub/b.md": {Data: []byte("b")}, "cmd/x.go": {Data: []byte("package x\n")}}
	blob := "https://" + brand.ModulePath + "/blob/main/"
	tree := "https://" + brand.ModulePath + "/tree/main/"
	site := map[string][]byte{
		"index.html": []byte(`<html><body id="top"><a href="/">home</a><a href="#top">up</a><a href="/sub/#s">s</a>` +
			`<a href="` + blob + `docs/a.md">a</a><a href="` + blob + `docs/a.md#a">a</a><a href="` + tree + `docs/sub">sub</a><a href="https://example.org/">x</a>` +
			`<a href="/page">page</a><a href="/sub">sub</a>` +
			`<svg><path marker-end="url(#top)"/></svg><link rel="stylesheet" href="assets/a.css"/></body></html>`),
		"sub/index.html":       []byte(`<html><body><p id="s">s</p><a href="../index.html#top">back</a></body></html>`),
		"page.html":            []byte(`<html><body><a href="/">home</a></body></html>`),
		"assets/a.css":         []byte(`@font-face{src:url("fonts/f.woff2")}`),
		"assets/fonts/f.woff2": nil,
	}
	problems, resolved := linkProblems(site, repo)
	wantNone(t, "a site whose links resolve", problems)
	if resolved != 13 {
		t.Errorf("resolved %d links, want 13 (the host link is not one)", resolved)
	}
	for name, c := range map[string]struct{ link, want string }{
		"a missing file":            {`<a href="/nothing.html">x</a>`, "the site does not hold"},
		"a missing relative file":   {`<a href="sub/none.html">x</a>`, "the site does not hold"},
		"a missing fragment":        {`<a href="#nowhere">x</a>`, `holds no id "nowhere"`},
		"a missing fragment across": {`<a href="/sub/#top">x</a>`, `sub/index.html holds no id "top"`},
		"a missing marker target":   {`<svg><path marker-end="url(#gone)"/></svg>`, `holds no id "gone"`},
		"a blob of a missing file":  {`<a href="` + blob + `docs/none.md">x</a>`, "not in the repository"},
		"a blob of a directory":     {`<a href="` + blob + `docs/sub">x</a>`, "a blob link to a directory"},
		"a tree of a file":          {`<a href="` + tree + `docs/a.md">x</a>`, "a tree link to a file"},
		"an empty link":             {`<a href="">x</a>`, "an empty link"},
		"a path with no page":       {`<a href="/nothing">x</a>`, "/nothing resolves to nothing, which the site does not hold"},
		"a blob's missing heading":  {`<a href="` + blob + `docs/a.md#nowhere">x</a>`, "docs/a.md has no heading #nowhere"},
		"a fragment into code":      {`<a href="` + blob + `cmd/x.go#L1">x</a>`, "a fragment into cmd/x.go, whose anchors cannot be checked"},
	} {
		files := maps.Clone(site)
		files["index.html"] = []byte(strings.Replace(string(site["index.html"]), "</body>", c.link+"</body>", 1))
		problems, _ := linkProblems(files, repo)
		wantProblem(t, name, problems, c.want)
	}
	files := maps.Clone(site)
	files["assets/a.css"] = []byte(`@font-face{src:url("fonts/none.woff2")}`)
	problems, _ = linkProblems(files, repo)
	wantProblem(t, "a stylesheet's missing font", problems, "assets/fonts/none.woff2")
	problems, _ = linkProblems(map[string][]byte{"index.html": []byte(`<html><a href="https://example.org/">x</a></html>`)}, repo)
	wantProblem(t, "no local link", problems, "no local link was resolved")
	problems, _ = linkProblems(map[string][]byte{"index.html": []byte(`<html><br></html>`)}, repo)
	wantProblem(t, "a page that does not parse", problems, "index.html:")
}

func TestIDProblemsAndFigureIndexes(t *testing.T) {
	doc := mustParse(t, `<html><figure class="dg" id="dgabc1231"/><p id="x"/><figure class="dg" id="dgabc1232"/></html>`)
	wantNone(t, "distinct ids", idProblems(doc))
	if got, problems := figureIndexes(doc); !slices.Equal(got, []int{1, 2}) || len(problems) != 0 {
		t.Errorf("figureIndexes = %v, %q", got, problems)
	}
	wantProblem(t, "a duplicate id", idProblems(mustParse(t, `<html><p id="x"/><svg><g id="x"/></svg></html>`)), `the id "x" is used twice`)
	wantProblem(t, "an empty id", idProblems(mustParse(t, `<html><p id=""/></html>`)), "empty id")
	if _, problems := figureIndexes(mustParse(t, `<html><figure class="dg" id="plain"/></html>`)); len(problems) == 0 {
		t.Error("a figure id with no index was accepted")
	}
}

func TestTagProblems(t *testing.T) {
	status := map[string]componentRow{
		"kernel-x": {id: "kernel-x", name: "Kernel `x`", label: "implemented"},
		"spool":    {id: "spool", name: "Spool", label: "experimental"},
		"web-ui":   {id: "web-ui", name: "Web UI", label: "planned"},
	}
	backlog := map[string]string{"B01": "Build the `first` thing", "B02": "Build the second thing"}
	good := `<html><head><title>A page</title><style>.st{content:""}</style></head>` +
		`<p>An <code class="st" data-status="spool" title="Spool">experimental</code> spool.</p>` +
		`<p class="state" data-status="kernel-x" title="Kernel x"><span class="st">implemented</span> today</p>` +
		`<li data-status="spool" title="Spool"><b>Spool</b><small class="st">experimental</small></li>` +
		`<section data-backlog="B01" title="Build the first thing"><p>Next · <code>planned</code> · <a class="id" href="/b">B01</a></p></section>` +
		`<p data-backlog="B02" title="Build the second thing">Later, <code>planned</code> (<a class="id" href="/b">B02</a>).</p></html>`
	wantNone(t, "labels and items that name their sources", tagProblems(mustParse(t, good), status, backlog, 3, 2))
	for name, c := range map[string]struct{ from, to, want string }{
		"a label not the row's":           {`<small class="st">experimental</small>`, `<small class="st">implemented</small>`, `shows ["implemented"], want the row's label "experimental"`},
		"no label shown":                  {`<small class="st">experimental</small>`, ``, `data-status "spool" shows []`},
		"two labels shown":                {`<small class="st">experimental</small>`, `<small class="st">experimental</small><i class="st">experimental</i>`, `shows ["experimental" "experimental"]`},
		"an unknown row":                  {`<li data-status="spool"`, `<li data-status="spool-store"`, `data-status "spool-store" names no row`},
		"a row's name for its id":         {`<li data-status="spool"`, `<li data-status="Spool"`, `data-status "Spool" is not a component id`},
		"an empty data-status":            {`<li data-status="spool"`, `<li data-status=""`, "an empty data-status"},
		"a label with no data-status":     {`<li data-status="spool" title="Spool">`, `<li>`, `a status label "experimental" outside a data-status item`},
		"an inline label not the row's":   {`title="Spool">experimental</code>`, `title="Spool">implemented</code>`, `shows ["implemented"], want the row's label "experimental"`},
		"an inline label with no row":     {`<code class="st" data-status="spool" title="Spool">`, `<code class="st">`, `a status label "experimental" outside a data-status item`},
		"a row's title missing":           {`<li data-status="spool" title="Spool">`, `<li data-status="spool">`, `data-status "spool" carries the title "", want the row's name "Spool"`},
		"another row's title":             {`<li data-status="spool" title="Spool">`, `<li data-status="spool" title="Kernel x">`, `data-status "spool" carries the title "Kernel x"`},
		"the id for a title":              {`<li data-status="spool" title="Spool">`, `<li data-status="spool" title="spool">`, `data-status "spool" carries the title "spool"`},
		"a code span left in a row title": {`data-status="kernel-x" title="Kernel x"`, "data-status=\"kernel-x\" title=\"Kernel `x`\"", "data-status \"kernel-x\" carries the title \"Kernel `x`\""},
		"a task's title missing":          {` title="Build the second thing"`, ``, `data-backlog "B02" carries the title "", want the task's Work cell "Build the second thing"`},
		"a code span left in a title":     {`title="Build the first thing"`, "title=\"Build the `first` thing\"", "data-backlog \"B01\" carries the title \"Build the `first` thing\""},
		"a bare label":                    {`</html>`, `<small>experimental</small></html>`, `the word "experimental" in "experimental" is tied to no row or task`},
		"a bare label in capitals":        {`</html>`, `<p>Implemented</p></html>`, `the word "Implemented" in "Implemented"`},
		"a label in a sentence":           {`</html>`, `<p>All six are experimental today.</p></html>`, `the word "experimental" in "All six are experimental today."`},
		"a label with a full stop":        {`</html>`, `<small>implemented.</small></html>`, `the word "implemented" in "implemented."`},
		"a label beside an empty icon":    {`</html>`, `<small><i></i>implemented</small></html>`, `the word "implemented" in "implemented"`},
		"a label after a word":            {`</html>`, `<small>Status: implemented</small></html>`, `the word "implemented" in "Status: implemented"`},
		"a claim in prose":                {`</html>`, `<p>The web UI is implemented.</p></html>`, `the word "implemented" in "The web UI is implemented."`},
		"a label beside the row's label":  {`<b>Spool</b>`, `<b>Spool is implemented</b>`, `the word "implemented" in "Spool is implemented"`},
		"a label inside a task":           {`Later, <code>planned</code>`, `Later, <code>implemented</code>`, `the word "implemented" in "implemented"`},
		"planned outside a backlog":       {`<p data-backlog="B02" title="Build the second thing">`, `<p>`, `the word "planned" in "planned"`},
		"an unknown backlog id":           {`data-backlog="B02"`, `data-backlog="B99"`, `"B99" names no task`},
		"an empty data-backlog":           {`data-backlog="B02"`, `data-backlog=""`, "an empty data-backlog"},
		"a backlog id not shown":          {`(<a class="id" href="/b">B02</a>)`, ``, `data-backlog "B02" shows the ids []`},
		"another backlog id shown":        {`<a class="id" href="/b">B02</a>`, `<a class="id" href="/b">B01</a>`, `data-backlog "B02" shows the ids ["B01"]`},
		"too few status labels":           {`<p class="state" data-status="kernel-x" title="Kernel x"><span class="st">implemented</span> today</p>`, ``, "2 status labels, want at least 3"},
		"one task tied twice":             {`<p data-backlog="B02" title="Build the second thing">Later, <code>planned</code> (<a class="id" href="/b">B02</a>).</p>`, `<p data-backlog="B01" title="Build the first thing">Later, <code>planned</code> (<a class="id" href="/b">B01</a>).</p>`, "1 distinct backlog tasks, want at least 2"},
	} {
		page := strings.Replace(good, c.from, c.to, 1)
		if page == good {
			t.Fatalf("%s: the fixture edit changed nothing", name)
		}
		wantProblem(t, name, tagProblems(mustParse(t, page), status, backlog, 3, 2), c.want)
	}
}

func TestPlannedOutsideBacklog(t *testing.T) {
	good := `<html><p>Built today.</p><section data-backlog="B01"><h2>Where it is going</h2><p>A graph view is planned.</p></section>` +
		`<p>Records are checked. <span data-backlog="B02">Tampering is planned.</span></p></html>`
	problems, read := plannedOutsideBacklog("index.html", pageSegments(mustParse(t, good)), nil)
	wantNone(t, "planned sentences inside backlog items", problems)
	if read != 2 {
		t.Errorf("read %d sentences that say planned, want 2", read)
	}
	for name, c := range map[string]struct{ from, to, want string }{
		"a planned sentence beside the item": {`<p>Built today.</p>`, `<p>Built today. Streaming is planned.</p>`, `"Streaming is planned." calls something planned`},
		"a planned label in code":            {`<p>Built today.</p>`, `<p>Streaming: <code>Planned</code></p>`, `"Streaming: Planned"`},
		"a section that lost its id":         {`<section data-backlog="B01">`, `<section>`, `"A graph view is planned."`},
		"on the roadmap":                     {`<p>Built today.</p>`, `<p>Streaming is on the roadmap.</p>`, `"Streaming is on the roadmap."`},
		"we plan to":                         {`<p>Built today.</p>`, `<p>We plan to stream.</p>`, `"We plan to stream."`},
		"later this year":                    {`<p>Built today.</p>`, `<p>Streaming arrives later this year.</p>`, `"Streaming arrives later this year."`},
		"coming soon":                        {`<p>Built today.</p>`, `<p>Streaming is coming soon.</p>`, `"Streaming is coming soon."`},
		"will be added":                      {`<p>Built today.</p>`, `<p>Streaming will be added.</p>`, `"Streaming will be added."`},
		"a task id outside the item":         {`<p>Built today.</p>`, `<p>Streaming is planned (B01).</p>`, `"Streaming is planned (B01)."`},
	} {
		page := strings.Replace(good, c.from, c.to, 1)
		problems, _ := plannedOutsideBacklog("index.html", pageSegments(mustParse(t, page)), nil)
		wantProblem(t, name, problems, c.want)
	}
	if _, read := plannedOutsideBacklog("index.html", pageSegments(mustParse(t, `<html><p>The plan is set.</p></html>`)), nil); read != 0 {
		t.Errorf("a sentence without the word was read as planned")
	}

	tasks := map[string]string{"B29": "Make the trail tamper-evident"}
	readme := "# P\n\nThe trail is checked for order, not yet for tampering (`planned`, [B29](docs/backlog.md)).\n"
	segments, err := readmeSegments([]byte(readme))
	if err != nil {
		t.Fatal(err)
	}
	if problems, read := plannedOutsideBacklog("README.md", segments, tasks); len(problems) != 0 || read != 1 {
		t.Errorf("a README sentence that names its task: problems %q, read %d, want none and 1", problems, read)
	}
	for name, c := range map[string]struct{ from, to, want string }{
		"no task named":     {"(`planned`, [B29](docs/backlog.md))", "(`planned`)", "tampering (`planned`)."},
		"an unknown task":   {"[B29]", "[B99]", "B99"},
		"a known and stray": {"[B29](docs/backlog.md)", "[B29](docs/backlog.md), B98", "B98"},
		"a promise":         {"The trail is checked for order, not yet for tampering (`planned`, [B29](docs/backlog.md)).", "Tamper evidence will be added.", "Tamper evidence will be added."},
	} {
		changed := strings.Replace(readme, c.from, c.to, 1)
		if changed == readme {
			t.Fatalf("%s: the fixture edit changed nothing", name)
		}
		segments, err := readmeSegments([]byte(changed))
		if err != nil {
			t.Fatal(err)
		}
		problems, _ := plannedOutsideBacklog("README.md", segments, tasks)
		wantProblem(t, name, problems, c.want)
	}
}

func TestIllustrationProblems(t *testing.T) {
	good := `<html><svg role="img" aria-label="A call is allowed."/><div role="img" aria-label="Three calls."/><p>text</p></html>`
	problems, drawn := illustrationProblems(mustParse(t, good))
	wantNone(t, "illustrations with text alternatives", problems)
	if drawn != 2 {
		t.Errorf("counted %d illustrations, want 2", drawn)
	}
	problems, drawn = illustrationProblems(mustParse(t, `<html><svg role="img" aria-label=" "/><div role="img"/></html>`))
	wantProblem(t, "a blank text alternative", problems, `a <svg role="img"> has no aria-label`)
	wantProblem(t, "no text alternative", problems, `a <div role="img"> has no aria-label`)
	if drawn != 0 {
		t.Errorf("counted %d illustrations without a text alternative, want 0", drawn)
	}
}

func TestScriptProblems(t *testing.T) {
	wantNone(t, "a page with no script", scriptProblems(mustParse(t, `<html><body><a href="/">x</a><svg><animate attributeName="opacity"/></svg></body></html>`)))
	for name, c := range map[string]struct{ page, want string }{
		"a script element":         {`<html><body><script>x()</script></body></html>`, "a script element"},
		"a script in capitals":     {`<html><body><SCRIPT/></body></html>`, "a script element"},
		"a script in an svg":       {`<html><svg><script href="/a.js"/></svg></html>`, "a script element"},
		"an event handler":         {`<html><body onload="x()"/></html>`, "the event handler onload on a <body>"},
		"an SVG animation handler": {`<html><svg><animate onbegin="x()"/></svg></html>`, "the event handler onbegin on a <animate>"},
		"a handler in capitals":    {`<html><a ONCLICK="x()">x</a></html>`, "the event handler ONCLICK"},
	} {
		wantProblem(t, name, scriptProblems(mustParse(t, c.page)), c.want)
	}
}

func TestThemeSwitchProblems(t *testing.T) {
	const tokens = "/t.css"
	good := `<html><head><link rel="stylesheet" href="/t.css"/></head><body><input type="checkbox" id="theme"/><label for="theme">x</label></body></html>`
	wantNone(t, "a page with its switch", themeSwitchProblems(mustParse(t, good), tokens))
	for name, c := range map[string]struct{ from, to, want string }{
		"no checkbox":           {`<input type="checkbox" id="theme"/>`, ``, "0 elements carry the id theme"},
		"a radio":               {`type="checkbox"`, `type="radio"`, "1 elements carry the id theme and 0 of them are a checkbox"},
		"the id on a label too": {`<label for="theme">`, `<label for="theme" id="theme">`, "2 elements carry the id theme"},
		"no label":              {`<label for="theme">x</label>`, ``, "0 labels for the theme switch"},
		"no tokens":             {`<link rel="stylesheet" href="/t.css"/>`, ``, "0 links to /t.css"},
		"other tokens":          {`href="/t.css"`, `href="/v1/t.css"`, "0 links to /t.css"},
	} {
		page := strings.Replace(good, c.from, c.to, 1)
		wantProblem(t, name, themeSwitchProblems(mustParse(t, page), tokens), c.want)
	}
}

func TestThemeTokenProblems(t *testing.T) {
	lightP := "color-scheme:light;--a:#fff;--b:#000;--c:1;--d:2;--e:3;--f:4;--g:5;--h:6;--i:7"
	darkP := "color-scheme:dark;--a:#000;--b:#fff;--c:1;--d:2;--e:3;--f:4;--g:5;--h:6;--i:7"
	good := ":root{\n  " + lightP + ";\n  --sans:\"X\",sans-serif;\n}\n" +
		"@media (prefers-color-scheme:dark){:root{\n  " + darkP + "}}\n" +
		"@media (prefers-color-scheme:light){html:has(#theme:checked){\n  " + darkP + "}}\n" +
		"@media (prefers-color-scheme:dark){html:has(#theme:checked){\n  " + lightP + "}}\n"
	wantNone(t, "the pinned shape", themeTokenProblems([]byte(good)))
	for name, c := range map[string]struct{ from, to, want string }{
		"a switch that stays light": {"@media (prefers-color-scheme:light){html:has(#theme:checked){\n  " + darkP, "@media (prefers-color-scheme:light){html:has(#theme:checked){\n  " + lightP, "the switch to dark differs from the dark palette"},
		"a colour that drifted":     {"html:has(#theme:checked){\n  " + lightP, "html:has(#theme:checked){\n  " + strings.Replace(lightP, "--b:#000", "--b:#111", 1), `the switch to light differs from the light palette in ["--b"]`},
		"no switch to light":        {"@media (prefers-color-scheme:dark){html:has(#theme:checked){\n  " + lightP + "}}\n", "", "the switch to light holds 0 colours"},
		"no dark default":           {"@media (prefers-color-scheme:dark){:root{\n  " + darkP + "}}\n", "", "the dark palette holds 0 colours"},
		"a palette set twice":       {":root{", ":root{--z:1}\n:root{", `the palette " :root" is set twice`},
	} {
		css := strings.Replace(good, c.from, c.to, 1)
		if css == good {
			t.Fatalf("%s: the fixture edit changed nothing", name)
		}
		wantProblem(t, name, themeTokenProblems([]byte(css)), c.want)
	}
}

func TestBacklogTitles(t *testing.T) {
	titles := backlogTitles(strings.Split("| ID | Work |\n| --- | --- |\n| B05 | Package a demo |\n| B5 | b |\n| X01 | c |\n", "\n"))
	if len(titles) != 1 || titles["B05"] != "Package a demo" {
		t.Errorf("backlogTitles = %v", titles)
	}
}

func TestTaglineProblem(t *testing.T) {
	want, err := readmeTagline([]string{"# T", "", "**Watch the calls your *agents* make.**", "**Later.**"})
	if err != nil || want != "Watch the calls your *agents* make." {
		t.Fatalf("readmeTagline = %q, %v", want, err)
	}
	if _, err := readmeTagline([]string{"# T", "plain"}); err == nil {
		t.Error("a README with no bold line gave a tagline")
	}
	const tagline = "Watch the tool calls your AI agents make."
	good := `<html><p class="tagline">Watch the tool calls your <span>AI agents</span>
	make.</p></html>`
	if p := taglineProblem(mustParse(t, good), tagline); p != "" {
		t.Errorf("a matching tagline: %s", p)
	}
	for name, c := range map[string]struct{ page, want string }{
		"an older tagline": {`<html><p class="tagline">Gate the tools your agents call.</p></html>`, "want the README's"},
		"no tagline":       {`<html><p>Watch the tool calls your AI agents make.</p></html>`, "0 tagline elements"},
		"two taglines":     {`<html><p class="tagline">a</p><p class="big tagline">b</p></html>`, "2 tagline elements"},
	} {
		if p := taglineProblem(mustParse(t, c.page), tagline); !strings.Contains(p, c.want) {
			t.Errorf("%s: %q, want a problem containing %q", name, p, c.want)
		}
	}
}

const goodWrangler = `{
  "name": "` + brand.Slug + `",
  "compatibility_date": "2026-09-28",
  "assets": {"directory": "./site", "html_handling": "auto-trailing-slash"},
  "routes": [{"pattern": "control.guardana.dev", "custom_domain": true}],
  "workers_dev": false,
  "preview_urls": false
}
`

func TestWranglerProblems(t *testing.T) {
	wantNone(t, "the pinned configuration", wranglerProblems([]byte(goodWrangler)))
	for name, c := range map[string]struct{ from, to, want string }{
		"a comment":          {`{`, "{\n  // deployed from here", "invalid character"},
		"a key twice":        {`"workers_dev": false,`, `"workers_dev": false, "workers_dev": true,`, `"workers_dev" appears twice`},
		"a nested key twice": {`"./site",`, `"./site", "directory": "./",`, `$.assets: the key "directory" appears twice`},
		"an extra key":       {`"preview_urls": false`, `"preview_urls": false, "main": "worker.js"`, "main is worker.js, want <nil>"},
		"workers.dev on":     {`"workers_dev": false`, `"workers_dev": true`, "workers_dev is true, want false"},
		"a missing key": {`,
  "preview_urls": false`, ``, "preview_urls is <nil>, want false"},
		"another directory":       {`"./site"`, `"."`, "assets is"},
		"another name":            {`"` + brand.Slug + `"`, `"site"`, "name is site"},
		"a value after the value": {"}\n", "}\n{}\n", "something follows"},
		"not an object":           {goodWrangler, `[]`, "not an object"},
		"a route, not a domain":   {`"custom_domain": true`, `"custom_domain": false`, "routes is"},
		"a pattern with a path":   {`"pattern": "control.guardana.dev"`, `"pattern": "control.guardana.dev/*"`, "routes is"},
		"no address":              {`"routes": [{"pattern": "control.guardana.dev", "custom_domain": true}],`, ``, "routes is <nil>"},
	} {
		wantProblem(t, name, wranglerProblems([]byte(strings.Replace(goodWrangler, c.from, c.to, 1))), c.want)
	}
}

func titledBlock(title string) string {
	return "```mermaid\nflowchart LR\n    accTitle: " + title + "\n    accDescr: d\n    A --> B\n```\n\n"
}

// A block inserted before a drawn one moves every later slot onto another
// diagram under its unchanged number; the pinned title catches it.
func TestSlotTitleProblems(t *testing.T) {
	page := []byte("<!-- diagram: README.md 1 --><!-- /diagram --><!-- diagram: README.md 2 --><!-- /diagram -->")
	readme := []byte(titledBlock("First") + titledBlock("Second"))
	wantNone(t, "slots on their diagrams", slotTitleProblems(page, readme, []string{"First", "Second"}))
	inserted := []byte(titledBlock("First") + titledBlock("New") + titledBlock("Second"))
	wantProblem(t, "a block inserted", slotTitleProblems(page, inserted, []string{"First", "Second"}), `slot 2 draws "New", want "Second"`)
	wantProblem(t, "a slot missing", slotTitleProblems(page, readme, []string{"First", "Second", "Third"}), "2 slots, want 3")
	wantProblem(t, "a block the README lacks", slotTitleProblems(page, []byte(titledBlock("First")), []string{"First", "Second"}), "slot 2 asks for block 2")
}

func TestPagePromiseProblems(t *testing.T) {
	for name, page := range map[string]string{
		"a plain statement":            `<html><p>The gateway decides each call. It records evidence.</p></html>`,
		"a promise in a backlog item":  `<html><ul><li data-backlog="B01"><span class="t">Policy explain is next</span></li></ul></html>`,
		"a word that holds the phrase": `<html><p>It ran through the monsoon season.</p></html>`,
		"a phrase in an attribute":     `<html><p title="coming soon">Shipped.</p></html>`,
		"a phrase in a style":          `<html><style>.soon{color:red}</style><p>Shipped.</p></html>`,
	} {
		problems, read := promiseProblems("index.html", pageSegments(mustParse(t, page)))
		wantNone(t, name, problems)
		if read == 0 {
			t.Errorf("%s: no sentence was read", name)
		}
	}
	for name, c := range map[string]struct{ page, want string }{
		"a promise of what shipped": {`<html><p>Today: a gateway. Explaining decisions and starter policy packs come next.</p></html>`,
			`index.html: the sentence "Explaining decisions and starter policy packs come next." promises future work ("come next")`},
		"a promise across markup": {`<html><p>Policy <code>explain</code> <em>comes</em>
			next.</p></html>`, `"Policy explain comes next." promises future work ("comes next")`},
		"a promise in capitals":        {`<html><h2>COMING SOON</h2></html>`, `("COMING SOON")`},
		"a promise beside a backlog":   {`<html><ul><li data-backlog="B01">B01</li></ul><p>B01 is next.</p></html>`, `("is next")`},
		"a promise in a backlog's tag": {`<html><p>Soon: <span data-backlog="B01">B01</span></p></html>`, `"Soon:" promises future work ("Soon")`},
		"a release promise":            {`<html><p>The next release will ship it.</p></html>`, `("next release")`},
	} {
		problems, _ := promiseProblems("index.html", pageSegments(mustParse(t, c.page)))
		wantProblem(t, name, problems, c.want)
	}
}

func TestReadmePromiseProblems(t *testing.T) {
	good := "<div align=\"center\"><img alt=\"coming soon\" src=\"x.png\"/></div>\n\n# Title\n\nThe gateway decides each call.\n\n```text\nPolicy explain is coming soon\n```\n\n- A listed item.\n"
	segments, err := readmeSegments([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	problems, read := promiseProblems("README.md", segments)
	wantNone(t, "prose with the phrase only in a fence and a tag", problems)
	if read != 3 {
		t.Errorf("read %d sentences, want 3", read)
	}
	for name, c := range map[string]struct{ readme, want string }{
		"a promise in a paragraph": {"# T\n\nPolicy explain is coming soon\n", `README.md: the sentence "Policy explain is coming soon" promises future work ("coming soon")`},
		"a promise over two lines": {"# T\n\nPolicy explain is\nnext. Then more.\n", `"Policy explain is next." promises future work ("is next")`},
		"a promise in a list item": {"- Done.\n- Up next: hooks.\n", `"Up next: hooks." promises`},
		"a promise in a table":     {"| a | b |\n| --- | --- |\n| hooks | soon |\n", `("soon")`},
		"a promise after a fence":  {"```\nx\n```\nPacks will ship.\n", `("will ship")`},
	} {
		segments, err := readmeSegments([]byte(c.readme))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		problems, _ := promiseProblems("README.md", segments)
		wantProblem(t, name, problems, c.want)
	}
	if _, err := readmeSegments([]byte("text\n```\nsoon\n")); err == nil {
		t.Error("an unclosed fence was read as prose")
	}
}

func TestPlannedProblems(t *testing.T) {
	status := map[string]componentRow{
		"evidence-spool": {id: "evidence-spool", name: "Evidence spool", label: "experimental"},
		"kernel-x":       {id: "kernel-x", name: "Kernel `x`", label: "implemented"},
		"web-ui":         {id: "web-ui", name: "Web UI", label: "planned"},
		"run-stop":       {id: "run-stop", name: "Stopping a run through a signed route", label: "experimental"},
		"mcp-gateway":    {id: "mcp-gateway", name: "Model Context Protocol (MCP) gateway", label: "experimental"},
		"backup-restore": {id: "backup-restore", name: "Backup and restore of authority state", label: "experimental"},
	}
	for name, page := range map[string]string{
		"planned work that is not built":      `<html><p>A <code>planned</code> Web UI.</p></html>`,
		"a delivered row in another sentence": `<html><p>The Evidence spool is experimental. Other work is <code>planned</code>.</p></html>`,
		"a delivered row in another block":    `<html><ul><li>Evidence spool</li><li><code>planned</code> work</li></ul></html>`,
		"part of a row's name":                `<html><p>Evidence is <code>planned</code>.</p></html>`,
		"a row's name inside a longer word":   `<html><p>Evidence spools are <code>planned</code>.</p></html>`,
		"planned outside code":                `<html><p>The Evidence spool was planned.</p></html>`,
		"a planned row's id":                  `<html><p>The web-ui is <code>planned</code>.</p></html>`,
		"an id inside a longer id":            `<html><p>An evidence-spool-mirror is <code>planned</code>.</p></html>`,
		"a name's one-word head":              `<html><p>A backup is <code>planned</code>.</p></html>`,
		"a lone abbreviation":                 `<html><p>Another MCP proxy is <code>planned</code>.</p></html>`,
	} {
		problems, _ := plannedProblems("index.html", pageSegments(mustParse(t, page)), status)
		wantNone(t, name, problems)
	}
	for name, c := range map[string]struct{ page, want string }{
		"an experimental row called planned": {`<html><p>The Evidence spool is <code>planned</code>.</p></html>`,
			`index.html: the sentence "The Evidence spool is planned." calls "evidence spool" planned; docs/status.md labels it experimental`},
		"a capital Planned": {`<html><p><code>Planned</code>: the Evidence spool. Then more.</p></html>`, `"Planned: the Evidence spool." calls "evidence spool" planned`},
		"an implemented row with a code span": {`<html><p>The Kernel <code>x</code> is <code>planned</code>.</p></html>`,
			`calls "kernel x" planned; docs/status.md labels it implemented`},
		"the last sentence of two":        {`<html><p>A gateway. <code>planned</code>: Evidence spool</p></html>`, `"planned: Evidence spool" calls "evidence spool"`},
		"a row's name in another case":    {`<html><p>An evidence spool is <code>planned</code>.</p></html>`, `calls "evidence spool" planned`},
		"a name's head":                   {`<html><p>Stopping a run is <code>planned</code>.</p></html>`, `calls "stopping a run" planned; docs/status.md labels it experimental`},
		"a name's abbreviation":           {`<html><p>An MCP gateway is <code>planned</code>.</p></html>`, `calls "mcp gateway" planned`},
		"a name without its abbreviation": {`<html><p>A Model Context Protocol gateway is <code>planned</code>.</p></html>`, `calls "model context protocol gateway" planned`},
		"a delivered row's id": {`<html><p>The <code>evidence-spool</code> row is <code>planned</code>.</p></html>`,
			`the sentence "The evidence-spool row is planned." calls "evidence-spool" planned; docs/status.md labels it experimental`},
		"an id before a full stop": {`<html><p><code>planned</code>: kernel-x.</p></html>`, `calls "kernel-x" planned; docs/status.md labels it implemented`},
	} {
		problems, read := plannedProblems("index.html", pageSegments(mustParse(t, c.page)), status)
		wantProblem(t, name, problems, c.want)
		if read != 1 {
			t.Errorf("%s: read %d planned labels, want 1", name, read)
		}
	}
}
