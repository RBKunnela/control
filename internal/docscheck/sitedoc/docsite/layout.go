package docsite

import (
	stdhtml "html"
	"slices"
	"strings"

	"github.com/guardana/control/internal/brand"

	"github.com/guardana/control/internal/docscheck/frontmatter"
	"github.com/guardana/control/internal/docscheck/indexdoc"
	"github.com/guardana/control/internal/docscheck/sitedoc"
)

// The two sections a page type does not name: the records, listed on the
// index rather than one by one, and the project pages the roadmap and the
// changelog join.
var (
	sectionRecords = "Decision records"
	sectionProject = indexdoc.Section("project")
)

// shield is the product's mark, drawn inline in the page's accent.
const shield = `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.8 4.5 5.6v6.1c0 4.6 3.2 8.2 7.5 9.5 4.3-1.3 7.5-4.9 7.5-9.5V5.6z"/><path d="M10.2 8.4v7.8M10.2 12.3h5.3"/></svg>`

// logo is the product's mark and name, linking the landing page.
var logo = `<a class="logo" href="/">` + shield + esc(brand.Name) + `</a>`

// repository is the project's home on its host.
var repository = "https://" + brand.ModulePath

// themeSwitch is a checkbox that selects the theme the system did not ask
// for, read by the tokens' :has() rule, so the switch needs no script.
const themeSwitch = `<input type="checkbox" id="theme" aria-label="Switch between light and dark"/><label class="tgl" for="theme" title="Switch theme"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M5.6 18.4 7 17M17 7l1.4-1.4"/></svg></label>`

// header is the site's one header, the landing page's as well: the logo, the
// released version's pill, the primary navigation and the theme switch. The
// landing page holds the same bytes with the pill inside its release slot.
func header(pill string) string {
	return `<header class="top"><div class="w">
  ` + logo + `
  ` + pill + `
  <nav class="links" aria-label="Primary"><a href="/#how">How it works</a><a href="/#signed">Signed</a><a href="/#get">What you get</a><a href="/#start">Quickstart</a><a href="/#limits">Limits</a><a href="/docs/">Docs</a></nav>
  <div class="right">
    ` + themeSwitch + `
    <a class="btn s sm" href="` + repository + `">Star on GitHub</a>
  </div>
</div></header>
`
}

// footer is the site's one footer, the landing page's as well.
var footer = `<footer class="ft"><div class="w">
  <div class="fb">` + logo + `<p>A control and supervision layer for AI agents. <a href="` + repository + `/blob/main/LICENSE">Apache-2.0</a>.</p><p><a href="https://guardana.dev">Guardana</a> and ` + esc(brand.Name) + ` are independent projects. See <a href="https://github.com/guardana/guardana">Guardana on GitHub</a>.</p></div>
  <div><b>Product</b><a href="/#how">How it works</a><a href="/#get">What you get</a><a href="/#limits">Limits</a><a href="/docs/status">Status</a></div>
  <div><b>Docs</b><a href="/docs/get-started/try-the-demo">Try the demo</a><a href="/docs/guides/connect-an-existing-mcp-setup">Connect an MCP setup</a><a href="/docs/guides/write-and-test-a-policy">Write a policy</a><a href="/docs/concepts/threat-model">Threat model</a></div>
  <div><b>Project</b><a href="` + repository + `">GitHub</a><a href="` + repository + `/releases">Releases</a><a href="/docs/roadmap">Roadmap</a><a href="` + repository + `/blob/main/SECURITY.md">Security</a><a href="` + repository + `/blob/main/TRADEMARKS.md">Trademarks</a></div>
</div></footer>
`

type navEntry struct{ label, url string }

type navSection struct {
	heading string
	entries []navEntry
}

// buildNav groups the pages the way docs/index.md groups them, in the order of
// the page types, with the records as one entry pointing at their list.
func buildNav(pages []*page) []navSection {
	var nav []navSection
	add := func(heading string, e navEntry) {
		for i := range nav {
			if nav[i].heading == heading {
				nav[i].entries = append(nav[i].entries, e)
				return
			}
		}
		nav = append(nav, navSection{heading: heading, entries: []navEntry{e}})
	}
	for _, typ := range frontmatter.Types {
		heading := indexdoc.Section(typ)
		for _, p := range pages {
			if p.section == heading {
				add(heading, navEntry{p.title, p.url})
			}
		}
	}
	add(sectionProject, navEntry{sectionRecords, "/docs/#decision-records"})
	return nav
}

// layout wraps a rendered body in the site's chrome: the header, the
// documentation's navigation with the current page marked, once as the menu a
// narrow screen shows above the content and once as the sidebar, the page's
// source with the released version, and the footer.
func layout(p *page, nav []navSection, released string, body []byte) []byte {
	var b strings.Builder
	title := p.title + " · " + brand.Name
	sections := sectionList(p, nav)
	b.WriteString(`<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>` + esc(title) + `</title>
<meta name="description" content="` + esc(p.summary) + `"/>
<link rel="canonical" href="` + Origin + p.url + `"/>
<meta name="theme-color" content="#FFFFFF" media="(prefers-color-scheme: light)"/>
<meta name="theme-color" content="#0A0A0A" media="(prefers-color-scheme: dark)"/>
<link rel="icon" href="/favicon.svg" type="image/svg+xml"/>
<link rel="stylesheet" href="/assets/control/v2/tokens.css"/>
<link rel="stylesheet" href="/assets/control/control.css"/>
<link rel="stylesheet" href="/assets/control/docs.css"/>
</head>
<body class="doc">
<a class="skip" href="#main">Skip to content</a>
` + header(sitedoc.Pill(released)) + `<div class="w shell">
<details class="mnav">
<summary>Menu · <b>` + esc(p.title) + `</b></summary>
<nav class="inner" aria-label="Documentation">
` + sections + `</nav>
</details>
<main id="main" class="prose">
`)
	b.Write(body)
	b.WriteString(`<p class="src">Rendered from <a href="` + sourceURL(p.src, false) + `">` + esc(p.src) +
		`</a> on <code>main</code>. It describes the tree as it is now; a release's notes say what a tag holds. ` +
		`The latest release is v` + esc(released) + `, and <a href="` + esc(sitedoc.TagDocs(released)) + `">its documentation</a> is in its tag.</p>
</main>
<nav class="side" aria-label="Documentation">
` + sections + `</nav>
</div>
` + footer + `</body>
</html>
`)
	return []byte(b.String())
}

// sectionList is the documentation's sections as lists of links, the
// current page marked.
func sectionList(p *page, nav []navSection) string {
	var b strings.Builder
	current := func(url string) string {
		if url == p.url {
			return ` aria-current="page"`
		}
		return ""
	}
	b.WriteString(`<ul class="home"><li><a href="/docs/"` + current("/docs/") + `>Overview</a></li></ul>
`)
	for _, s := range nav {
		b.WriteString("<h2>" + esc(s.heading) + "</h2><ul>\n")
		for _, e := range s.entries {
			b.WriteString(`<li><a href="` + e.url + `"` + current(e.url) + `>` + esc(e.label) + "</a></li>\n")
		}
		b.WriteString("</ul>\n")
	}
	return b.String()
}

// sitemap lists the landing page and every rendered page, in path order.
func sitemap(pages []*page) []byte {
	urls := []string{Origin + "/"}
	for _, p := range pages {
		urls = append(urls, Origin+p.url)
	}
	slices.Sort(urls)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
`)
	for _, u := range urls {
		b.WriteString("  <url><loc>" + esc(u) + "</loc></url>\n")
	}
	b.WriteString("</urlset>\n")
	return []byte(b.String())
}

func esc(s string) string { return stdhtml.EscapeString(s) }
