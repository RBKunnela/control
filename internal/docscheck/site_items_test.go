// What ties the landing page to its sources beyond the labels: each tied
// element paired with the heading it carries, the lede README sets, the
// status llms.txt states, the one footer, and stylesheets that neither set a
// token nor write words.
package docscheck

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// siteItem pairs a tied element's heading with the row or the task it names:
// "status: <component id>" or "backlog: <task id>".
type siteItem struct{ heading, source string }

// landingItems is the reviewed list of the landing page's tied elements. A
// card that claims a row it does not describe, a row used once more, or a
// card that is gone fails until this list is reviewed with it.
var landingItems = []siteItem{
	{"Policy tests", "status: policy-cli"},
	{"Approvals", "status: approval-binding"},
	{"Run review", "status: run-supervision"},
	{"Downloads", "status: releases"},
	{"Rules in front of every call", "status: mcp-gateway"},
	{"A person signs off the risky ones", "status: approval-binding"},
	{"Catch what went around the rules", "status: run-supervision"},
	{"Why was that call allowed?", "status: evidence-spool"},
	{"What did we not see?", "status: coverage-map"},
	{"Can we stop it?", "status: run-stop"},
	{"Can our auth service overrule it?", "status: external-pdp"},
	{"What about tools that are not MCP?", "status: enforce-receiver"},
	{"Does it fit what we already watch?", "status: observations"},
	{"The rules", "status: policy-keys"},
	{"That the rules are current", "status: policy-refresh"},
	{"Who may operate", "status: trust-roster"},
	{"What operators do", "status: approval-authority"},
	{"What you download", "status: releases"},
	{"Watch a run as a graph. Change the rule beside it.", "backlog: B39"},
	{"The record itself", "backlog: B29"},
	{"The evidence trail is checked for order, not yet for tampering (planned, B29).", "backlog: B29"},
	{"The bundled demo saves its call records on your machine (experimental).", "status: dev-mode"},
	{"Does supervision run on its own?", "backlog: B28"},
}

// minLandingTasks is the number of distinct backlog tasks the landing page
// ties: B28, B29 and B39.
const minLandingTasks = 3

var itemHeadings = map[string]bool{"h1": true, "h2": true, "h3": true, "h4": true, "b": true, "summary": true}

// itemHeading is the text of the first heading, bold or summary element in
// n, n itself included, or n's whole text when it holds none.
func itemHeading(n *xnode) string {
	heading := ""
	n.walk(func(e *xnode) {
		if heading == "" && itemHeadings[e.name] {
			heading = e.text()
		}
	})
	if heading == "" {
		return n.text()
	}
	return heading
}

// pageItems lists every tied element of a page as a siteItem.
func pageItems(doc *xnode) []siteItem {
	var items []siteItem
	doc.walk(func(n *xnode) {
		if row, ok := n.attrs["data-status"]; ok {
			items = append(items, siteItem{itemHeading(n), "status: " + row})
		}
		if id, ok := n.attrs["data-backlog"]; ok {
			items = append(items, siteItem{itemHeading(n), "backlog: " + id})
		}
	})
	return items
}

// itemListProblems compares the page's items with the reviewed list as two
// multisets: an item on the page more often than listed, or listed and not
// on the page, is refused.
func itemListProblems(got, want []siteItem) []string {
	count := map[siteItem]int{}
	for _, it := range want {
		count[it]++
	}
	for _, it := range got {
		count[it]--
	}
	var problems []string
	for _, it := range slices.Concat(want, got) {
		switch n := count[it]; {
		case n < 0:
			problems = append(problems, fmt.Sprintf("the page ties %q to %q %d more time(s) than the reviewed list", it.heading, it.source, -n))
		case n > 0:
			problems = append(problems, fmt.Sprintf("the reviewed list ties %q to %q, and the page does not, %d time(s)", it.heading, it.source, n))
		default:
			continue
		}
		count[it] = 0
	}
	return problems
}

// readmeLede is the first paragraph after README's bold tagline line,
// joined onto one line.
func readmeLede(lines []string) (string, error) {
	start := slices.IndexFunc(lines, func(l string) bool { return boldLine.MatchString(strings.TrimSpace(l)) })
	if start < 0 {
		return "", fmt.Errorf("the README holds no bold tagline line")
	}
	var lede []string
	for _, line := range lines[start+1:] {
		line = strings.TrimSpace(line)
		if line == "" && len(lede) > 0 {
			break
		}
		if line != "" {
			lede = append(lede, line)
		}
	}
	if len(lede) == 0 {
		return "", fmt.Errorf("no paragraph follows the README's tagline")
	}
	return strings.Join(lede, " "), nil
}

// oneTextProblem holds the one element of a page that carries class to want.
func oneTextProblem(doc *xnode, class, want string) string {
	found := doc.texts(class)
	switch {
	case len(found) != 1:
		return fmt.Sprintf("%d %s elements, want 1", len(found), class)
	case found[0] != want:
		return fmt.Sprintf("the %s reads %q, want the README's %q", class, found[0], want)
	}
	return ""
}

// llmsProblems holds llms.txt to the description README sets and to the
// two facts its status must state.
func llmsProblems(llms, lede string) []string {
	var problems []string
	if !strings.Contains(llms, "\n> "+lede+"\n") {
		problems = append(problems, fmt.Sprintf("the description is not README's lede %q", lede))
	}
	for _, fact := range []string{"alpha", "not a security boundary"} {
		if !strings.Contains(llms, fact) {
			problems = append(problems, fmt.Sprintf("it does not say %q", fact))
		}
	}
	return append(problems, readinessProblems(llms)...)
}

var readinessPhrase = regexp.MustCompile(`(?i)\bproduction[\s-]+ready\b`)

// readinessProblems refuses each claim in text that the project is ready
// for production: the status page says it is alpha, and no sentence that
// says otherwise is true, however it is hedged.
func readinessProblems(text string) []string {
	var problems []string
	for _, m := range readinessPhrase.FindAllString(text, -1) {
		problems = append(problems, fmt.Sprintf("it says %q; the project is alpha", m))
	}
	return problems
}

// footerCountProblem holds a page to one footer element.
func footerCountProblem(doc *xnode) string {
	footers := 0
	doc.walk(func(n *xnode) { footers += count(n.name == "footer") })
	if footers != 1 {
		return fmt.Sprintf("%d footer elements, want 1", footers)
	}
	return ""
}

var (
	cssComment     = regexp.MustCompile(`(?s)/\*.*?\*/`)
	customProperty = regexp.MustCompile(`(?:^|[{;\s])(--[A-Za-z0-9_-]+)\s*:`)
	contentValue   = regexp.MustCompile(`(?i)(?:^|[{;\s])content\s*:\s*([^;}]*)`)
	quotedLetter   = regexp.MustCompile(`["'][^"']*\pL[^"']*["']`)
)

// tokenNames lists the custom properties a stylesheet sets.
func tokenNames(css string) map[string]bool {
	names := map[string]bool{}
	for _, m := range customProperty.FindAllStringSubmatch(cssComment.ReplaceAllString(css, ""), -1) {
		names[m[1]] = true
	}
	return names
}

// styleProblems refuses, in a stylesheet other than the tokens, a custom
// property the tokens set, and a `content` that writes letters or reads an
// attribute: the page's words and colours come from the page and the tokens.
func styleProblems(css string, tokens map[string]bool) []string {
	css = cssComment.ReplaceAllString(css, "")
	var problems []string
	for _, m := range customProperty.FindAllStringSubmatch(css, -1) {
		if tokens[m[1]] {
			problems = append(problems, fmt.Sprintf("it sets %s, a token only tokens.css sets", m[1]))
		}
	}
	for _, m := range contentValue.FindAllStringSubmatch(css, -1) {
		if quotedLetter.MatchString(m[1]) || strings.Contains(strings.ToLower(m[1]), "attr(") {
			problems = append(problems, fmt.Sprintf("content: %s writes words", strings.TrimSpace(m[1])))
		}
	}
	return problems
}
