package docscheck

import (
	"strings"
	"testing"
)

func TestItemListProblems(t *testing.T) {
	page := `<html><div data-status="spool"><h3>Can we read it?</h3></div>` +
		`<div class="txt" data-status="kernel"><span>01</span><h3>Rules first</h3><p class="state">x</p></div>` +
		`<li data-backlog="B29"><i></i><b>The record itself</b></li>` +
		`<span data-backlog="B29">Records are checked (B29).</span>` +
		`<details data-backlog="B28"><summary>Does it run alone?</summary><p>Not yet.</p></details></html>`
	want := []siteItem{
		{"Can we read it?", "status: spool"},
		{"Rules first", "status: kernel"},
		{"The record itself", "backlog: B29"},
		{"Records are checked (B29).", "backlog: B29"},
		{"Does it run alone?", "backlog: B28"},
	}
	wantNone(t, "a page that matches its reviewed list", itemListProblems(pageItems(mustParse(t, page)), want))
	for name, c := range map[string]struct{ from, to, want string }{
		"a card that claims another row": {`data-status="spool"><h3>Can we read it?`, `data-status="decision-records"><h3>Can we read it?`, `the page ties "Can we read it?" to "status: decision-records" 1 more time(s)`},
		"one row tied to a second card":  {`</html>`, `<div data-status="spool"><h3>Can we stop it?</h3></div></html>`, `ties "Can we stop it?" to "status: spool"`},
		"the same card twice":            {`</html>`, `<div data-status="spool"><h3>Can we read it?</h3></div></html>`, `ties "Can we read it?" to "status: spool" 1 more time(s)`},
		"a listed card gone":             {`<details data-backlog="B28"><summary>Does it run alone?</summary><p>Not yet.</p></details>`, ``, `the reviewed list ties "Does it run alone?" to "backlog: B28", and the page does not`},
		"a heading reworded":             {`<b>The record itself</b>`, `<b>The trail itself</b>`, `the page ties "The trail itself" to "backlog: B29"`},
	} {
		changed := strings.Replace(page, c.from, c.to, 1)
		if changed == page {
			t.Fatalf("%s: the fixture edit changed nothing", name)
		}
		wantProblem(t, name, itemListProblems(pageItems(mustParse(t, changed)), want), c.want)
	}
}

func TestReadmeLede(t *testing.T) {
	for _, c := range []struct{ readme, want, err string }{
		{"# P\n\n**Run it.**\n\nIt decides each call\nbefore it runs.\n\n[badge]\n", "It decides each call before it runs.", ""},
		{"# P\n\n**Run it.**\nIt decides.", "It decides.", ""},
		{"# P\n\nIt decides.\n", "", "no bold tagline"},
		{"# P\n\n**Run it.**\n\n", "", "no paragraph follows"},
	} {
		got, err := readmeLede(strings.Split(c.readme, "\n"))
		switch {
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%q: err = %v, want %q", c.readme, err, c.err)
		case c.err == "" && (err != nil || got != c.want):
			t.Errorf("%q: lede = %q, %v; want %q", c.readme, got, err, c.want)
		}
	}
}

func TestOneTextProblem(t *testing.T) {
	const lede = "It decides each call that goes through it."
	page := `<html><h1 class="tagline">Run it.</h1><p class="lede">It decides each call that goes through it.</p></html>`
	if problem := oneTextProblem(mustParse(t, page), "lede", lede); problem != "" {
		t.Errorf("the README's lede: %s", problem)
	}
	for name, c := range map[string]struct{ from, to, want string }{
		"a lede that drops the limit": {"each call that goes through it.", "each call.", `the lede reads "It decides each call.", want the README's`},
		"no lede":                     {` class="lede"`, ``, "0 lede elements, want 1"},
		"two ledes":                   {`</html>`, `<p class="lede">More.</p></html>`, "2 lede elements, want 1"},
	} {
		if problem := oneTextProblem(mustParse(t, strings.Replace(page, c.from, c.to, 1)), "lede", lede); !strings.Contains(problem, c.want) {
			t.Errorf("%s: problem = %q, want %q", name, problem, c.want)
		}
	}
}

func TestLLMsProblems(t *testing.T) {
	const lede = "It decides each call that goes through it."
	good := "# P\n\n> It decides each call that goes through it.\n\n" +
		"This is alpha software and not a security boundary: do not deploy it as one. https://example.org/docs/status\n"
	wantNone(t, "a map that quotes the lede and states the status", llmsProblems(good, lede))
	for name, c := range map[string]struct{ from, to, want string }{
		"a status that claims readiness":     {"This is alpha software and not a security boundary: do not deploy it as one.", "This is production-ready software and a security boundary you can deploy.", `it does not say "alpha"`},
		"the boundary dropped":               {"not a security boundary", "a boundary", `it does not say "not a security boundary"`},
		"another description":                {"> It decides each call that goes through it.", "> It decides each call.", "the description is not README's lede"},
		"readiness claimed beside the facts": {"This is alpha software", "Past alpha, production-ready; earlier releases were alpha software", `it says "production-ready"`},
	} {
		wantProblem(t, name, llmsProblems(strings.Replace(good, c.from, c.to, 1), lede), c.want)
	}
}

func TestReadinessProblems(t *testing.T) {
	wantNone(t, "alpha, deletes in production", readinessProblems("Alpha software. Deletes in production are denied."))
	for _, text := range []string{"It is production-ready.", "Production ready today.", "production\nready", "PRODUCTION-READY"} {
		if len(readinessProblems(text)) != 1 {
			t.Errorf("%q: readiness not refused", text)
		}
	}
}

func TestFooterCountProblem(t *testing.T) {
	page := `<html><main>x</main><footer class="ft">f</footer></html>`
	if problem := footerCountProblem(mustParse(t, page)); problem != "" {
		t.Errorf("one footer: %s", problem)
	}
	for name, changed := range map[string]string{
		"a second footer": strings.Replace(page, `<main>x</main>`, `<main>x<footer class="foot">claim</footer></main>`, 1),
		"no footer":       `<html><main>x</main></html>`,
	} {
		if problem := footerCountProblem(mustParse(t, changed)); problem == "" {
			t.Errorf("%s: no problem reported", name)
		}
	}
}

func TestStyleProblems(t *testing.T) {
	tokens := tokenNames(`:root{color-scheme:light;--bg:#fff;--ink:#000}` +
		`@media (prefers-color-scheme:light){html:has(#theme:checked){--bg:#000;--ink:#fff}}`)
	if len(tokens) != 2 || !tokens["--bg"] || !tokens["--ink"] {
		t.Fatalf("tokens = %v, want --bg and --ink", tokens)
	}
	good := `/* --bg:red is a comment */ :root{--panel:var(--bg)} .a{justify-content:center;align-content:start}` +
		`.b:before{content:""} .c:after{content:"+"} .d:before{content:'\2212'}`
	wantNone(t, "a stylesheet that reads tokens and writes no words", styleProblems(good, tokens))
	for name, c := range map[string]struct{ add, want string }{
		"a token set again":       {`html:has(#theme:checked){--bg:#FF0000}`, "it sets --bg, a token only tokens.css sets"},
		"a token set in a rule":   {`.e{color:red;--ink:red}`, "it sets --ink"},
		"words through content":   {`.lede::after{content:" Production-ready, implemented."}`, `content: " Production-ready, implemented." writes words`},
		"words in single quotes":  {`.f:before{content:'Rule: '}`, `content: 'Rule: ' writes words`},
		"an attribute read aloud": {`.g:after{content:attr(title)}`, "content: attr(title) writes words"},
		"content in capitals":     {`.h:after{CONTENT:"Beta"}`, `content: "Beta" writes words`},
	} {
		wantProblem(t, name, styleProblems(good+c.add, tokens), c.want)
	}
}
