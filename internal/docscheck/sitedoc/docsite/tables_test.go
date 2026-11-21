package docsite

import (
	"strings"
	"testing"
)

// words is n words of one letter each.
func words(n int) string { return strings.TrimSpace(strings.Repeat("w ", n)) }

// A table whose cells are sentences renders as a list: each row's first cell
// its title, every other cell under its column's name.
func TestASentenceTableBecomesStackedRows(t *testing.T) {
	long := "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen"
	out := renderA(t, "# A\n\n| Risk | Control | Gap |\n| --- | --- | --- |\n"+
		"| R1 | "+long+" | "+long+" |\n| R2 | *short* | |\n")
	want := "<ul class=\"stack\">\n" +
		"<li><p class=\"rt\">R1</p><dl><dt>Control</dt><dd>one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen</dd>" +
		"<dt>Gap</dt><dd>one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen</dd></dl></li>\n" +
		"<li><p class=\"rt\">R2</p><dl><dt>Control</dt><dd><em>short</em></dd><dt>Gap</dt><dd></dd></dl></li>\n" +
		"</ul>\n"
	if !strings.Contains(out, want) {
		t.Errorf("the sentence table is not stacked rows:\n%s", out)
	}
	if strings.Contains(out, "<table") || strings.Contains(out, `class="tbl"`) {
		t.Errorf("the stacked table also rendered as a table:\n%s", out)
	}
}

// The bound: two columns that each hold a cell of fifteen words stack the
// table; one word fewer in either, or one sentence column alone, keeps it a
// table. The title column counts like any other.
func TestATableStacksAtFifteenWordsInTwoColumns(t *testing.T) {
	cases := map[string]struct {
		a, b, c string
		stacked bool
	}{
		"two columns at fifteen":   {"t", words(15), words(15), true},
		"the title column counts":  {words(15), words(15), "x", true},
		"one column at fourteen":   {"t", words(15), words(14), false},
		"one sentence column":      {"t", words(80), "x", false},
		"fourteen in every column": {words(14), words(14), words(14), false},
		"code within a word":       {"t", words(15), words(13) + " (`x`)", false},
	}
	for name, c := range cases {
		out := renderA(t, "# A\n\n| A | B | C |\n| --- | --- | --- |\n| "+c.a+" | "+c.b+" | "+c.c+" |\n| x | y | z |\n")
		stacked := strings.Contains(out, `<ul class="stack">`)
		boxed := strings.Contains(out, "<div class=\"tbl\">\n<table>")
		if stacked != c.stacked || boxed == c.stacked {
			t.Errorf("%s: stacked %v, boxed %v; want stacked %v:\n%s", name, stacked, boxed, c.stacked, out)
		}
	}
}

// A word in code or a link counts as a word of the sentence.
func TestCodeAndLinksCountAsWords(t *testing.T) {
	cell := "`one two` three [four five](https://example.invalid/x) six seven eight nine ten eleven twelve thirteen fourteen fifteen"
	out := renderA(t, "# A\n\n| A | B | C |\n| --- | --- | --- |\n| t | "+cell+" | "+cell+" |\n")
	if !strings.Contains(out, `<ul class="stack">`) {
		t.Errorf("fifteen words with code and a link were not read as a sentence:\n%s", out)
	}
}

// A header cell with markup still gives a plain label, escaped once; its code
// keeps a backslash and a reference as written.
func TestAStackedLabelIsTheHeadersPlainText(t *testing.T) {
	out := renderA(t, "# A\n\n| Name | `<id>\\*` **key** &amp; [ref](https://example.invalid/r) | C |\n| --- | --- | --- |\n"+
		"| t | "+words(15)+" | "+words(15)+" |\n")
	if !strings.Contains(out, "<dt>&lt;id&gt;\\* key &amp; ref</dt>") {
		t.Errorf("the label is not the header's plain text:\n%s", out)
	}
}

// Code in a table cell may break after each slash; code anywhere else, and a
// pipe escaped inside code in a cell, render as they always did, a backslash
// and a reference in code as written.
func TestCodeInATableBreaksAfterAPathSeparator(t *testing.T) {
	out := renderA(t, "# A\n\n`a/b` and `c\\*&amp;` here.\n\n| File | Note |\n| --- | --- |\n| `internal/x/y.go` | `p\\|q` and `/` |\n")
	for _, want := range []string{
		"<code>a/b</code> and <code>c\\*&amp;amp;</code> here.",
		"<td><code>internal/<wbr/>x/<wbr/>y.go</code></td>",
		"<td><code>p|q</code> and <code>/</code></td>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("want %s in:\n%s", want, out)
		}
	}
}
