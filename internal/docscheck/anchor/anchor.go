// Package anchor spells the fragment GitHub gives a Markdown heading. The link
// check and the rendered pages both use it, so a fragment that resolves on one
// resolves on the other.
package anchor

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	closingHashes = regexp.MustCompile(`[ \t]+#+$`)
	inlineLink    = regexp.MustCompile(`!?\[([^\]]*)\]\([^)]*\)`)
	// What GitHub drops from a heading to make its anchor: everything but
	// letters, marks, decimal digits, connector punctuation such as "_",
	// spaces and hyphens.
	notInAnchor = regexp.MustCompile(`[^\p{L}\p{M}\p{Nd}\p{Pc} -]`)
)

// Of spells the anchor of a heading's text as written in Markdown: link syntax
// reduced to its text, lower case, the characters above dropped, each space
// turned into a hyphen.
func Of(text string) string {
	text = closingHashes.ReplaceAllString(text, "")
	text = inlineLink.ReplaceAllString(text, "$1")
	text = notInAnchor.ReplaceAllString(strings.ToLower(text), "")
	return strings.ReplaceAll(text, " ", "-")
}

// Numbering gives the headings of one page their anchors in page order, a
// repeated one numbered "-1", "-2" and on, as GitHub numbers them. It holds
// every anchor it gave with the last number tried after it, so a numbered
// anchor is never given twice.
type Numbering map[string]int

// Next is the anchor of the page's next heading: its own anchor, or the
// first numbered one after it that no earlier heading took.
func (n Numbering) Next(text string) string {
	base := Of(text)
	a := base
	for {
		if _, taken := n[a]; !taken {
			break
		}
		n[base]++
		a = base + "-" + strconv.Itoa(n[base])
	}
	n[a] = 0
	return a
}
