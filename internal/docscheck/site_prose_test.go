// The landing page's and the README's free prose, read sentence by sentence:
// a promise of later work and a `planned` label are claims no status or
// backlog tag carries, so they are checked here.
package docscheck

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// futurePhrase matches a sentence that promises work for later.
var futurePhrase = regexp.MustCompile(`(?i)\b(?:comes?\s+next|coming\s+soon|next\s+release|will\s+ship|is\s+next|are\s+next|up\s+next|soon|on\s+the\s+roadmap|we\s+plan\s+to|later\s+this\s+year|will\s+be\s+added)\b`)

// inlineElements continue a sentence; every other element ends one.
var inlineElements = map[string]bool{
	"a": true, "abbr": true, "b": true, "cite": true, "code": true, "dfn": true, "em": true,
	"i": true, "kbd": true, "mark": true, "q": true, "s": true, "samp": true, "small": true,
	"span": true, "strong": true, "sub": true, "sup": true, "time": true, "u": true, "var": true,
}

// proseSegment is a run of text no block boundary breaks, whitespace
// collapsed, with the offsets at which a `planned` code element starts.
type proseSegment struct {
	text    string
	planned []int
	backlog bool
}

type segmenter struct {
	segments []proseSegment
	b        strings.Builder
	space    bool
	planned  []int
	backlog  bool
}

func (s *segmenter) flush() {
	if s.b.Len() > 0 {
		s.segments = append(s.segments, proseSegment{text: s.b.String(), planned: s.planned, backlog: s.backlog})
	}
	s.b.Reset()
	s.space, s.planned = false, nil
}

func (s *segmenter) write(text string) {
	for _, r := range text {
		if unicode.IsSpace(r) {
			s.space = s.b.Len() > 0
			continue
		}
		if s.space {
			s.b.WriteByte(' ')
			s.space = false
		}
		s.b.WriteRune(r)
	}
}

func (s *segmenter) markPlanned() {
	at := s.b.Len()
	if s.space {
		at++
	}
	s.planned = append(s.planned, at)
}

func (s *segmenter) visit(n *xnode) {
	if n.name == "style" || n.name == "script" {
		return
	}
	_, backlog := n.attrs["data-backlog"]
	block := backlog || !inlineElements[n.name]
	if block {
		s.flush()
	}
	outer := s.backlog
	s.backlog = outer || backlog
	if t := n.text(); n.name == "code" && (t == "planned" || t == "Planned") {
		s.markPlanned()
	}
	for _, p := range n.parts {
		if p.node != nil {
			s.visit(p.node)
		} else {
			s.write(p.text)
		}
	}
	if block {
		s.flush()
	}
	s.backlog = outer
}

// pageSegments is the page's visible text, broken at every block element and
// at every data-backlog element.
func pageSegments(doc *xnode) []proseSegment {
	s := &segmenter{}
	s.visit(doc)
	s.flush()
	return s.segments
}

var (
	markdownTag       = regexp.MustCompile(`<[^>]*>`)
	markdownListStart = regexp.MustCompile(`^(?:[-*>]|[0-9]+\.)\s`)
)

// readmeSegments is the README's prose: one segment per paragraph, list
// item, heading or table row, with fenced blocks and HTML tags left out.
func readmeSegments(markdown []byte) ([]proseSegment, error) {
	s := &segmenter{}
	fenced, opened := false, 0
	for i, line := range strings.Split(string(markdown), "\n") {
		trimmed := strings.TrimSpace(markdownTag.ReplaceAllString(line, " "))
		switch {
		case !fenced && strings.HasPrefix(strings.TrimSpace(line), "```"):
			s.flush()
			fenced, opened = true, i+1
		case fenced:
			fenced = strings.TrimSpace(line) != "```"
		case trimmed == "":
			s.flush()
		case strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "|"):
			s.flush()
			s.write(strings.TrimLeft(trimmed, "#"))
			s.flush()
		case markdownListStart.MatchString(trimmed):
			s.flush()
			s.write(markdownListStart.ReplaceAllString(trimmed, ""))
		default:
			s.write(" " + trimmed)
		}
	}
	if fenced {
		return nil, fmt.Errorf("the fence opened on line %d is not closed", opened)
	}
	s.flush()
	return s.segments, nil
}

// sentenceSpans splits collapsed text after each `.`, `!` or `?` that a
// space follows.
func sentenceSpans(text string) [][2]int {
	var spans [][2]int
	start := 0
	for i := 0; i+1 < len(text); i++ {
		if strings.IndexByte(".!?", text[i]) >= 0 && text[i+1] == ' ' {
			spans = append(spans, [2]int{start, i + 1})
			start = i + 2
		}
	}
	if start < len(text) {
		spans = append(spans, [2]int{start, len(text)})
	}
	return spans
}

// promiseProblems refuses each sentence that promises later work outside a
// data-backlog element, and counts the sentences it read.
func promiseProblems(name string, segments []proseSegment) ([]string, int) {
	var problems []string
	read := 0
	for _, seg := range segments {
		for _, span := range sentenceSpans(seg.text) {
			read++
			sentence := seg.text[span[0]:span[1]]
			if phrase := futurePhrase.FindString(sentence); phrase != "" && !seg.backlog {
				problems = append(problems, fmt.Sprintf("%s: the sentence %q promises future work (%q) outside a data-backlog item; name the task in docs/backlog.md instead", name, sentence, phrase))
			}
		}
	}
	return problems, read
}

// deliveredNames maps each phrase that names a component row labelled
// implemented or experimental, in lower case, to its label: the row's id,
// its name as the page shows it, Markdown code spans unwrapped, and the
// shorter names a reader uses for it.
func deliveredNames(status map[string]componentRow) map[string]string {
	names := map[string]string{}
	for _, row := range status {
		if row.label == "implemented" || row.label == "experimental" {
			names[row.id] = row.label
			for _, name := range shortNames(unwrapCode(row.name)) {
				names[strings.ToLower(name)] = row.label
			}
		}
	}
	return names
}

var (
	// abbreviated is a run of words its abbreviation follows in brackets,
	// such as "Model Context Protocol (MCP)".
	abbreviated = regexp.MustCompile(`(?:[\w-]+ )+\(([A-Z0-9]+)\)`)
	// nameJoint is where a name's head ends and its qualifiers begin.
	nameJoint = regexp.MustCompile(`,| (?:and|of|through|against|per|for|from|to|on|in|over|with) `)
)

// shortNames lists name and the shorter names a sentence may use for it:
// with its abbreviation alone or without it, and its head before a comma
// or a joining word. A name of one word is too common a word to match.
func shortNames(name string) []string {
	names := []string{name}
	if abbreviated.MatchString(name) {
		names = append(names, abbreviated.ReplaceAllString(name, "$1"), strings.ReplaceAll(abbreviated.ReplaceAllStringFunc(name, func(m string) string {
			return m[:strings.LastIndex(m, " (")]
		}), "  ", " "))
	}
	if i := nameJoint.FindStringIndex(name); i != nil {
		names = append(names, name[:i[0]])
	}
	return slices.DeleteFunc(names, func(n string) bool { return len(strings.Fields(n)) < 2 && n != name })
}

// plannedProblems refuses each `planned` code element whose sentence names a
// delivered component row by its id, its name or a shorter name, in any
// case, and counts the elements it read.
func plannedProblems(name string, segments []proseSegment, status map[string]componentRow) ([]string, int) {
	delivered := deliveredNames(status)
	phrases := sortedKeys(delivered)
	var problems []string
	read := 0
	for _, seg := range segments {
		spans := sentenceSpans(seg.text)
		for _, at := range seg.planned {
			read++
			i := slices.IndexFunc(spans, func(sp [2]int) bool { return at >= sp[0] && at < sp[1] })
			if i < 0 {
				problems = append(problems, fmt.Sprintf("%s: a `planned` label at byte %d of %q sits in no sentence", name, at, seg.text))
				continue
			}
			sentence := seg.text[spans[i][0]:spans[i][1]]
			for _, phrase := range phrases {
				if namesRow(strings.ToLower(sentence), phrase) {
					problems = append(problems, fmt.Sprintf("%s: the sentence %q calls %q planned; docs/status.md labels it %s", name, sentence, phrase, delivered[phrase]))
				}
			}
		}
	}
	return problems, read
}

// namesRow reports whether sentence holds phrase whole: the same case, with
// no letter, digit or, for an id, hyphen against either end.
func namesRow(sentence, phrase string) bool {
	word := isWordRune
	if componentID.MatchString(phrase) {
		word = func(r rune) bool { return isWordRune(r) || r == '-' }
	}
	for from := 0; ; {
		i := strings.Index(sentence[from:], phrase)
		if i < 0 {
			return false
		}
		start, end := from+i, from+i+len(phrase)
		before, _ := utf8.DecodeLastRuneInString(sentence[:start])
		after, _ := utf8.DecodeRuneInString(sentence[end:])
		if !word(before) && !word(after) {
			return true
		}
		from = start + 1
	}
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}
