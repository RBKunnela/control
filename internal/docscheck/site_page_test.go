package docscheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/docscheck/sitedoc"
	"github.com/guardana/control/internal/docscheck/sitedoc/mermaid"
)

// linkTargets lists what an element points at: href and src, and every
// url(...) inside any attribute, such as an SVG marker reference.
func linkTargets(n *xnode) []string {
	var targets []string
	for _, name := range sortedKeys(n.attrs) {
		value := n.attrs[name]
		if name == "href" || name == "src" {
			targets = append(targets, value)
		}
		for _, m := range cssURL.FindAllStringSubmatch(value, -1) {
			targets = append(targets, m[1])
		}
	}
	return targets
}

func idsOf(doc *xnode) map[string]bool {
	ids := map[string]bool{}
	doc.walk(func(n *xnode) {
		if id, ok := n.attrs["id"]; ok {
			ids[id] = true
		}
	})
	return ids
}

// linkProblems resolves every local link of the site's pages and
// stylesheets, and every link to a file of this repository on its host,
// against repo. It returns the number of links it resolved; zero is a
// problem, because a check that followed nothing proved nothing.
func linkProblems(site map[string][]byte, repo fs.FS) ([]string, int) {
	var problems []string
	docs := map[string]*xnode{}
	for _, name := range sortedKeys(site) {
		if path.Ext(name) != ".html" {
			continue
		}
		doc, err := parseXHTML(site[name])
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		docs[name] = doc
	}
	resolved := 0
	check := func(from, target string) {
		if problem, counted := resolveLink(site, docs, repo, from, target); counted {
			resolved++
			if problem != "" {
				problems = append(problems, fmt.Sprintf("%s: %s", from, problem))
			}
		}
	}
	for _, name := range sortedKeys(docs) {
		docs[name].walk(func(n *xnode) {
			for _, target := range linkTargets(n) {
				check(name, target)
			}
		})
	}
	for _, name := range sortedKeys(site) {
		if path.Ext(name) == ".css" {
			for _, m := range cssURL.FindAllStringSubmatch(string(site[name]), -1) {
				check(name, m[1])
			}
		}
	}
	if resolved == 0 {
		problems = append(problems, "no local link was resolved")
	}
	return problems, resolved
}

// resolveLink judges one target and says whether it was one to judge: a
// link to another host is not.
func resolveLink(site map[string][]byte, docs map[string]*xnode, repo fs.FS, from, target string) (string, bool) {
	if problem, ok := repoLinkProblem(repo, target); ok {
		return problem, true
	}
	if isRemote(target) {
		return "", false
	}
	dest, fragment, _ := strings.Cut(target, "#")
	if dest == "" && fragment == "" {
		return "an empty link", true
	}
	file, ok := served(site, sitePath(from, dest))
	if !ok {
		return fmt.Sprintf("%s resolves to %s, which the site does not hold", target, file), true
	}
	if fragment != "" {
		doc, ok := docs[file]
		if !ok || !idsOf(doc)[fragment] {
			return fmt.Sprintf("%s: %s holds no id %q", target, file, fragment), true
		}
	}
	return "", true
}

// repoLinkProblem judges a link to a file or directory of this repository
// on its host, and says whether target was one.
func repoLinkProblem(repo fs.FS, target string) (string, bool) {
	for _, kind := range []string{"blob", "tree"} {
		rest, ok := strings.CutPrefix(target, "https://"+brand.ModulePath+"/"+kind+"/main/")
		if !ok {
			continue
		}
		rel, fragment, _ := strings.Cut(rest, "#")
		info, err := fs.Stat(repo, rel)
		switch {
		case err != nil:
			return fmt.Sprintf("%s names %q, which is not in the repository", target, rel), true
		case info.IsDir() != (kind == "tree"):
			return fmt.Sprintf("%s: a %s link to a %s", target, kind, map[bool]string{true: "directory", false: "file"}[info.IsDir()]), true
		case fragment != "" && path.Ext(rel) != ".md":
			return fmt.Sprintf("%s: a fragment into %s, whose anchors cannot be checked", target, rel), true
		case fragment != "":
			anchors, err := newAnchorIndex(repo).anchors(rel)
			if err != nil {
				return fmt.Sprintf("%s: %v", target, err), true
			}
			if !anchors[fragment] {
				return fmt.Sprintf("%s: %s has no heading #%s", target, rel, fragment), true
			}
		}
		return "", true
	}
	return "", false
}

// sitePath resolves a link's path part against the file it appears in; a
// directory stands for its index.html.
func sitePath(from, dest string) string {
	file := from
	switch {
	case dest == "":
	case strings.HasPrefix(dest, "/"):
		file = strings.TrimPrefix(dest, "/")
	default:
		file = path.Join(path.Dir(from), dest)
	}
	if file == "" || strings.HasSuffix(file, "/") {
		file += "index.html"
	}
	return path.Clean(file)
}

// served is the file the host answers a path with: the file itself, or, for
// a path with no extension, the page of that name or the directory's
// index.html, as `auto-trailing-slash` serves them.
func served(site map[string][]byte, file string) (string, bool) {
	if _, ok := site[file]; ok {
		return file, true
	}
	if path.Ext(file) != "" {
		return file, false
	}
	for _, candidate := range []string{file + ".html", file + "/index.html"} {
		if _, ok := site[candidate]; ok {
			return candidate, true
		}
	}
	return file, false
}

// idProblems refuses an empty or repeated id: a fragment or a drawing's
// reference to it would reach the wrong element.
func idProblems(doc *xnode) []string {
	var problems []string
	seen := map[string]bool{}
	doc.walk(func(n *xnode) {
		id, ok := n.attrs["id"]
		switch {
		case !ok:
		case id == "":
			problems = append(problems, fmt.Sprintf("a <%s> has an empty id", n.name))
		case seen[id]:
			problems = append(problems, fmt.Sprintf("the id %q is used twice", id))
		default:
			seen[id] = true
		}
	})
	return problems
}

var figureID = regexp.MustCompile(`^dg[0-9a-f]{6}([1-9][0-9]*)$`)

// figureIndexes lists the index each drawn figure carries in its id, in
// page order.
func figureIndexes(doc *xnode) ([]int, []string) {
	var indexes []int
	var problems []string
	doc.walk(func(n *xnode) {
		if n.name != "figure" || !n.hasClass("dg") {
			return
		}
		m := figureID.FindStringSubmatch(n.attrs["id"])
		if m == nil {
			problems = append(problems, fmt.Sprintf("figure id %q does not carry an index", n.attrs["id"]))
			return
		}
		i, err := strconv.Atoi(m[1])
		if err != nil {
			problems = append(problems, err.Error())
			return
		}
		indexes = append(indexes, i)
	})
	return indexes, problems
}

var backlogID = regexp.MustCompile(`^B[0-9]{2}$`)

// backlogTitles maps each task identifier of docs/backlog.md's tables to
// its Work cell.
func backlogTitles(lines []string) map[string]string {
	titles := map[string]string{}
	for _, line := range lines {
		if s := strings.TrimSpace(line); strings.HasPrefix(s, "|") {
			if cells := tableCells(s); len(cells) >= 2 && backlogID.MatchString(cells[0]) {
				titles[cells[0]] = cells[1]
			}
		}
	}
	return titles
}

var labelWord = regexp.MustCompile(`(?i)\b(?:implemented|experimental|planned)\b`)

// tagProblems holds the page's labels and planned items to their sources.
// Each data-status element holds a component row's id, carries the row's
// name as its title and shows the row's own label in one `st` element,
// itself or below it. Each data-backlog element names a task, carries the
// task's Work cell as its title and shows its id in one `id` element. A
// label word anywhere in the page's text is refused unless it is a `st`
// element's inside a data-status element, or the word planned inside a
// data-backlog element; a `st` element outside a data-status element is
// refused too. The data-status elements number at least minStatus and the
// distinct tasks at least minBacklog.
func tagProblems(doc *xnode, status map[string]componentRow, backlog map[string]string, minStatus, minBacklog int) []string {
	tally := &tagTally{status: status, backlog: backlog, tasks: map[string]bool{}}
	tally.visit(doc, tagContext{})
	problems := tally.problems
	if tally.statusItems < minStatus {
		problems = append(problems, fmt.Sprintf("%d status labels, want at least %d", tally.statusItems, minStatus))
	}
	if len(tally.tasks) < minBacklog {
		problems = append(problems, fmt.Sprintf("%d distinct backlog tasks, want at least %d", len(tally.tasks), minBacklog))
	}
	return problems
}

// tagTally walks a page for tagProblems, counting items as it goes.
type tagTally struct {
	status      map[string]componentRow
	backlog     map[string]string
	statusItems int
	tasks       map[string]bool
	problems    []string
}

// tagContext is what encloses a node: a data-status element, a data-backlog
// element, a `st` element.
type tagContext struct{ status, backlog, st bool }

func (c *tagTally) add(problem string) {
	if problem != "" {
		c.problems = append(c.problems, problem)
	}
}

func (c *tagTally) visit(n *xnode, in tagContext) {
	statusID, isStatus := n.attrs["data-status"]
	id, isBacklog := n.attrs["data-backlog"]
	if isStatus {
		c.statusItems++
		c.add(statusItemProblem(n, statusID, c.status))
	}
	if isBacklog {
		c.tasks[id] = true
		c.add(backlogItemProblem(n, id, c.backlog))
	}
	if n.hasClass("st") && !in.status && !isStatus {
		c.add(fmt.Sprintf("a status label %q outside a data-status item", n.text()))
	}
	in = tagContext{in.status || isStatus, in.backlog || isBacklog, in.st || n.hasClass("st")}
	for _, p := range n.parts {
		if p.node != nil {
			c.visit(p.node, in)
			continue
		}
		for _, word := range labelWord.FindAllString(p.text, -1) {
			c.add(labelWordProblem(n, word, in))
		}
	}
}

// labelWordProblem refuses a label word in a text the page does not tie to
// a row or a task.
func labelWordProblem(n *xnode, word string, in tagContext) string {
	switch {
	case n.name == "style":
		return ""
	case in.st && in.status:
		return ""
	case strings.EqualFold(word, "planned") && in.backlog && !in.st:
		return ""
	}
	return fmt.Sprintf("the word %q in %q is tied to no row or task; show a label as `st` inside a data-status item, or planned inside a data-backlog item", word, n.text())
}

// texts lists the text of n and of every element below it that carries class.
func (n *xnode) texts(class string) []string {
	var found []string
	n.walk(func(e *xnode) {
		if e.hasClass(class) {
			found = append(found, e.text())
		}
	})
	return found
}

func statusItemProblem(n *xnode, id string, status map[string]componentRow) string {
	row, known := status[id]
	switch {
	case id == "":
		return "an empty data-status"
	case !componentID.MatchString(id):
		return fmt.Sprintf("data-status %q is not a component id", id)
	case !known:
		return fmt.Sprintf("data-status %q names no row of the component table", id)
	case n.attrs["title"] != unwrapCode(row.name):
		return fmt.Sprintf("data-status %q carries the title %q, want the row's name %q", id, n.attrs["title"], unwrapCode(row.name))
	}
	if shown := n.texts("st"); len(shown) != 1 || shown[0] != row.label {
		return fmt.Sprintf("data-status %q shows %q, want the row's label %q", id, shown, row.label)
	}
	return ""
}

func backlogItemProblem(n *xnode, id string, backlog map[string]string) string {
	work, known := backlog[id]
	switch {
	case id == "":
		return "an empty data-backlog"
	case !known:
		return fmt.Sprintf("data-backlog %q names no task of the backlog", id)
	case n.attrs["title"] != unwrapCode(work):
		return fmt.Sprintf("data-backlog %q carries the title %q, want the task's Work cell %q", id, n.attrs["title"], unwrapCode(work))
	}
	if shown := n.texts("id"); len(shown) != 1 || shown[0] != id {
		return fmt.Sprintf("data-backlog %q shows the ids %q, want %q once", id, shown, id)
	}
	return ""
}

// unwrapCode drops the backticks of Markdown code spans, as a title shows
// the text.
func unwrapCode(s string) string { return strings.ReplaceAll(s, "`", "") }

var (
	plannedWord = regexp.MustCompile(`(?i)\bplanned\b`)
	taskID      = regexp.MustCompile(`\bB[0-9]{2}\b`)
)

// plannedOutsideBacklog refuses each sentence that calls something planned or
// promises later work and is tied to no task, and counts the sentences that
// do either. On the page a data-backlog element ties a sentence; in README,
// read with tasks, the sentence names its task's id, and every id it names
// is a task of the backlog.
func plannedOutsideBacklog(name string, segments []proseSegment, tasks map[string]string) ([]string, int) {
	var problems []string
	read := 0
	for _, seg := range segments {
		for _, span := range sentenceSpans(seg.text) {
			sentence := seg.text[span[0]:span[1]]
			if !plannedWord.MatchString(sentence) && !futurePhrase.MatchString(sentence) {
				continue
			}
			read++
			if !seg.backlog && !namesTasks(sentence, tasks) {
				problems = append(problems, fmt.Sprintf("%s: the sentence %q calls something planned or promises later work outside a data-backlog item; name its task in docs/backlog.md", name, sentence))
			}
		}
	}
	return problems, read
}

// namesTasks reports whether sentence names at least one task id, each a
// task of tasks.
func namesTasks(sentence string, tasks map[string]string) bool {
	ids := taskID.FindAllString(sentence, -1)
	for _, id := range ids {
		if _, ok := tasks[id]; !ok {
			return false
		}
	}
	return len(ids) > 0
}

var boldLine = regexp.MustCompile(`^\*\*(.+)\*\*$`)

// readmeTagline is the README's first line set wholly in bold.
func readmeTagline(lines []string) (string, error) {
	for _, line := range lines {
		if m := boldLine.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			return m[1], nil
		}
	}
	return "", errors.New("the README holds no bold tagline line")
}

// taglineProblem holds the one `tagline` element of a page to want.
func taglineProblem(doc *xnode, want string) string {
	var found []string
	doc.walk(func(n *xnode) {
		if n.hasClass("tagline") {
			found = append(found, n.text())
		}
	})
	switch {
	case len(found) != 1:
		return fmt.Sprintf("%d tagline elements, want 1", len(found))
	case found[0] != want:
		return fmt.Sprintf("the tagline reads %q, want the README's %q", found[0], want)
	}
	return ""
}

// wranglerConfig is the whole deploy configuration, key for key.
func wranglerConfig() map[string]any {
	return map[string]any{
		"name":               brand.Slug,
		"compatibility_date": "2026-09-28",
		"assets": map[string]any{
			"directory":     "./site",
			"html_handling": "auto-trailing-slash",
		},
		"routes": []any{map[string]any{
			"pattern":       strings.TrimSuffix(strings.TrimPrefix(siteOrigin, "https://"), "/"),
			"custom_domain": true,
		}},
		"workers_dev":  false,
		"preview_urls": false,
	}
}

// wranglerProblems decodes the deploy file as strict JSON: no comment, no
// repeated key, nothing after the value, and exactly the pinned keys.
func wranglerProblems(data []byte) []string {
	d := json.NewDecoder(bytes.NewReader(data))
	if err := duplicateKeys(d, "$"); err != nil {
		return []string{err.Error()}
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return []string{"something follows the configuration's value"}
	}
	var got any
	if err := json.Unmarshal(data, &got); err != nil {
		return []string{err.Error()}
	}
	gotMap, ok := got.(map[string]any)
	if !ok {
		return []string{"the configuration is not an object"}
	}
	want := wranglerConfig()
	var problems []string
	keys := append(sortedKeys(gotMap), sortedKeys(want)...)
	seen := map[string]bool{}
	for _, key := range keys {
		if seen[key] {
			continue
		}
		seen[key] = true
		if !reflect.DeepEqual(gotMap[key], want[key]) {
			problems = append(problems, fmt.Sprintf("%s is %v, want %v", key, gotMap[key], want[key]))
		}
	}
	return problems
}

// duplicateKeys reads one JSON value and refuses an object that names a key
// twice, which encoding/json would silently resolve to the last.
func duplicateKeys(d *json.Decoder, at string) error {
	tok, err := d.Token()
	if err != nil {
		return fmt.Errorf("%s: %w", at, err)
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
			name, _ := key.(string)
			if seen[name] {
				return fmt.Errorf("%s: the key %q appears twice", at, name)
			}
			seen[name] = true
			if err := duplicateKeys(d, at+"."+name); err != nil {
				return err
			}
		}
		_, err = d.Token()
	case json.Delim('['):
		for i := 0; d.More(); i++ {
			if err := duplicateKeys(d, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
		_, err = d.Token()
	}
	if err != nil {
		return fmt.Errorf("%s: %w", at, err)
	}
	return nil
}

// slotTitleProblems holds each slot of the page to the accessible title of
// the block it draws, so a block inserted in the README cannot put another
// diagram under a slot's unchanged number.
func slotTitleProblems(page, readme []byte, want []string) []string {
	slots, err := sitedoc.Slots(page)
	if err != nil {
		return []string{err.Error()}
	}
	blocks, err := sitedoc.Blocks(readme)
	if err != nil {
		return []string{err.Error()}
	}
	if len(slots) != len(want) {
		return []string{fmt.Sprintf("%d slots, want %d", len(slots), len(want))}
	}
	var problems []string
	for i, slot := range slots {
		if slot.Block > len(blocks) {
			problems = append(problems, fmt.Sprintf("slot %d asks for block %d; the README holds %d", i+1, slot.Block, len(blocks)))
			continue
		}
		g, err := mermaid.Parse(blocks[slot.Block-1])
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("slot %d: %v", i+1, err))
		case g.Title != want[i]:
			problems = append(problems, fmt.Sprintf("slot %d draws %q, want %q", i+1, g.Title, want[i]))
		}
	}
	return problems
}
