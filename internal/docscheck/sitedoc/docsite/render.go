package docsite

import (
	"bytes"
	"errors"
	"fmt"
	stdhtml "html"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"

	"github.com/guardana/control/internal/docscheck/anchor"
	"github.com/guardana/control/internal/docscheck/sitedoc"
	"github.com/guardana/control/internal/docscheck/sitedoc/mermaid"
)

// scheme matches a link that names its own scheme, such as https: or mailto:.
var scheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// schemes are the ones a page may link to; any other, javascript: or data:
// among them, is refused rather than left for the renderer to blank.
var schemes = []string{"http:", "https:", "mailto:"}

func allowedScheme(target string) bool {
	lower := strings.ToLower(target)
	for _, s := range schemes {
		if strings.HasPrefix(lower, s) {
			return true
		}
	}
	return false
}

// renderBody renders one page's Markdown. Every refusal names the line.
func renderBody(p *page, pages map[string]*page, fsys fs.FS) ([]byte, error) {
	if err := xmlText(p); err != nil {
		return nil, err
	}
	rw := &rewriter{page: p, pages: pages, fsys: fsys, source: p.body}
	md := goldmark.New(
		goldmark.WithExtensions(extension.Table, extension.Strikethrough, extension.Linkify),
		goldmark.WithParserOptions(parser.WithASTTransformers(util.Prioritized(rw, 100))),
		goldmark.WithRendererOptions(html.WithXHTML(),
			renderer.WithNodeRenderers(util.Prioritized(&blocks{page: p}, 100))),
	)
	var out bytes.Buffer
	if err := md.Convert(p.body, &out); err != nil {
		return nil, err
	}
	if err := errors.Join(rw.errs...); err != nil {
		return nil, err
	}
	// A character reference becomes its character only here, so the source
	// check above cannot see one XHTML forbids.
	for _, r := range out.String() {
		if forbidden(r) {
			return nil, fmt.Errorf("a character reference renders %U, which XHTML cannot carry", r)
		}
	}
	return out.Bytes(), nil
}

// xmlText refuses a page the XHTML it becomes could not carry: bytes that are
// not UTF-8, or a character XML 1.0 forbids.
func xmlText(p *page) error {
	if !utf8.Valid(p.body) {
		return errors.New("the page is not valid UTF-8")
	}
	line := p.bodyLine
	for _, r := range string(p.body) {
		switch {
		case r == '\n':
			line++
		case forbidden(r):
			return fmt.Errorf("line %d: the character %U, which XHTML cannot carry", line, r)
		}
	}
	return nil
}

// forbidden reports whether XML 1.0 refuses r in a document.
func forbidden(r rune) bool {
	return r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0xFFFE || r == 0xFFFF
}

// rewriter gives each heading the anchor GitHub gives it, points each link at
// what it names on the site or on the repository's host, and refuses what
// the site cannot carry: raw HTML, which the page would serve unchecked, and
// images, which the pages do not use.
type rewriter struct {
	page   *page
	pages  map[string]*page
	fsys   fs.FS
	source []byte
	errs   []error
	// numbering and comments hold one walk's headings and the comments it
	// drops once it is done.
	numbering anchor.Numbering
	comments  []ast.Node
}

func (r *rewriter) Transform(doc *ast.Document, _ text.Reader, _ parser.Context) {
	r.numbering = anchor.Numbering{}
	err := ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		return r.visit(n), nil
	})
	if err != nil {
		r.errs = append(r.errs, err)
	}
	for _, c := range r.comments {
		c.Parent().RemoveChild(c.Parent(), c)
	}
}

// visit rewrites or refuses one node on the way down.
func (r *rewriter) visit(n ast.Node) ast.WalkStatus {
	switch n := n.(type) {
	case *ast.Heading:
		n.SetAttributeString("id", []byte(r.numbering.Next(string(n.Lines().Value(r.source)))))
	case *ast.Link:
		dest, err := r.link(string(n.Destination))
		if err != nil {
			r.fail(n, err)
			return ast.WalkContinue
		}
		n.Destination = []byte(dest)
	case *ast.AutoLink:
		url := string(n.URL(r.source))
		if n.AutoLinkType == ast.AutoLinkURL && !allowedScheme(url) && !strings.HasPrefix(url, "www.") {
			r.fail(n, fmt.Errorf("link %q: only http, https and mailto links are served", url))
		}
	case *ast.Image:
		r.fail(n, errors.New("an image; the pages carry none"))
	case *ast.HTMLBlock:
		return r.html(n, n.HTMLBlockType == ast.HTMLBlockType2 && r.oneComment(n))
	case *ast.RawHTML:
		return r.html(n, r.isComment(n))
	}
	return ast.WalkContinue
}

// html keeps a comment to be dropped after the walk and refuses any other
// raw HTML.
func (r *rewriter) html(n ast.Node, comment bool) ast.WalkStatus {
	if comment {
		r.comments = append(r.comments, n)
		return ast.WalkSkipChildren
	}
	r.fail(n, errors.New("raw HTML, which the site would serve unchecked"))
	return ast.WalkContinue
}

// oneComment reports whether an HTML block is one comment and nothing else, so
// dropping it drops no text written after the comment on its closing line.
func (r *rewriter) oneComment(n *ast.HTMLBlock) bool {
	var b bytes.Buffer
	for i := range n.Lines().Len() {
		line := n.Lines().At(i)
		b.Write(line.Value(r.source))
	}
	if n.HasClosure() {
		b.Write(n.ClosureLine.Value(r.source))
	}
	text := strings.TrimSpace(b.String())
	return strings.HasPrefix(text, "<!--") && strings.Index(text, "-->") == len(text)-len("-->")
}

// isComment reports whether inline HTML is a comment, which renders as
// nothing.
func (r *rewriter) isComment(n *ast.RawHTML) bool {
	if n.Segments.Len() == 0 {
		return false
	}
	first := n.Segments.At(0)
	return bytes.HasPrefix(first.Value(r.source), []byte("<!--"))
}

func (r *rewriter) fail(n ast.Node, err error) {
	r.errs = append(r.errs, fmt.Errorf("line %d: %w", r.line(n), err))
}

// line is the 1-based line where n's text starts, or its parent's when n
// holds none of its own.
func (r *rewriter) line(n ast.Node) int {
	for ; n != nil; n = n.Parent() {
		start := -1
		switch v := n.(type) {
		case *ast.RawHTML:
			if v.Segments.Len() > 0 {
				start = v.Segments.At(0).Start
			}
		case *ast.Text:
			start = v.Segment.Start
		default:
			if n.Type() == ast.TypeBlock && n.Lines().Len() > 0 {
				start = n.Lines().At(0).Start
			} else if c := n.FirstChild(); c != nil {
				if t, ok := c.(*ast.Text); ok {
					start = t.Segment.Start
				}
			}
		}
		if start >= 0 {
			return r.page.bodyLine + bytes.Count(r.source[:start], []byte("\n"))
		}
	}
	return 0
}

// link is where target, a link written in the page, points on the site: a
// rendered page at its address, anything else the repository holds on its
// host. A target that is neither is refused.
func (r *rewriter) link(target string) (string, error) {
	if target == "" {
		return "", errors.New("an empty link")
	}
	if scheme.MatchString(target) {
		if !allowedScheme(target) {
			return "", fmt.Errorf("link %q: only http, https and mailto links are served", target)
		}
		return target, nil
	}
	if strings.HasPrefix(target, "#") {
		return target, nil
	}
	dest, fragment, hasFragment := strings.Cut(target, "#")
	if hasFragment {
		fragment = "#" + fragment
	}
	unescaped, err := url.PathUnescape(dest)
	if err != nil {
		return "", fmt.Errorf("link %q: %w", target, err)
	}
	dir := path.Dir(r.page.src)
	if strings.HasPrefix(unescaped, "/") {
		dir = "."
	}
	rel := path.Clean(path.Join(dir, unescaped))
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("link %q escapes the repository", target)
	}
	if p, ok := r.pages[rel]; ok {
		return p.url + fragment, nil
	}
	info, err := fs.Stat(r.fsys, rel)
	if err != nil {
		return "", fmt.Errorf("link %q names %s, which the repository does not hold", target, rel)
	}
	return sourceURL(rel, info.IsDir()) + fragment, nil
}

// blocks renders fenced code: a Mermaid block as a figure, anything else as
// preformatted text; and each table inside a box of its own.
type blocks struct {
	page    *page
	figures int
}

func (b *blocks) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindFencedCodeBlock, b.fenced)
	extension.NewTableHTMLRenderer(extension.WithTableHTMLOptions(html.WithXHTML())).RegisterFuncs(boxedTables{reg})
}

// boxedTables passes the table renderer's functions on, and puts each table
// in a `tbl` box: the box scrolls a wide table, so the page never does.
type boxedTables struct {
	reg renderer.NodeRendererFuncRegisterer
}

func (b boxedTables) Register(kind ast.NodeKind, f renderer.NodeRendererFunc) {
	if kind != east.KindTable {
		b.reg.Register(kind, f)
		return
	}
	b.reg.Register(kind, func(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
		if entering {
			if _, err := w.WriteString("<div class=\"tbl\">\n"); err != nil {
				return ast.WalkStop, err
			}
		}
		status, err := f(w, source, n, entering)
		if err != nil || entering {
			return status, err
		}
		if _, err := w.WriteString("</div>\n"); err != nil {
			return ast.WalkStop, err
		}
		return status, nil
	})
}

func (b *blocks) fenced(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkSkipChildren, nil
	}
	n, _ := node.(*ast.FencedCodeBlock)
	var body strings.Builder
	for i := range n.Lines().Len() {
		line := n.Lines().At(i)
		body.Write(line.Value(source))
	}
	language := string(n.Language(source))
	if language == "mermaid" {
		b.figures++
		figure, err := diagram(body.String(), b.figures, sourceURL(b.page.src, false))
		if err != nil {
			line := b.page.bodyLine + bytes.Count(source[:n.Info.Segment.Start], []byte("\n"))
			return ast.WalkStop, fmt.Errorf("line %d: diagram: %w", line, err)
		}
		_, _ = w.WriteString(figure + "\n")
		return ast.WalkSkipChildren, nil
	}
	_, _ = w.WriteString("<pre><code")
	if language != "" {
		_, _ = w.WriteString(` class="language-` + stdhtml.EscapeString(language) + `"`)
	}
	_, _ = w.WriteString(">" + stdhtml.EscapeString(body.String()) + "</code></pre>\n")
	return ast.WalkSkipChildren, nil
}

// diagram draws a flowchart the drawer's subset holds, as the landing page
// draws the README's. Any other diagram is shown as its text alternative with
// its source beside it and a link to the page on the repository's host, which
// draws it; never dropped, so its accTitle and accDescr are required.
func diagram(source string, index int, drawn string) (string, error) {
	title, description, err := textAlternative(source)
	if err != nil {
		return "", err
	}
	if g, err := mermaid.Parse(source); err == nil && len(g.Nodes) <= sitedoc.MaxNodes {
		if figure, err := mermaid.Figure(source, index); err == nil {
			return figure, nil
		}
	}
	id := "diagram-" + strconv.Itoa(index)
	return `<figure class="dg-text" id="` + id + `"><figcaption>` + stdhtml.EscapeString(title) +
		`</figcaption><p>` + stdhtml.EscapeString(description) + ` <a href="` + stdhtml.EscapeString(drawn) + `">Drawn on GitHub</a>.</p>` +
		`<details><summary>The diagram's source</summary><pre><code class="language-mermaid">` +
		stdhtml.EscapeString(source) + `</code></pre></details></figure>`, nil
}

// textAlternative reads a block's one-line accTitle and accDescr.
func textAlternative(source string) (title, description string, err error) {
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "accTitle:"); ok {
			title = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "accDescr:"); ok {
			description = strings.TrimSpace(v)
		}
	}
	if title == "" || description == "" {
		return "", "", errors.New("a Mermaid block needs a one-line accTitle and accDescr, its text alternative")
	}
	return title, description, nil
}
