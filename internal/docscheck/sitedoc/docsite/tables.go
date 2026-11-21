package docsite

import (
	"bytes"
	"strings"

	"github.com/yuin/goldmark/ast"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/util"
)

// A table is stacked when its cells are sentences: when at least
// stackColumns of its columns hold a body cell of stackWords words or more.
// Any other table is compact and stays a table.
const (
	stackWords   = 15
	stackColumns = 2
)

// boxedTables passes the table renderer's functions on. A compact table sits
// in a `tbl` box, which scrolls a wide table so the page never does. A stacked
// table becomes a list, one item per row: its first cell the item's title,
// every other cell a definition under its column's header.
type boxedTables struct {
	reg renderer.NodeRendererFuncRegisterer
	// stacked holds the decision for each table, made once on entering it.
	stacked map[ast.Node]bool
}

func newBoxedTables(reg renderer.NodeRendererFuncRegisterer) boxedTables {
	return boxedTables{reg: reg, stacked: map[ast.Node]bool{}}
}

func (b boxedTables) Register(kind ast.NodeKind, f renderer.NodeRendererFunc) {
	switch kind {
	case east.KindTable:
		b.reg.Register(kind, b.table(f))
	case east.KindTableHeader:
		b.reg.Register(kind, b.unlessStacked(f, skip))
	case east.KindTableRow:
		b.reg.Register(kind, b.unlessStacked(f, stackedRow))
	case east.KindTableCell:
		b.reg.Register(kind, b.unlessStacked(f, stackedCell))
	default:
		b.reg.Register(kind, f)
	}
}

func (b boxedTables) table(f renderer.NodeRendererFunc) renderer.NodeRendererFunc {
	return func(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
		if entering {
			b.stacked[n] = stacked(n, source)
		}
		if b.stacked[n] {
			return write(w, ast.WalkContinue, either(entering, "<ul class=\"stack\">\n", "</ul>\n"))
		}
		if entering {
			if _, err := w.WriteString("<div class=\"tbl\">\n"); err != nil {
				return ast.WalkStop, err
			}
		}
		status, err := f(w, source, n, entering)
		if err != nil || entering {
			return status, err
		}
		return write(w, status, "</div>\n")
	}
}

// unlessStacked renders a part of a stacked table with own, and of a compact
// one with the table renderer's f.
func (b boxedTables) unlessStacked(f, own renderer.NodeRendererFunc) renderer.NodeRendererFunc {
	return func(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
		table := n.Parent()
		if n.Kind() == east.KindTableCell {
			table = table.Parent()
		}
		if b.stacked[table] {
			return own(w, source, n, entering)
		}
		return f(w, source, n, entering)
	}
}

// skip leaves out a stacked table's header row; its cells become the labels.
func skip(util.BufWriter, []byte, ast.Node, bool) (ast.WalkStatus, error) {
	return ast.WalkSkipChildren, nil
}

func stackedRow(w util.BufWriter, _ []byte, _ ast.Node, entering bool) (ast.WalkStatus, error) {
	return write(w, ast.WalkContinue, either(entering, "<li>", "</dl></li>\n"))
}

func stackedCell(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	column := 0
	for c := n.PreviousSibling(); c != nil; c = c.PreviousSibling() {
		column++
	}
	if column == 0 {
		return write(w, ast.WalkContinue, either(entering, `<p class="rt">`, "</p><dl>"))
	}
	if !entering {
		return write(w, ast.WalkContinue, "</dd>")
	}
	if _, err := w.WriteString("<dt>"); err != nil {
		return ast.WalkStop, err
	}
	if header := headerCell(n.Parent().Parent(), column); header != nil {
		plain(source, header, func(value []byte, code bool) {
			if code {
				html.DefaultWriter.RawWrite(w, value)
			} else {
				html.DefaultWriter.Write(w, value)
			}
		})
	}
	return write(w, ast.WalkContinue, "</dt><dd>")
}

// headerCell is the table's header cell in the given column, or nil.
func headerCell(table ast.Node, column int) ast.Node {
	for part := table.FirstChild(); part != nil; part = part.NextSibling() {
		if part.Kind() != east.KindTableHeader {
			continue
		}
		cell := part.FirstChild()
		for range column {
			if cell == nil {
				return nil
			}
			cell = cell.NextSibling()
		}
		return cell
	}
	return nil
}

// stacked reports whether a table's cells are sentences, read from the
// words of its body cells.
func stacked(table ast.Node, source []byte) bool {
	long := map[int]bool{}
	for part := table.FirstChild(); part != nil; part = part.NextSibling() {
		if part.Kind() == east.KindTableHeader {
			continue
		}
		column := 0
		for cell := part.FirstChild(); cell != nil; cell = cell.NextSibling() {
			var text bytes.Buffer
			plain(source, cell, func(value []byte, _ bool) { text.Write(value) })
			if len(strings.Fields(text.String())) >= stackWords {
				long[column] = true
			}
			column++
		}
	}
	return len(long) >= stackColumns
}

// plain hands emit the text of n and everything inside it, with no markup:
// each run of text as its source spells it, and whether it is code, which
// the renderer writes without resolving references.
func plain(source []byte, n ast.Node, emit func(value []byte, code bool)) {
	_ = ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch c := c.(type) {
		case *ast.CodeSpan:
			for t := c.FirstChild(); t != nil; t = t.NextSibling() {
				if t, ok := t.(*ast.Text); ok {
					emit(t.Segment.Value(source), true)
				}
			}
			return ast.WalkSkipChildren, nil
		case *ast.Text:
			emit(c.Segment.Value(source), c.IsRaw())
		case *ast.String:
			emit(c.Value, c.IsRaw())
		case *ast.AutoLink:
			emit(c.Label(source), false)
		}
		return ast.WalkContinue, nil
	})
}

// codeSpan renders inline code as the HTML renderer does, and inside a table
// cell lets it break after each slash, so a path wraps at its separators
// rather than widening its column.
func codeSpan(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return write(w, ast.WalkContinue, "</code>")
	}
	if _, err := w.WriteString("<code>"); err != nil {
		return ast.WalkStop, err
	}
	inCell := false
	for p := n.Parent(); p != nil && !inCell; p = p.Parent() {
		inCell = p.Kind() == east.KindTableCell
	}
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		t, ok := c.(*ast.Text)
		if !ok {
			continue
		}
		value := t.Segment.Value(source)
		if v, cut := bytes.CutSuffix(value, []byte("\n")); cut {
			value = append(v[:len(v):len(v)], ' ')
		}
		if !inCell {
			html.DefaultWriter.RawWrite(w, value)
			continue
		}
		parts := bytes.Split(value, []byte("/"))
		for i, part := range parts {
			if i > 0 {
				_ = w.WriteByte('/')
				if len(part) > 0 {
					_, _ = w.WriteString("<wbr/>")
				}
			}
			html.DefaultWriter.RawWrite(w, part)
		}
	}
	return ast.WalkSkipChildren, nil
}

// either is in on entering a node and out on leaving it.
func either(entering bool, in, out string) string {
	if entering {
		return in
	}
	return out
}

// write writes s and returns status, or stops the render when it cannot.
func write(w util.BufWriter, status ast.WalkStatus, s string) (ast.WalkStatus, error) {
	if _, err := w.WriteString(s); err != nil {
		return ast.WalkStop, err
	}
	return status, nil
}
