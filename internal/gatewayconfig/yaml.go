package gatewayconfig

import (
	"fmt"
	"strings"
)

// The configuration file is a small, strict subset of YAML, read here rather
// than by a library: nested mappings, sequences of scalars and of mappings,
// plain and double-quoted scalars, full-line and trailing comments. Anchors,
// aliases, tags, flow collections, multi-line scalars and tab indentation are
// refused with the line that holds them, because a file this program half
// understands is a configuration nobody has read.

// entry is one scalar the file sets: the dotted path a sequence's indexes are
// part of, the value, and the line it came from.
type entry struct {
	path  string
	value string
	line  int
}

// parseYAML flattens the document into one entry per scalar. A mapping
// contributes its key to the path; a sequence contributes the index of each
// item, so upstreams[0].name is "upstreams.0.name" and an origin is
// "listener.origins.0".
func parseYAML(text string) ([]entry, error) {
	lines, err := split(text)
	if err != nil {
		return nil, err
	}
	p := &parser{lines: lines}
	out, err := p.mapping(0, "")
	if err != nil {
		return nil, err
	}
	if p.at < len(p.lines) {
		return nil, p.errorf(p.at, "expected a key at indentation %d", 0)
	}
	return out, nil
}

type parser struct {
	lines []line
	at    int
}

// line is one significant line: its indentation, its content without the
// comment, and its number in the file.
type line struct {
	indent  int
	content string
	number  int
}

// split drops blank lines and comments and refuses a tab in the indentation,
// which YAML forbids and which no reader can see.
func split(text string) ([]line, error) {
	var out []line
	for i, raw := range strings.Split(text, "\n") {
		content := strings.TrimRight(stripComment(raw), " \t")
		trimmed := strings.TrimLeft(content, " ")
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "\t") {
			return nil, fmt.Errorf("line %d: the indentation holds a tab; this reader takes spaces, as YAML does", i+1)
		}
		out = append(out, line{indent: len(content) - len(trimmed), content: trimmed, number: i + 1})
	}
	return out, nil
}

// stripComment cuts a comment: a '#' that starts the line or follows a space,
// and is outside a double-quoted scalar, in which a backslash escapes the
// next byte.
func stripComment(raw string) string {
	quoted := false
	for i := 0; i < len(raw); i++ {
		switch {
		case quoted && raw[i] == '\\':
			i++
		case raw[i] == '"':
			quoted = !quoted
		case quoted:
		case raw[i] == '\\' && i+1 < len(raw):
			i++
		case raw[i] == '#' && (i == 0 || raw[i-1] == ' ' || raw[i-1] == '\t'):
			return raw[:i]
		}
	}
	return raw
}

func (p *parser) errorf(at int, format string, args ...any) error {
	number := 0
	if at < len(p.lines) {
		number = p.lines[at].number
	} else if len(p.lines) > 0 {
		number = p.lines[len(p.lines)-1].number
	}
	return fmt.Errorf("line %d: %s", number, fmt.Sprintf(format, args...))
}

// mapping reads the keys at indent under prefix, and everything nested under
// them.
func (p *parser) mapping(indent int, prefix string) ([]entry, error) {
	var out []entry
	for p.at < len(p.lines) {
		cur := p.lines[p.at]
		if cur.indent < indent {
			return out, nil
		}
		if cur.indent > indent {
			return nil, p.errorf(p.at, "indented under a key that takes a value")
		}
		key, rest, ok := strings.Cut(cur.content, ":")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, p.errorf(p.at, "expected a key followed by a colon")
		}
		key = strings.TrimSpace(key)
		if err := checkKey(key, shown(prefix, key)); err != nil {
			return nil, p.errorf(p.at, "%v", err)
		}
		p.at++
		nested, err := p.value(prefix+key, indent, strings.TrimSpace(rest), cur.number)
		if err != nil {
			return nil, err
		}
		out = append(out, nested...)
	}
	return out, nil
}

// value reads what one key holds: a scalar on its own line, or the block
// indented under it.
func (p *parser) value(path string, indent int, inline string, number int) ([]entry, error) {
	if inline != "" {
		scalar, err := scalar(inline)
		if err != nil {
			return nil, fmt.Errorf("line %d: %s: %s: %w", number, path, shown(path, inline), err)
		}
		return []entry{{path: path, value: scalar, line: number}}, nil
	}
	if p.at >= len(p.lines) || p.lines[p.at].indent <= indent {
		return nil, fmt.Errorf("line %d: %s: no value and no block under it", number, path)
	}
	if strings.HasPrefix(p.lines[p.at].content, "- ") || p.lines[p.at].content == "-" {
		return p.sequence(path, p.lines[p.at].indent)
	}
	return p.mapping(p.lines[p.at].indent, path+".")
}

// sequence reads the items at indent, each a scalar or a mapping block.
func (p *parser) sequence(path string, indent int) ([]entry, error) {
	var out []entry
	for index := 0; p.at < len(p.lines); index++ {
		cur := p.lines[p.at]
		if cur.indent < indent {
			return out, nil
		}
		if cur.indent > indent || !strings.HasPrefix(cur.content, "-") {
			return nil, p.errorf(p.at, "expected a sequence item under %s", path)
		}
		item := fmt.Sprintf("%s.%d", path, index)
		rest := strings.TrimSpace(strings.TrimPrefix(cur.content, "-"))
		switch {
		case rest == "":
			p.at++
			if p.at >= len(p.lines) || p.lines[p.at].indent <= indent {
				return nil, p.errorf(p.at-1, "%s: no value under the item", item)
			}
			nested, err := p.mapping(p.lines[p.at].indent, item+".")
			if err != nil {
				return nil, err
			}
			out = append(out, nested...)
		case opensMapping(rest):
			// "- name: x" opens a mapping whose first key sits on the dash's
			// own line and whose others are indented to where that key is.
			p.lines[p.at] = line{indent: cur.indent + 2, content: rest, number: cur.number}
			nested, err := p.mapping(cur.indent+2, item+".")
			if err != nil {
				return nil, err
			}
			out = append(out, nested...)
		default:
			value, err := scalar(rest)
			if err != nil {
				return nil, p.errorf(p.at, "%s: %s: %v", item, shown(item, rest), err)
			}
			out = append(out, entry{path: item, value: value, line: cur.number})
			p.at++
		}
	}
	return out, nil
}

// opensMapping reports whether a sequence item is a mapping rather than a
// scalar: a key is followed by a colon and then nothing or a space, which is
// what tells "name: mail" from "http://localhost:5173".
func opensMapping(item string) bool {
	key, after, ok := strings.Cut(item, ":")
	return ok && !strings.ContainsAny(key, " \t") && (after == "" || strings.HasPrefix(after, " "))
}

// checkKey refuses what this subset does not read, before it is silently
// taken for a key.
func checkKey(key, shown string) error {
	if strings.ContainsAny(key, "&*{}[]|>'\"") {
		return fmt.Errorf("%s: anchors, tags, quoted keys and flow collections are not read here", shown)
	}
	return nil
}

// scalar reads one value: double-quoted with the four escapes below, or
// plain. A plain value keeps its inner spaces and carries no structure. A
// refusal gives the reason alone; shown names the value for the caller.
func scalar(raw string) (string, error) {
	if !strings.HasPrefix(raw, `"`) {
		switch {
		case strings.ContainsAny(raw, "&*{}[]|>"):
			return "", fmt.Errorf("anchors, tags and flow collections are not read here")
		case strings.HasPrefix(raw, "!"), strings.HasPrefix(raw, "'"):
			// Kept as text, a tag or a single-quoted value would reach the
			// configuration with its marks, as a tenant id no run matches.
			return "", fmt.Errorf("tags and single quotes are not read here; quote a value with double quotes")
		}
		return raw, nil
	}
	var out strings.Builder
	for i := 1; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			if i != len(raw)-1 {
				return "", fmt.Errorf("text after the closing quote")
			}
			return out.String(), nil
		case '\\':
			i++
			if i >= len(raw) {
				return "", fmt.Errorf("the value ends inside an escape")
			}
			switch raw[i] {
			case '"', '\\':
				out.WriteByte(raw[i])
			case 'n':
				out.WriteByte('\n')
			case 't':
				out.WriteByte('\t')
			default:
				return "", fmt.Errorf(`\%c is not an escape this reader knows`, raw[i])
			}
		default:
			out.WriteByte(raw[i])
		}
	}
	return "", fmt.Errorf("the value ends without a closing quote")
}

// shown is a value as a refusal names it: under a header map or a credential
// key not at all, under an address key only while it carries nothing that
// could hold a credential, and quoted otherwise. A refused value is often
// half-written YAML, so it is judged by the key it was meant for.
func shown(path, raw string) string {
	if strings.HasPrefix(path, HeadersPrefix) || strings.HasPrefix(path, PDPHeadersPrefix) {
		return NotPrinted
	}
	credential, address := flagsOf(path)
	switch {
	case credential:
		return NotPrinted
	case address:
		if withheld := ShowAddress(raw); withheld != raw {
			return withheld
		}
	}
	return quoteValue(raw)
}

// flagsOf reports whether the key at path is a credential or an address; an
// entry's key is looked up by its name after the index.
func flagsOf(path string) (credential, address bool) {
	for _, f := range configFields {
		if f.path == path {
			return f.credential, f.address
		}
	}
	if rest, ok := strings.CutPrefix(path, "upstreams."); ok {
		if _, name, ok := strings.Cut(rest, "."); ok {
			for _, f := range upstreamFields {
				if f.path == name {
					return f.credential, f.address
				}
			}
		}
	}
	return false, false
}
