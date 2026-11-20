package attempts

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// internal/scenario reads by the same rules but keeps its nodes; conditions and journal lines need exported values.

// Kind is the type of one JSON value.
type Kind uint8

// The kinds a value may have. null is refused wherever it stands.
const (
	Object Kind = iota + 1
	Array
	String
	Number
	Bool
)

// Value is one parsed JSON value. Text is a string's decoded text or a
// number's literal as written; numbers are never converted, so two numbers
// are equal only when they are written alike.
type Value struct {
	Kind    Kind
	Members []Member
	Items   []*Value
	Text    string
	Truth   bool
}

// Member is one member of an object, in document order.
type Member struct {
	Name  string
	Value *Value
}

// Get is the member called name, or nil.
func (v *Value) Get(name string) *Value {
	for _, m := range v.Members {
		if m.Name == name {
			return m.Value
		}
	}
	return nil
}

// Canonical is v written with every object's members sorted by name and no
// white space, so two values are equal exactly when their canonical forms
// are.
func (v *Value) Canonical() string {
	var b strings.Builder
	v.canonical(&b)
	return b.String()
}

func (v *Value) canonical(b *strings.Builder) {
	switch v.Kind {
	case Object:
		members := slices.SortedFunc(slices.Values(v.Members), func(a, b Member) int { return strings.Compare(a.Name, b.Name) })
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(jsonString(m.Name))
			b.WriteByte(':')
			m.Value.canonical(b)
		}
		b.WriteByte('}')
	case Array:
		b.WriteByte('[')
		for i, item := range v.Items {
			if i > 0 {
				b.WriteByte(',')
			}
			item.canonical(b)
		}
		b.WriteByte(']')
	case String:
		b.WriteString(jsonString(v.Text))
	case Number:
		b.WriteString(v.Text)
	case Bool:
		b.WriteString(strconv.FormatBool(v.Truth))
	}
}

// jsonString is s as a JSON string, escaping only the quote, the backslash
// and the control bytes. Every string a parse accepts is UTF-8, so the
// encoding is one to one.
func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// parser reads a document by hand: encoding/json keeps the last of two
// repeated members and replaces bytes that are not UTF-8 and lone surrogates
// without a word. A refusal about what a value holds is noted and the parse
// goes on, so a caller can judge the kind before it; a refusal about the
// shape of the text ends the parse.
type parser struct {
	raw      []byte
	pos      int
	maxDepth int
	noted    error
}

// parse reads raw as one JSON value. noted is the first refusal of a null, a
// repeated member, a string that is not UTF-8 or escapes a lone surrogate, or
// bytes after the value; fatal is a document that cannot be read at all.
func parse(raw []byte, maxDepth int) (root *Value, noted, fatal error) {
	p := &parser{raw: raw, maxDepth: maxDepth}
	root, fatal = p.value(0)
	if fatal != nil {
		return nil, nil, fatal
	}
	p.ws()
	if p.pos < len(p.raw) {
		p.note(fmt.Errorf("%w: at byte %d", ErrTrailing, p.pos))
	}
	return root, p.noted, nil
}

func (p *parser) note(err error) {
	if p.noted == nil {
		p.noted = err
	}
}

func (p *parser) syntax(what string) error {
	return fmt.Errorf("%w: %s at byte %d", ErrSyntax, what, p.pos)
}

func (p *parser) ws() {
	for p.pos < len(p.raw) && strings.IndexByte(" \t\n\r", p.raw[p.pos]) >= 0 {
		p.pos++
	}
}

func (p *parser) at(c byte) bool { return p.pos < len(p.raw) && p.raw[p.pos] == c }

func (p *parser) value(depth int) (*Value, error) {
	p.ws()
	if p.pos >= len(p.raw) {
		return nil, p.syntax("a value is missing")
	}
	switch c := p.raw[p.pos]; {
	case c == '{' || c == '[':
		return p.container(c, depth+1)
	case c == '"':
		s, err := p.str()
		return &Value{Kind: String, Text: s}, err
	case c == 't':
		return p.literal("true", &Value{Kind: Bool, Truth: true})
	case c == 'f':
		return p.literal("false", &Value{Kind: Bool})
	case c == 'n':
		return p.null()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return nil, p.syntax("an unexpected byte")
}

func (p *parser) container(c byte, depth int) (*Value, error) {
	if depth > p.maxDepth {
		return nil, fmt.Errorf("%w: more than %d containers", ErrTooDeep, p.maxDepth)
	}
	if c == '{' {
		return p.object(depth)
	}
	return p.array(depth)
}

// null is read so that the document parses on, and noted: a null anywhere
// refuses the document once its kind has been judged.
func (p *parser) null() (*Value, error) {
	v, err := p.literal("null", &Value{})
	if err == nil {
		p.note(fmt.Errorf("%w: at byte %d", ErrNull, p.pos-len("null")))
	}
	return v, err
}

func (p *parser) literal(word string, v *Value) (*Value, error) {
	if !strings.HasPrefix(string(p.raw[p.pos:min(len(p.raw), p.pos+len(word))]), word) {
		return nil, p.syntax("an unknown literal")
	}
	p.pos += len(word)
	return v, nil
}

func (p *parser) object(depth int) (*Value, error) {
	v := &Value{Kind: Object}
	p.pos++
	p.ws()
	if p.at('}') {
		p.pos++
		return v, nil
	}
	seen := map[string]bool{}
	for {
		p.ws()
		if !p.at('"') {
			return nil, p.syntax("a member name is missing")
		}
		start := p.pos
		name, err := p.str()
		if err != nil {
			return nil, err
		}
		if seen[name] {
			p.note(fmt.Errorf("%w: %q at byte %d", ErrDuplicate, clip(name), start))
		}
		seen[name] = true
		p.ws()
		if !p.at(':') {
			return nil, p.syntax("a colon is missing")
		}
		p.pos++
		member, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		v.Members = append(v.Members, Member{Name: name, Value: member})
		if done, err := p.next('}'); err != nil || done {
			return v, err
		}
	}
}

func (p *parser) array(depth int) (*Value, error) {
	v := &Value{Kind: Array}
	p.pos++
	p.ws()
	if p.at(']') {
		p.pos++
		return v, nil
	}
	for {
		item, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		v.Items = append(v.Items, item)
		if done, err := p.next(']'); err != nil || done {
			return v, err
		}
	}
}

func (p *parser) next(closer byte) (bool, error) {
	p.ws()
	switch {
	case p.at(','):
		p.pos++
		return false, nil
	case p.at(closer):
		p.pos++
		return true, nil
	}
	return false, p.syntax("a comma or the end of the container is missing")
}

func (p *parser) number() (*Value, error) {
	start := p.pos
	if p.at('-') {
		p.pos++
	}
	switch {
	case p.at('0'):
		p.pos++
	case p.digits() == 0:
		return nil, p.syntax("a number has no digits")
	}
	if p.at('.') {
		p.pos++
		if p.digits() == 0 {
			return nil, p.syntax("a fraction has no digits")
		}
	}
	if p.at('e') || p.at('E') {
		p.pos++
		if p.at('+') || p.at('-') {
			p.pos++
		}
		if p.digits() == 0 {
			return nil, p.syntax("an exponent has no digits")
		}
	}
	return &Value{Kind: Number, Text: string(p.raw[start:p.pos])}, nil
}

func (p *parser) digits() int {
	n := 0
	for p.pos < len(p.raw) && p.raw[p.pos] >= '0' && p.raw[p.pos] <= '9' {
		p.pos++
		n++
	}
	return n
}

// str reads one string and returns its decoded text. Raw bytes that are not
// UTF-8 and an escaped surrogate without its pair are noted.
func (p *parser) str() (string, error) {
	start := p.pos
	p.pos++
	var b strings.Builder
	for {
		if p.pos >= len(p.raw) {
			return "", p.syntax("a string never closes")
		}
		c := p.raw[p.pos]
		switch {
		case c == '"':
			p.pos++
			if !utf8.Valid(p.raw[start:p.pos]) {
				p.note(fmt.Errorf("%w: the string at byte %d", ErrNotUTF8, start))
			}
			return b.String(), nil
		case c < 0x20:
			return "", p.syntax("a control byte inside a string")
		case c == '\\':
			if err := p.escape(&b); err != nil {
				return "", err
			}
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
}

func (p *parser) escape(b *strings.Builder) error {
	if p.pos+1 >= len(p.raw) {
		return p.syntax("an escape is cut off")
	}
	c := p.raw[p.pos+1]
	if i := strings.IndexByte(`"\/bfnrt`, c); i >= 0 {
		b.WriteByte("\"\\/\b\f\n\r\t"[i])
		p.pos += 2
		return nil
	}
	if c != 'u' {
		return p.syntax("an unknown escape")
	}
	r, ok := p.hex4(p.pos + 2)
	if !ok {
		return p.syntax("a \\u escape without four hex digits")
	}
	p.pos += 6
	p.unicode(b, r)
	return nil
}

// unicode writes the code point r escapes, joined with the low surrogate
// escaped after it when r is a high one; a lone surrogate is noted.
func (p *parser) unicode(b *strings.Builder, r rune) {
	switch {
	case r >= 0xd800 && r < 0xdc00:
		low, ok := p.hex4(p.pos + 2)
		if ok && p.at('\\') && p.pos+1 < len(p.raw) && p.raw[p.pos+1] == 'u' && low >= 0xdc00 && low < 0xe000 {
			b.WriteRune(0x10000 + (r-0xd800)<<10 + (low - 0xdc00))
			p.pos += 6
			return
		}
		p.note(fmt.Errorf("%w: at byte %d", ErrSurrogate, p.pos-6))
	case r >= 0xdc00 && r < 0xe000:
		p.note(fmt.Errorf("%w: at byte %d", ErrSurrogate, p.pos-6))
	default:
		b.WriteRune(r)
	}
}

func (p *parser) hex4(at int) (rune, bool) {
	if at+4 > len(p.raw) {
		return 0, false
	}
	var r rune
	for _, c := range p.raw[at : at+4] {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(d)
	}
	return r, true
}

// clip keeps at most 64 bytes of s for a refusal.
func clip(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}

// ParseValue reads raw as one JSON value under the rules a journal line is
// read by: arguments sent are read so, to be compared with what a victim
// received.
func ParseValue(raw []byte) (*Value, error) {
	v, noted, fatal := parse(raw, MaxJournalDepth)
	if fatal != nil {
		return nil, fatal
	}
	return v, noted
}
