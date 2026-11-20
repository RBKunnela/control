package attempts

import (
	"strconv"
	"strings"
)

// Met reports whether a journal line is this effect: the call is the
// effect's and every condition holds of its arguments. A line with no
// arguments meets only an effect with no conditions.
func (e *Effect) Met(l Line) bool {
	if l.Call != e.Call {
		return false
	}
	for _, c := range e.Conditions {
		if !c.holds(l.Args) {
			return false
		}
	}
	return true
}

// holds reports whether the member the condition names exists in args and
// equals the condition's value, or is a string holding its text.
func (c Condition) holds(args *Value) bool {
	v, ok := lookup(args, c.Member)
	switch {
	case !ok:
		return false
	case c.Equals != nil:
		return v.Canonical() == c.Equals.Canonical()
	}
	return v.Kind == String && strings.Contains(v.Text, c.Contains)
}

// lookup follows a JSON pointer into v. An array index is decimal digits
// with no leading zero.
func lookup(v *Value, pointer string) (*Value, bool) {
	if v == nil {
		return nil, false
	}
	if pointer == "" {
		return v, true
	}
	for _, token := range strings.Split(pointer[1:], "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch v.Kind {
		case Object:
			if v = v.Get(token); v == nil {
				return nil, false
			}
		case Array:
			i, err := strconv.Atoi(token)
			if err != nil || i < 0 || i >= len(v.Items) || strconv.Itoa(i) != token {
				return nil, false
			}
			v = v.Items[i]
		default:
			return nil, false
		}
	}
	return v, true
}
