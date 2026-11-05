package rules

import "strings"

// The parameters restrict_resources reads.
const (
	paramIDs    = "ids"
	paramPrefix = "prefix"
)

// ResourceAllowed reads params as restrict_resources' exact ids,
// comma-separated, and literal prefix; id passes when either matches. Neither
// parameter present allows nothing, and an exact id is compared as text.
func ResourceAllowed(id string, params map[string]string) bool {
	if ids, ok := params[paramIDs]; ok {
		for want := range strings.SplitSeq(ids, ",") {
			if want != "" && want == id {
				return true
			}
		}
	}
	prefix, ok := params[paramPrefix]
	return ok && UnderPrefix(id, prefix)
}

// UnderPrefix reports whether id starts with the non-empty prefix and the
// path from the segment the prefix ends in avoids every spelling a resolver
// is known to read as leaving it: a percent escape, a `;` parameter, a `?` or
// `#`, which a URI resolver cuts before it removes dot segments, a backslash,
// a byte outside printable ASCII, a segment of only dots and spaces, and an
// empty segment but a trailing one. The upstream's own resolver is not
// consulted.
func UnderPrefix(id, prefix string) bool {
	return prefix != "" && strings.HasPrefix(id, prefix) && plainBelow(id[strings.LastIndex(prefix, "/")+1:])
}

func plainBelow(rest string) bool {
	for i := 0; i < len(rest); i++ {
		if !plainByte(rest[i]) {
			return false
		}
	}
	segments := strings.Split(rest, "/")
	for i, s := range segments {
		if s == "" {
			if i != len(segments)-1 {
				return false
			}
			continue
		}
		if strings.Trim(s, ". ") == "" {
			return false
		}
	}
	return true
}

// plainByte reports whether b is printable ASCII that no resolver reads as
// an escape, a parameter, a query, a fragment or a separator.
func plainByte(b byte) bool {
	switch b {
	case '%', ';', '?', '#', '\\':
		return false
	}
	return b >= 0x20 && b <= 0x7e
}
