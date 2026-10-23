package adapterkit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/guardana/control/internal/canon"
)

// ResourceID reads the resource id at pointer p in the arguments: a string as
// it stands, a number as the text the canonical form writes for it, anything
// else as no id. It decodes the document itself rather than through the
// canonical form, which the digest applies later to the same bytes.
func ResourceID(args []byte, p string) string {
	if p == "" {
		return ""
	}
	v, err := decode(args)
	if err != nil {
		return ""
	}
	v, ok := walk(v, p)
	if !ok {
		return ""
	}
	return scalarText(v)
}

func decode(args []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.UseNumber()
	var v any
	err := dec.Decode(&v)
	return v, err
}

// walk descends the non-empty pointer p from v.
func walk(v any, p string) (any, bool) {
	for _, tok := range strings.Split(p[1:], "/") {
		var ok bool
		if v, ok = step(v, tok); !ok {
			return nil, false
		}
	}
	return v, true
}

// step descends one pointer token: a member of an object, or an element of
// an array by a decimal index without a leading zero.
func step(v any, tok string) (any, bool) {
	tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
	switch c := v.(type) {
	case map[string]any:
		next, ok := c[tok]
		return next, ok
	case []any:
		if tok == "" || strings.Trim(tok, "0123456789") != "" || len(tok) > 1 && tok[0] == '0' {
			return nil, false
		}
		i, err := strconv.Atoi(tok)
		if err != nil || i >= len(c) {
			return nil, false
		}
		return c[i], true
	}
	return nil, false
}

// scalarText is a number's canonical text, so every spelling of one value,
// 42 and 42.0 among them, names one resource. A number the canonical form
// refuses names none; the digest refuses the call it is in.
func scalarText(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case json.Number:
		if text, err := canon.CanonicalizeJSON([]byte(s.String())); err == nil {
			return string(text)
		}
	}
	return ""
}

// SameResource reports whether the authorized bytes name the resource a call
// was decided on: the member at pointer p reads as decidedID and is, in
// canonical form, the member the proposed bytes hold. An object, a list or a
// boolean there reads as no id on either side, so a rewrite inside it is
// caught only by the second. With no pointer no member names a resource, and
// only a call decided on no id names the same one.
func SameResource(proposed, authorized []byte, p, decidedID string) bool {
	if p == "" {
		return decidedID == ""
	}
	if ResourceID(authorized, p) != decidedID {
		return false
	}
	want, err := memberHash(proposed, p)
	if err != nil {
		return false
	}
	got, err := memberHash(authorized, p)
	return err == nil && got == want
}

// memberHash is the canonical hash of the member at the non-empty pointer p
// in args, "null" for a null member and "" for an absent one.
func memberHash(args []byte, p string) (string, error) {
	v, err := decode(args)
	if err != nil {
		return "", err
	}
	v, ok := walk(v, p)
	if !ok {
		return "", nil
	}
	if v == nil {
		return "null", nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return canon.ArgumentsHashV1(raw)
}

// OverlongPrefix starts the placeholder of a name or a resource id past the
// contract's bound; the digest after it ties the record to the original
// without holding it (ADR-0043).
const OverlongPrefix = "overlong:sha256:"

// Placeholder is what a name or resource id past the bound is recorded as;
// nothing stays nothing.
func Placeholder(original string) string {
	if original == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(original))
	return OverlongPrefix + hex.EncodeToString(sum[:])
}
