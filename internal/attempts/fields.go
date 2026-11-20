package attempts

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

func refuse(err Error, at, detail string) error {
	switch {
	case at != "" && detail != "":
		return fmt.Errorf("%w at %s: %s", err, at, detail)
	case at != "":
		return fmt.Errorf("%w at %s", err, at)
	case detail != "":
		return fmt.Errorf("%w: %s", err, detail)
	}
	return err
}

func join(at, name string) string {
	if at == "" {
		return name
	}
	return at + "." + name
}

// closed reads an object whose members the format fixes. Every name in
// required is required; a name after "?" in the list is optional. It refuses
// the first unknown member in document order, then the first missing one.
func closed(v *Value, at string, names ...string) (map[string]*Value, error) {
	if v.Kind != Object {
		return nil, refuse(ErrWrongType, at, "want an object")
	}
	var required, all []string
	optional := false
	for _, n := range names {
		if n == "?" {
			optional = true
			continue
		}
		all = append(all, n)
		if !optional {
			required = append(required, n)
		}
	}
	f := make(map[string]*Value, len(v.Members))
	for _, m := range v.Members {
		if !slices.Contains(all, m.Name) {
			return nil, refuse(ErrUnknownMember, join(at, m.Name), "")
		}
		f[m.Name] = m.Value
	}
	for _, n := range required {
		if _, ok := f[n]; !ok {
			return nil, refuse(ErrMissing, join(at, n), "")
		}
	}
	return f, nil
}

func text(v *Value, at string) (string, error) {
	if v.Kind != String {
		return "", refuse(ErrWrongType, at, "want a string")
	}
	return v.Text, nil
}

// boundedText is a string of 1 to limit bytes with no control character.
func boundedText(v *Value, at string, limit int) (string, error) {
	s, err := text(v, at)
	if err != nil {
		return "", err
	}
	if s == "" || len(s) > limit {
		return "", refuse(ErrBound, at, fmt.Sprintf("%d bytes, want 1 to %d", len(s), limit))
	}
	if i := strings.IndexFunc(s, func(r rune) bool { return unicode.Is(unicode.Cc, r) }); i >= 0 {
		return "", refuse(ErrValue, at, fmt.Sprintf("a control character at byte %d", i))
	}
	return s, nil
}

// integer is a number written as decimal digits alone, from lo to hi.
func integer(v *Value, at string, lo, hi int) (int, error) {
	if v.Kind != Number {
		return 0, refuse(ErrWrongType, at, "want a number")
	}
	if strings.ContainsAny(v.Text, "-.eE") || len(v.Text) > 9 {
		return 0, refuse(ErrValue, at, fmt.Sprintf("%s is not a whole number from %d to %d", clip(v.Text), lo, hi))
	}
	n, err := strconv.Atoi(v.Text)
	if err != nil || n < lo || n > hi {
		return 0, refuse(ErrBound, at, fmt.Sprintf("%s, want %d to %d", v.Text, lo, hi))
	}
	return n, nil
}

// identifier is an id of this format: [a-z0-9][a-z0-9-]{0,63}.
func identifier(v *Value, at string) (string, error) {
	s, err := text(v, at)
	if err != nil {
		return "", err
	}
	valid := s != "" && len(s) <= MaxIDBytes && s[0] != '-'
	for i := 0; valid && i < len(s); i++ {
		c := s[i]
		valid = c == '-' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
	}
	if !valid {
		return "", refuse(ErrValue, at, fmt.Sprintf("%q is not [a-z0-9][a-z0-9-]{0,63}", clip(s)))
	}
	return s, nil
}

// list is an array of lo to hi items.
func list(v *Value, at string, lo, hi int) ([]*Value, error) {
	if v.Kind != Array {
		return nil, refuse(ErrWrongType, at, "want an array")
	}
	if len(v.Items) < lo || len(v.Items) > hi {
		return nil, refuse(ErrBound, at, fmt.Sprintf("%d items, want %d to %d", len(v.Items), lo, hi))
	}
	return v.Items, nil
}

func index(at string, i int) string { return fmt.Sprintf("%s[%d]", at, i) }

// oneOf is a string among set.
func oneOf(v *Value, at string, set ...string) (string, error) {
	s, err := text(v, at)
	if err != nil {
		return "", err
	}
	if !slices.Contains(set, s) {
		return "", refuse(ErrValue, at, fmt.Sprintf("%q, want one of %s", clip(s), strings.Join(set, ", ")))
	}
	return s, nil
}

func readThresholds(v *Value) (Thresholds, error) {
	const at = "thresholds"
	f, err := closed(v, at, "attack_observed_max", "legitimate_completed_min")
	if err != nil {
		return Thresholds{}, err
	}
	var t Thresholds
	if t.AttackObservedMax, err = integer(f["attack_observed_max"], at+".attack_observed_max", 0, MaxObservedLimit); err != nil {
		return Thresholds{}, err
	}
	share := f["legitimate_completed_min"]
	if share.Kind != Number {
		return Thresholds{}, refuse(ErrWrongType, at+".legitimate_completed_min", "want a number")
	}
	basis, ok := shareBasis(share.Text)
	if !ok {
		return Thresholds{}, refuse(ErrValue, at+".legitimate_completed_min",
			fmt.Sprintf("%s is not a share from 0 to 1 with at most four decimals", clip(share.Text)))
	}
	t.CompletedMin, t.CompletedMinBasis = share.Text, basis
	return t, nil
}

// shareBasis reads 0, 1, or a decimal between them with at most four places,
// in ten-thousandths, so the comparison with a count is exact.
func shareBasis(s string) (int, bool) {
	whole, frac, dotted := strings.Cut(s, ".")
	if (whole != "0" && whole != "1") || (dotted && (frac == "" || len(frac) > 4)) {
		return 0, false
	}
	frac += strings.Repeat("0", 4-len(frac))
	n, err := strconv.Atoi(whole + frac)
	if err != nil || strings.ContainsAny(frac, "+-") || n > 10000 {
		return 0, false
	}
	return n, true
}
