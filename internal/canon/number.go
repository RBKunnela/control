package canon

import (
	"math"
	"strconv"
	"strings"
)

// A number is written as ECMAScript's Number::toString writes the double it
// denotes (RFC 8785 section 3.2.2.3), with negative zero written 0. The action
// form accepts a literal only when that double is exactly the value written,
// so a second implementation that reads the literal into a double and writes
// it back computes the same bytes; the definition form takes any finite
// double. json.Marshal is not the formatter: it writes negative zero as -0.

// The refusals about a number. Like every refusal they name the shape of the
// value, never the literal, which has no length limit.
const (
	notANumber     = "value is not a JSON number literal"
	numberOutside  = "number is outside the JSON-safe range +/-(2^53-1)"
	numberNotExact = "number is not exactly the shortest decimal of a double"
	// Past the largest double, or so close to zero that it reads as zero.
	numberNotDouble = "number is outside the range of a double"

	// maxExponentDigits bounds the exponent a literal's value is compared
	// under. A longer exponent saturates: no double's shortest decimal is
	// within 10^15 orders of magnitude of it, so the comparison still fails
	// for every nonzero value, and a zero is zero under any exponent.
	maxExponentDigits = 15
)

// decimal is a number as digits * 10^exp, where digits has no leading and no
// trailing zero. Zero has no digits and no sign.
type decimal struct {
	neg    bool
	digits string
	exp    int64
}

// isIntegerLiteral reports whether literal has neither a fraction nor an
// exponent. Such a literal is written by integerText, whose bytes the digest
// goldens pin.
func isIntegerLiteral(literal string) bool {
	return !strings.ContainsAny(literal, ".eE")
}

// actionNumber returns the canonical text of literal under the action form's
// rule, or the reason it is refused.
func actionNumber(literal string) (string, string) {
	d, ok := parseDecimal(literal)
	if !ok {
		return "", notANumber
	}
	if isIntegerLiteral(literal) {
		return integerText(literal)
	}
	f, err := d.float()
	if err != nil || math.IsInf(f, 0) || (f == 0 && d.digits != "") {
		return "", numberNotDouble
	}
	if math.Abs(f) > MaxSafeInteger {
		return "", numberOutside
	}
	nearest, ok := shortest(f)
	if !ok || nearest != d {
		return "", numberNotExact
	}
	return esText(nearest), ""
}

// integerText writes an integer literal as its decimal digits, the bytes the
// digest goldens pin for every integer inside the JSON-safe range.
func integerText(literal string) (string, string) {
	i, err := strconv.ParseInt(literal, 10, 64)
	if err != nil || i > MaxSafeInteger || i < MinSafeInteger {
		return "", outsideRange
	}
	return strconv.FormatInt(i, 10), ""
}

// definitionNumber returns the canonical text of literal under the definition
// form's rule: the double nearest to it, with no range bound and no exactness
// check.
func definitionNumber(literal string) (string, string) {
	d, ok := parseDecimal(literal)
	if !ok {
		return "", notANumber
	}
	f, err := d.float()
	if err != nil || math.IsInf(f, 0) {
		return "", numberNotDouble
	}
	nearest, ok := shortest(f)
	if !ok {
		return "", numberNotDouble
	}
	return esText(nearest), ""
}

// float is the double nearest to d. strconv.ParseFloat caps an exponent above
// about 10000, so it is handed the position of the decimal point rather than
// the literal: a long fraction offset by a long exponent, such as
// 0.000...07e100001, is then read as the 7 it denotes.
func (d decimal) float() (float64, error) {
	if d.digits == "" {
		return 0, nil
	}
	sign := ""
	if d.neg {
		sign = "-"
	}
	point := d.exp + int64(len(d.digits))
	return strconv.ParseFloat(sign+"0."+d.digits+"e"+strconv.FormatInt(point, 10), 64)
}

// shortest is the shortest decimal that reads back as f.
func shortest(f float64) (decimal, bool) {
	return parseDecimal(strconv.FormatFloat(f, 'e', -1, 64))
}

// parseDecimal reads a number literal of RFC 8259 section 6 exactly, and
// reports false for anything else, a leading +, a leading zero or a bare
// fraction among them. A json.Number can hold any string, so the grammar is
// checked here rather than trusted.
func parseDecimal(literal string) (decimal, bool) {
	var d decimal
	s := literal
	if rest, ok := strings.CutPrefix(s, "-"); ok {
		d.neg, s = true, rest
	}
	n := digitRun(s)
	if n == 0 || (n > 1 && s[0] == '0') {
		return decimal{}, false
	}
	whole, s := s[:n], s[n:]
	var fraction string
	if rest, ok := strings.CutPrefix(s, "."); ok {
		n = digitRun(rest)
		if n == 0 {
			return decimal{}, false
		}
		fraction, s = rest[:n], rest[n:]
	}
	var exp int64
	if s != "" {
		if s[0] != 'e' && s[0] != 'E' {
			return decimal{}, false
		}
		var ok bool
		if exp, ok = exponent(s[1:]); !ok {
			return decimal{}, false
		}
	}
	digits := strings.TrimLeft(whole+fraction, "0")
	if digits == "" {
		return decimal{}, true
	}
	trimmed := strings.TrimRight(digits, "0")
	d.digits = trimmed
	d.exp = exp - int64(len(fraction)) + int64(len(digits)-len(trimmed))
	return d, true
}

// exponent reads the part of a literal after its e: an optional sign and at
// least one digit, saturating past maxExponentDigits.
func exponent(s string) (int64, bool) {
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg, s = s[0] == '-', s[1:]
	}
	if s == "" || digitRun(s) != len(s) {
		return 0, false
	}
	s = strings.TrimLeft(s, "0")
	var e int64
	if len(s) > maxExponentDigits {
		e = int64(math.Pow10(maxExponentDigits))
	} else if s != "" {
		var err error
		if e, err = strconv.ParseInt(s, 10, 64); err != nil {
			return 0, false
		}
	}
	if neg {
		e = -e
	}
	return e, true
}

func digitRun(s string) int {
	i := 0
	for i < len(s) && '0' <= s[i] && s[i] <= '9' {
		i++
	}
	return i
}

// esText lays d out as Number::toString does (ECMA-262, Number::toString,
// steps 5 to 10). d is always a double's shortest decimal, so it has at most
// 17 digits and the padding below is bounded.
func esText(d decimal) string {
	if d.digits == "" {
		return "0"
	}
	var b strings.Builder
	if d.neg {
		b.WriteByte('-')
	}
	k := int64(len(d.digits))
	n := d.exp + k
	switch {
	case k <= n && n <= 21:
		b.WriteString(d.digits)
		b.WriteString(strings.Repeat("0", int(n-k)))
	case 0 < n && n <= 21:
		b.WriteString(d.digits[:n])
		b.WriteByte('.')
		b.WriteString(d.digits[n:])
	case -6 < n && n <= 0:
		b.WriteString("0.")
		b.WriteString(strings.Repeat("0", int(-n)))
		b.WriteString(d.digits)
	default:
		b.WriteByte(d.digits[0])
		if k > 1 {
			b.WriteByte('.')
			b.WriteString(d.digits[1:])
		}
		b.WriteByte('e')
		if n-1 >= 0 {
			b.WriteByte('+')
		}
		b.WriteString(strconv.FormatInt(n-1, 10))
	}
	return b.String()
}
