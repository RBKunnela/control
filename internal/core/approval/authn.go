package approval

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/guardana/control/pkg/contract"
)

// AuthnPrefix begins the approver id of an approver the plane authenticated.
// Only AuthenticatedApproverID spells it; every approver id a person or a file
// supplies is held to CheckClaimedApproverID, which refuses it.
const AuthnPrefix = "authn:"

// MaxApproverIDBytes bounds an approver id, claimed or authenticated, so both
// cost a record and a listing the same.
const MaxApproverIDBytes = 128

// Error is a refusal of this package's own. Its values are constants, so a
// sentinel can never be nil and read as success.
type Error string

func (e Error) Error() string { return string(e) }

const (
	// ErrReservedApproverID is a claimed approver id CheckClaimedApproverID
	// refuses. One of the six rules below is wrapped beside it.
	ErrReservedApproverID Error = "approval: a claimed approver id may not read as the reserved authn: prefix, which only the plane writes"
	// ErrApproverPrefix is a claimed id that begins with AuthnPrefix.
	ErrApproverPrefix Error = "approval: the approver id begins with the reserved authn: prefix"
	// ErrApproverCodePoint is a claimed id holding a code point that shows
	// nothing or shows unpredictably.
	ErrApproverCodePoint Error = "approval: the approver id holds a code point that shows nothing, or nothing predictable"
	// ErrApproverScripts is a claimed id whose letters mix scripts beyond
	// UTS #39's highly restrictive level.
	ErrApproverScripts Error = "approval: the approver id mixes scripts that may not stand together"
	// ErrApproverMark is a claimed id with a combining mark on ASCII
	// punctuation or an ASCII symbol.
	ErrApproverMark Error = "approval: the approver id puts a combining mark on ASCII punctuation or a symbol"
	// ErrApproverRestyled is a claimed id holding a character of a block that
	// restyles ASCII: fullwidth, mathematical, enclosed, letterlike, small,
	// vertical, superscript or subscript forms.
	ErrApproverRestyled Error = "approval: the approver id holds a fullwidth, mathematical, enclosed, letterlike, small, vertical, superscript or subscript form"
	// ErrApproverReadsAsPrefix is a claimed id whose first six visible
	// characters could read as AuthnPrefix and include an ASCII letter.
	ErrApproverReadsAsPrefix Error = "approval: the approver id could read as the reserved authn: prefix: its first six characters match it, a character outside ASCII counting as any of them"
	// ErrAuthenticatedApprover is an issuer or a subject an authenticated
	// approver id cannot be built from.
	ErrAuthenticatedApprover Error = "approval: an authenticated approver id needs an issuer of printable ASCII with no colon and a subject that begins with no mark, each an identifier, within the approver id's bound"
)

// AuthenticatedApproverID builds "authn:<issuer>:<subject>" for an approver
// the plane authenticated. The issuer is printable ASCII with no colon, so it
// holds no lookalike of one either and the first two colons split the id the
// same way for every reader. The subject is held to the code points a claim
// may hold, and may not begin with a mark, which would sit on the colon.
func AuthenticatedApproverID(issuer, subject string) (string, error) {
	if issuer == "" || subject == "" {
		return "", fmt.Errorf("%w: the issuer and the subject are both required", ErrAuthenticatedApprover)
	}
	for _, part := range []string{issuer, subject} {
		if err := codePoints(part); err != nil {
			return "", fmt.Errorf("%w: %w", ErrAuthenticatedApprover, err)
		}
	}
	if strings.ContainsFunc(issuer, func(r rune) bool { return r < ' ' || r > '~' || r == ':' }) {
		return "", fmt.Errorf("%w: the issuer holds a colon or a character outside printable ASCII", ErrAuthenticatedApprover)
	}
	if first, _ := utf8.DecodeRuneInString(subject); unicode.Is(unicode.M, first) {
		return "", fmt.Errorf("%w: the subject begins with the mark U+%04X", ErrAuthenticatedApprover, first)
	}
	id := AuthnPrefix + issuer + ":" + subject
	if len(id) > MaxApproverIDBytes {
		return "", fmt.Errorf("%w: %d bytes, limit %d", ErrAuthenticatedApprover, len(id), MaxApproverIDBytes)
	}
	return id, nil
}

// CheckClaimedApproverID refuses a claimed approver id that a reader could
// take for an authenticated one. It applies six rules, in order:
//
//  1. the id begins with AuthnPrefix in any ASCII case once leading
//     default-ignorable code points are skipped, which is what a machine
//     comparing bytes would take for the prefix;
//  2. it holds a code point the identifier rule refuses, or one that is
//     private use, unassigned in this build's Unicode version, a
//     noncharacter, or a symbol whose glyph is blank;
//  3. its letters mix scripts beyond UTS #39's highly restrictive level:
//     one script, or Latin with Han, Hiragana and Katakana, with Han and
//     Bopomofo, or with Han and Hangul, where Common and Inherited count as
//     no script;
//  4. it puts a combining mark on ASCII punctuation or an ASCII symbol;
//  5. it holds a character of a block that restyles ASCII: Halfwidth and
//     Fullwidth Forms, Mathematical Alphanumeric Symbols, Enclosed
//     Alphanumerics and their supplement, Letterlike Symbols, Small Form
//     Variants, Vertical Forms, or Superscripts and Subscripts;
//  6. its first six visible characters, marks, white space and blanks passed
//     over, read as AuthnPrefix with at least one ASCII letter among them,
//     where an ASCII character is compared without case and any other
//     character matches whatever position it stands in.
//
// The cost of rules 5 and 6 is that a name in fullwidth, mathematical,
// enclosed or halfwidth letters is refused, and so is an ASCII name that
// begins like "authné:" or "aéééé…". A lookalike written wholly in one
// script other than Latin, with no ASCII letter among its first six
// characters, is accepted: Lisu "ꓮꓴꓔꓧꓠ:ꓧꓠ" is one. The plane never writes such
// an id, and a machine comparing bytes never takes it for the prefix.
func CheckClaimedApproverID(id string) error {
	if beginsWithPrefix(id) {
		return fmt.Errorf("%w: %w", ErrReservedApproverID, ErrApproverPrefix)
	}
	if err := codePoints(id); err != nil {
		return fmt.Errorf("%w: %w: %w", ErrReservedApproverID, ErrApproverCodePoint, err)
	}
	if mixesScripts(id) {
		return fmt.Errorf("%w: %w", ErrReservedApproverID, ErrApproverScripts)
	}
	if i, ok := markOnASCIISymbol(id); ok {
		return fmt.Errorf("%w: %w: at byte %d", ErrReservedApproverID, ErrApproverMark, i)
	}
	if i, r, ok := restyled(id); ok {
		return fmt.Errorf("%w: %w: U+%04X at byte %d", ErrReservedApproverID, ErrApproverRestyled, r, i)
	}
	if readsAsPrefix(id) {
		return fmt.Errorf("%w: %w", ErrReservedApproverID, ErrApproverReadsAsPrefix)
	}
	return nil
}

func beginsWithPrefix(id string) bool {
	rest := strings.TrimLeftFunc(id, defaultIgnorable)
	if len(rest) < len(AuthnPrefix) {
		return false
	}
	for i := range len(AuthnPrefix) {
		c := rest[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != AuthnPrefix[i] {
			return false
		}
	}
	return true
}

// defaultIgnorable is the set the identifier rule refuses as format
// characters and default-ignorable code points.
func defaultIgnorable(r rune) bool {
	return unicode.In(r, unicode.Cf, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point)
}

// blankSymbols are symbols whose glyph is blank by design, or stands for an
// object that is not there.
var blankSymbols = []rune{0x2800, 0x1d159, 0xfffc}

// codePoints holds s to the identifier rule, and then refuses what that rule
// leaves to the reader: private use, unassigned and noncharacter code points,
// and the blank symbols.
func codePoints(s string) error {
	if err := contract.CheckIdentifier(s); err != nil {
		return err
	}
	for i, r := range s {
		if class := unpredictable(r); class != "" {
			return fmt.Errorf("%s U+%04X at byte %d", class, r, i)
		}
	}
	return nil
}

func unpredictable(r rune) string {
	switch {
	case r <= unicode.MaxASCII:
		return ""
	case unicode.Is(unicode.Co, r):
		return "a private-use code point"
	case unicode.Is(unicode.Noncharacter_Code_Point, r):
		return "a noncharacter"
	// The standard library's C table holds the unassigned code points too.
	case !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs):
		return "an unassigned code point"
	case slices.Contains(blankSymbols, r):
		return "a blank symbol"
	}
	return ""
}

// highlyRestrictive are the sets of scripts UTS #39's highly restrictive
// level allows in one identifier beside a single script.
var highlyRestrictive = [][]*unicode.RangeTable{
	{unicode.Latin, unicode.Han, unicode.Hiragana, unicode.Katakana},
	{unicode.Latin, unicode.Han, unicode.Bopomofo},
	{unicode.Latin, unicode.Han, unicode.Hangul},
}

// mixesScripts reports whether the scripts of id's code points, Common and
// Inherited left out, are more than one and fit no highly restrictive set. A
// mark of the Inherited script takes its base's script, which is counted
// already.
func mixesScripts(id string) bool {
	var seen []*unicode.RangeTable
	for _, r := range id {
		if s := scriptOf(r); s != nil && !slices.Contains(seen, s) {
			seen = append(seen, s)
		}
	}
	if len(seen) <= 1 {
		return false
	}
	for _, set := range highlyRestrictive {
		if !slices.ContainsFunc(seen, func(s *unicode.RangeTable) bool { return !slices.Contains(set, s) }) {
			return false
		}
	}
	return true
}

// scriptOf returns the script r belongs to, or nil for Common, Inherited and
// a code point no script holds.
func scriptOf(r rune) *unicode.RangeTable {
	if r <= unicode.MaxASCII {
		if unicode.IsLetter(r) {
			return unicode.Latin
		}
		return nil
	}
	for _, table := range unicode.Scripts {
		if table != unicode.Common && table != unicode.Inherited && unicode.Is(table, r) {
			return table
		}
	}
	return nil
}

// markOnASCIISymbol returns the byte offset of a nonspacing or enclosing mark
// that follows ASCII punctuation or an ASCII symbol.
func markOnASCIISymbol(id string) (int, bool) {
	prev := utf8.RuneError
	for i, r := range id {
		if unicode.In(r, unicode.Mn, unicode.Me) && prev <= unicode.MaxASCII && (unicode.IsPunct(prev) || unicode.IsSymbol(prev)) {
			return i, true
		}
		prev = r
	}
	return 0, false
}

// restyledBlocks are the blocks whose characters restyle ASCII letters,
// digits or punctuation, so a reader takes them for the ASCII they restyle.
var restyledBlocks = []struct{ lo, hi rune }{
	{0x2070, 0x209f},   // Superscripts and Subscripts
	{0x2100, 0x214f},   // Letterlike Symbols
	{0x2460, 0x24ff},   // Enclosed Alphanumerics
	{0xfe10, 0xfe1f},   // Vertical Forms
	{0xfe50, 0xfe6f},   // Small Form Variants
	{0xff00, 0xffef},   // Halfwidth and Fullwidth Forms
	{0x1d400, 0x1d7ff}, // Mathematical Alphanumeric Symbols
	{0x1f100, 0x1f1ff}, // Enclosed Alphanumeric Supplement
}

// restyled returns the first character of id that lies in a restyled block,
// and its byte offset.
func restyled(id string) (int, rune, bool) {
	for i, r := range id {
		for _, b := range restyledBlocks {
			if b.lo <= r && r <= b.hi {
				return i, r, true
			}
		}
	}
	return 0, 0, false
}

// readsAsPrefix reports whether the first six characters a reader sees in id
// could read as AuthnPrefix with an ASCII letter among them. Nothing in the
// standard library says what a character outside ASCII looks like, so each
// one matches whatever position it stands in; the ASCII letter is what keeps
// a name wholly outside ASCII, such as "Владимир", from reading as the prefix.
func readsAsPrefix(id string) bool {
	matched, letter := 0, false
	for _, r := range id {
		if passedOver(r) {
			continue
		}
		if r <= unicode.MaxASCII {
			if unicode.ToLower(r) != rune(AuthnPrefix[matched]) {
				return false
			}
			letter = letter || unicode.IsLetter(r)
		}
		matched++
		if matched == len(AuthnPrefix) {
			return letter
		}
	}
	return false
}

// passedOver is a code point a reader does not see as a character of its
// own: a nonspacing or enclosing mark, white space, a separator, a blank
// symbol, or a default-ignorable code point.
func passedOver(r rune) bool {
	return defaultIgnorable(r) || slices.Contains(blankSymbols, r) ||
		unicode.In(r, unicode.Mn, unicode.Me, unicode.Z, unicode.White_Space)
}
