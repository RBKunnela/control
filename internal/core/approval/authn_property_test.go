package approval_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"pgregory.net/rapid"

	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/pkg/contract"
)

// unassignedRanges hold no assigned code point in any Unicode version this
// module builds with: a gap in Greek, and planes 4 to 13, which are reserved
// whole.
var unassignedRanges = &unicode.RangeTable{
	R16: []unicode.Range16{{Lo: 0x0378, Hi: 0x0379, Stride: 1}, {Lo: 0x0380, Hi: 0x0383, Stride: 1}},
	R32: []unicode.Range32{{Lo: 0x40000, Hi: 0xdfffd, Stride: 1}},
}

// noncharacters are the 66 the standard names: U+FDD0 to U+FDEF, and the
// last two code points of every plane.
var noncharacters = func() *unicode.RangeTable {
	t := &unicode.RangeTable{R16: []unicode.Range16{{Lo: 0xfdd0, Hi: 0xfdef, Stride: 1}, {Lo: 0xfffe, Hi: 0xffff, Stride: 1}}}
	for plane := uint32(1); plane <= 16; plane++ {
		t.R32 = append(t.R32, unicode.Range32{Lo: plane<<16 | 0xfffe, Hi: plane<<16 | 0xffff, Stride: 1})
	}
	return t
}()

// TestAnyRefusedCodePointAnywhereInAnAcceptedIDIsRefused: a private-use,
// unassigned, noncharacter or default-ignorable code point inserted at any
// position of an id the rule accepts makes it refused.
func TestAnyRefusedCodePointAnywhereInAnAcceptedIDIsRefused(t *testing.T) {
	valid := make([]string, 0, len(acceptedClaims))
	for _, id := range acceptedClaims {
		valid = append(valid, id)
	}
	slices.Sort(valid)
	refused := rapid.OneOf(
		rapid.RuneFrom(nil, unicode.Co),
		rapid.RuneFrom(nil, unassignedRanges),
		rapid.RuneFrom(nil, noncharacters),
		rapid.RuneFrom(nil, unicode.Cf, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point),
	)
	rapid.Check(t, func(t *rapid.T) {
		runes := []rune(rapid.SampledFrom(valid).Draw(t, "valid"))
		at := rapid.IntRange(0, len(runes)).Draw(t, "at")
		r := refused.Draw(t, "refused")
		id := string(slices.Insert(runes, at, r))
		if err := approval.CheckClaimedApproverID(id); !errors.Is(err, approval.ErrReservedApproverID) {
			t.Fatalf("U+%04X at %d of %+q: %v, want it refused", r, at, id, err)
		}
	})
}

// latinCompatible are the scripts UTS #39's highly restrictive level allows
// beside Latin, and the two that are no script at all.
var latinCompatible = []string{"Latin", "Han", "Hiragana", "Katakana", "Bopomofo", "Hangul", "Common", "Inherited"}

// scriptOf names the script r belongs to, or "".
func scriptOf(r rune) string {
	for name, table := range unicode.Scripts {
		if unicode.Is(table, r) {
			return name
		}
	}
	return ""
}

// TestALetterOfAnotherScriptInThePrefixIsRefused: "authn:" with any one
// letter replaced by a letter of a script no set allows beside Latin is
// refused for mixing scripts, whatever ASCII follows.
func TestALetterOfAnotherScriptInThePrefixIsRefused(t *testing.T) {
	foreign := rapid.RuneFrom(nil, unicode.L).Filter(func(r rune) bool {
		return !slices.Contains(latinCompatible, scriptOf(r)) && !unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
	})
	rapid.Check(t, func(t *rapid.T) {
		id := []rune("authn:")
		id[rapid.IntRange(0, 4).Draw(t, "at")] = foreign.Draw(t, "letter")
		rest := rapid.StringMatching(`[a-z0-9:]{0,8}`).Draw(t, "rest")
		claim := string(id) + rest
		if err := approval.CheckClaimedApproverID(claim); !errors.Is(err, approval.ErrApproverScripts) {
			t.Fatalf("%+q: %v, want %v", claim, err, approval.ErrApproverScripts)
		}
	})
}

// TestLettersOfOneScriptAreAccepted: any run of letters of one script outside
// ASCII and the restyled blocks, ASCII spaces and hyphens between them, is
// accepted, whichever script it is.
func TestLettersOfOneScriptAreAccepted(t *testing.T) {
	var names []string
	for name, table := range unicode.Scripts {
		if name != "Common" && name != "Inherited" && holdsALetter(table) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	rapid.Check(t, func(t *rapid.T) {
		script := unicode.Scripts[rapid.SampledFrom(names).Draw(t, "script")]
		letter := rapid.RuneFrom(nil, script).Filter(func(r rune) bool {
			return r > unicode.MaxASCII && unicode.IsLetter(r) && !unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) && !inARestyledBlock(r)
		})
		var b strings.Builder
		for i, n := 0, rapid.IntRange(1, 8).Draw(t, "letters"); i < n; i++ {
			if i > 0 && rapid.Bool().Draw(t, "separate") {
				b.WriteString(rapid.SampledFrom([]string{" ", "-"}).Draw(t, "separator"))
			}
			b.WriteRune(letter.Draw(t, "letter"))
		}
		id := b.String()
		if err := approval.CheckClaimedApproverID(id); err != nil {
			t.Fatalf("%+q: %v, want it accepted", id, err)
		}
	})
}

func inARestyledBlock(r rune) bool {
	for _, b := range restyledBlocks {
		if b.lo <= r && r <= b.hi {
			return true
		}
	}
	return false
}

// visibleOutsideASCII draws a code point outside ASCII that a reader sees as
// a character of its own.
func visibleOutsideASCII() *rapid.Generator[rune] {
	return rapid.RuneFrom(nil, unicode.L, unicode.Mc, unicode.N, unicode.P, unicode.S).Filter(func(r rune) bool {
		return r > unicode.MaxASCII && !slices.Contains(blankSymbols, r) && !unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
	})
}

// passedOver are code points a reader passes over, one of each class.
var passedOver = []string{"", "\u0301", "\u20dd", "\u200b", "\u2060", "\ufe0f", "\u034f", " ", "\u00a0", "\u2800", "\u3164"}

// TestEveryReadingOfThePrefixIsRefused: "authn:" with any of its positions in
// either case or replaced by a character outside ASCII, an ASCII letter left
// among the first five, and anything a reader passes over before any
// position, is refused whatever follows.
func TestEveryReadingOfThePrefixIsRefused(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		kept := rapid.IntRange(0, 4).Draw(t, "kept")
		var b strings.Builder
		for i, want := range "authn:" {
			b.WriteString(rapid.SampledFrom(passedOver).Draw(t, "passed over"))
			form := rapid.IntRange(0, 2).Draw(t, "form")
			switch {
			case i == kept || form == 0:
				b.WriteRune(want)
			case form == 1:
				b.WriteRune(unicode.ToUpper(want))
			default:
				b.WriteRune(visibleOutsideASCII().Draw(t, "lookalike"))
			}
		}
		b.WriteString(rapid.String().Draw(t, "rest"))
		id := b.String()
		if err := approval.CheckClaimedApproverID(id); !errors.Is(err, approval.ErrReservedApproverID) {
			t.Fatalf("%+q: %v, want it refused", id, err)
		}
	})
}

// holdsALetter reports whether table holds a letter that is not
// default-ignorable.
func holdsALetter(table *unicode.RangeTable) bool {
	for _, r := range table.R16 {
		for c := rune(r.Lo); c <= rune(r.Hi); c += rune(r.Stride) {
			if unicode.IsLetter(c) && !unicode.Is(unicode.Other_Default_Ignorable_Code_Point, c) {
				return true
			}
		}
	}
	for _, r := range table.R32 {
		for c := r.Lo; c <= r.Hi; c += r.Stride {
			if letter := rune(c); unicode.IsLetter(letter) && !unicode.Is(unicode.Other_Default_Ignorable_Code_Point, letter) { //nolint:gosec // G115: a range table holds code points, which fit a rune
				return true
			}
		}
	}
	return false
}

// TestNoClaimCanBeWhatTheConstructorBuilds: whatever issuer and subject the
// constructor accepts, its id is one every claimed path refuses, and it is
// an identifier within the bound the store holds a record to.
func TestNoClaimCanBeWhatTheConstructorBuilds(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		issuer := rapid.String().Draw(t, "issuer")
		subject := rapid.String().Draw(t, "subject")
		id, err := approval.AuthenticatedApproverID(issuer, subject)
		if err != nil {
			return
		}
		if !strings.HasPrefix(id, "authn:") || len(id) > 128 {
			t.Fatalf("built %q", id)
		}
		if err := contract.CheckIdentifier(id); err != nil {
			t.Fatalf("built %q, which is no identifier: %v", id, err)
		}
		if err := approval.CheckClaimedApproverID(id); !errors.Is(err, approval.ErrApproverPrefix) {
			t.Fatalf("built %q, which a claim may spell: %v", id, err)
		}
		if first, _ := utf8.DecodeRuneInString(subject); unicode.Is(unicode.M, first) {
			t.Fatalf("built %q from a subject that begins with a mark", id)
		}
	})
}

// FuzzCheckClaimedApproverID: no input panics, every refusal carries the
// reservation's sentinel, every input whose first six bytes are the prefix in
// any ASCII case is refused, and nothing accepted is refused by the
// identifier rule.
func FuzzCheckClaimedApproverID(f *testing.F) {
	for _, c := range refusedClaims {
		f.Add(c.id)
	}
	for _, id := range acceptedClaims {
		f.Add(id)
	}
	for _, id := range documentedResidue {
		f.Add(id)
	}
	for _, id := range []string{"\xff\xfe", "a\u0301", strings.Repeat("\u200b", 64)} {
		f.Add(id)
	}
	f.Fuzz(func(t *testing.T, id string) {
		err := approval.CheckClaimedApproverID(id)
		if err != nil && !errors.Is(err, approval.ErrReservedApproverID) {
			t.Fatalf("%+q: %v, a refusal of another kind", id, err)
		}
		if len(id) >= 6 && strings.EqualFold(id[:6], "authn:") && err == nil {
			t.Fatalf("%+q: accepted", id)
		}
		if err == nil && contract.CheckIdentifier(id) != nil {
			t.Fatalf("%+q: accepted, and no identifier", id)
		}
	})
}
