package approval_test

import (
	"errors"
	"strings"
	"testing"
	"unicode"

	"github.com/guardana/control/internal/core/approval"
)

// refusal is a claimed id and the rule that refuses it. The rules apply in
// order, so each case names the first that refuses it.
type refusal struct {
	id   string
	rule error
}

// refusedClaims are claimed ids a reader could take for one the plane
// authenticated. Code points are written as escapes, so the source shows what
// each one is.
var refusedClaims = map[string]refusal{
	"the prefix itself":                      {"authn:okta:alice", approval.ErrApproverPrefix},
	"the prefix and nothing after it":        {"authn:", approval.ErrApproverPrefix},
	"capitals":                               {"AUTHN:okta:alice", approval.ErrApproverPrefix},
	"a capital first letter":                 {"Authn:x", approval.ErrApproverPrefix},
	"mixed case":                             {"aUtHn:x", approval.ErrApproverPrefix},
	"a leading zero-width joiner":            {"\u200dauthn:x", approval.ErrApproverPrefix},
	"a leading zero-width non-joiner":        {"\u200cauthn:x", approval.ErrApproverPrefix},
	"a leading right-to-left override":       {"\u202eauthn:x", approval.ErrApproverPrefix},
	"a leading variation selector":           {"\ufe0fauthn:x", approval.ErrApproverPrefix},
	"a leading Hangul filler":                {"\u3164authn:x", approval.ErrApproverPrefix},
	"a leading Hangul choseong filler":       {"\u115fauthn:x", approval.ErrApproverPrefix},
	"a leading Hangul jungseong filler":      {"\u1160authn:x", approval.ErrApproverPrefix},
	"a leading halfwidth Hangul filler":      {"\uffa0authn:x", approval.ErrApproverPrefix},
	"two leading default-ignorables":         {"\u2060\U000e0100AUTHN:x", approval.ErrApproverPrefix},
	"a zero-width space inside":              {"au\u200bthn:x", approval.ErrApproverCodePoint},
	"a variation selector inside":            {"auth\ufe0fn:x", approval.ErrApproverCodePoint},
	"a Hangul filler inside":                 {"au\u3164thn:x", approval.ErrApproverCodePoint},
	"a zero-width joiner inside":             {"au\u200dthn:x", approval.ErrApproverCodePoint},
	"a zero-width non-joiner at the colon":   {"authn\u200c:x", approval.ErrApproverCodePoint},
	"a bidi override inside":                 {"authn\u202e:x", approval.ErrApproverCodePoint},
	"a bidi isolate inside":                  {"auth\u2067n:x", approval.ErrApproverCodePoint},
	"a leading space":                        {" authn:x", approval.ErrApproverCodePoint},
	"a no-break space inside":                {"auth\u00a0n:x", approval.ErrApproverCodePoint},
	"an ideographic space at the colon":      {"authn\u3000:x", approval.ErrApproverCodePoint},
	"a leading braille blank":                {"\u2800authn:okta:alice", approval.ErrApproverCodePoint},
	"a braille blank before the colon":       {"authn\u2800:x", approval.ErrApproverCodePoint},
	"a null notehead inside":                 {"a\U0001d159uthn:okta:alice", approval.ErrApproverCodePoint},
	"a null notehead after a Hebrew alef":    {"\u05d0au\U0001d159thn:okta:alice", approval.ErrApproverCodePoint},
	"a private-use code point":               {"a\U000f0000uthn:okta:alice", approval.ErrApproverCodePoint},
	"a BMP private-use code point":           {"auth\ue000n:x", approval.ErrApproverCodePoint},
	"an unassigned code point":               {"a\u0378uthn:okta:alice", approval.ErrApproverCodePoint},
	"the noncharacter U+FFFE":                {"authn\ufffex", approval.ErrApproverCodePoint},
	"the noncharacter U+10FFFF":              {"authn\U0010ffff:x", approval.ErrApproverCodePoint},
	"the noncharacter U+FDD0":                {"au\ufdd0thn:x", approval.ErrApproverCodePoint},
	"the object replacement character":       {"authn\ufffc:x", approval.ErrApproverCodePoint},
	"a Cyrillic a":                           {"\u0430uthn:x", approval.ErrApproverScripts},
	"a Cyrillic capital A":                   {"\u0410UTHN:x", approval.ErrApproverScripts},
	"a Greek alpha":                          {"\u03b1uthn:x", approval.ErrApproverScripts},
	"an Armenian u":                          {"a\u057dthn:x", approval.ErrApproverScripts},
	"a Greek upsilon":                        {"a\u03c5thn:x", approval.ErrApproverScripts},
	"a Cyrillic te":                          {"au\u0442hn:x", approval.ErrApproverScripts},
	"a Greek capital tau":                    {"AU\u03a4HN:x", approval.ErrApproverScripts},
	"a Cyrillic shha":                        {"aut\u04bbn:x", approval.ErrApproverScripts},
	"a Greek capital eta for the H":          {"AUT\u0397N:x", approval.ErrApproverScripts},
	"an Armenian vo":                         {"auth\u0578:x", approval.ErrApproverScripts},
	"a Greek capital nu":                     {"AUTH\u039d:x", approval.ErrApproverScripts},
	"the Armenian full stop":                 {"authn\u0589x", approval.ErrApproverScripts},
	"a Hebrew sof pasuq":                     {"authn\u05c3x", approval.ErrApproverScripts},
	"Lisu capitals":                          {"\ua4ee\ua4f4\ua4d4\ua4e7\ua4e0:okta:alice", approval.ErrApproverScripts},
	"one Lisu letter among ASCII":            {"AUT\ua4e7N:x", approval.ErrApproverScripts},
	"Coptic and Armenian capitals":           {"\u2c80\u054d\u2ca6\u2c8e\u2c9a:okta:alice", approval.ErrApproverScripts},
	"a Coptic small alfa":                    {"\u2c81uthn:x", approval.ErrApproverScripts},
	"Cherokee small letters":                 {"\uab7a\u144c\uab72\uab8b\u0578:x", approval.ErrApproverScripts},
	"a Canadian syllabics ne":                {"auth\u144e:x", approval.ErrApproverScripts},
	"a Cyrillic te with descender":           {"au\u04adhn:x", approval.ErrApproverScripts},
	"a Devanagari visarga":                   {"authn\u0903okta:alice", approval.ErrApproverScripts},
	"a Gujarati visarga":                     {"authn\u0a83okta:alice", approval.ErrApproverScripts},
	"a Bengali visarga":                      {"authn\u0983x", approval.ErrApproverScripts},
	"a Gurmukhi visarga":                     {"authn\u0a03x", approval.ErrApproverScripts},
	"a Telugu visarga":                       {"authn\u0c03x", approval.ErrApproverScripts},
	"a Sinhala visarga":                      {"authn\u0d83x", approval.ErrApproverScripts},
	"a Myanmar visarga":                      {"authn\u1038x", approval.ErrApproverScripts},
	"a Javanese wignyan":                     {"authn\ua983x", approval.ErrApproverScripts},
	"the Tibetan rnam bcad":                  {"authn\u0f7fokta:alice", approval.ErrApproverScripts},
	"a Tibetan gter tsheg":                   {"authn\u0f14x", approval.ErrApproverScripts},
	"a Syriac supralinear colon":             {"authn\u0706x", approval.ErrApproverScripts},
	"a Syriac colon skewed left":             {"authn\u0708x", approval.ErrApproverScripts},
	"the Ethiopic colon":                     {"authn\u1365x", approval.ErrApproverScripts},
	"the Ethiopic preface colon":             {"authn\u1366x", approval.ErrApproverScripts},
	"the Bamum colon":                        {"authn\ua6f4x", approval.ErrApproverScripts},
	"a Hebrew letter before the prefix":      {"\u05d0authn:x", approval.ErrApproverScripts},
	"an Arabic letter before the prefix":     {"\u0645authn:x", approval.ErrApproverScripts},
	"the prefix inside a Hebrew id":          {"x\u05d0authn:y", approval.ErrApproverScripts},
	"a Hebrew letter far from the prefix":    {"authn:okta:alice-\u05d0", approval.ErrApproverPrefix},
	"Latin beside Cyrillic in a name":        {"Ivan \u0418\u0432\u0430\u043d", approval.ErrApproverScripts},
	"Hiragana beside Hangul":                 {"\u3055\uae40", approval.ErrApproverScripts},
	"Bopomofo beside Katakana":               {"\u3105\u30ab", approval.ErrApproverScripts},
	"Hangul beside Bopomofo":                 {"\uae40\u3105", approval.ErrApproverScripts},
	"Bopomofo beside Hiragana":               {"\u3105\u3055", approval.ErrApproverScripts},
	"a dot above on a full stop":             {"authn.\u0307okta:alice", approval.ErrApproverMark},
	"a dot above on a semicolon":             {"authn;\u0307x", approval.ErrApproverMark},
	"a diaeresis on a full stop":             {"authn.\u0308x", approval.ErrApproverMark},
	"an enclosing circle on a hyphen":        {"authn-\u20ddx", approval.ErrApproverMark},
	"a mark on a symbol":                     {"authn+\u0307x", approval.ErrApproverMark},
	"fullwidth letters and colon":            {"\uff41\uff55\uff54\uff48\uff4e\uff1ax", approval.ErrApproverRestyled},
	"mathematical bold letters":              {"\U0001d41a\U0001d42e\U0001d42d\U0001d421\U0001d427:x", approval.ErrApproverRestyled},
	"mathematical bold capitals":             {"\U0001d400\U0001d414\U0001d413\U0001d407\U0001d40d:x", approval.ErrApproverRestyled},
	"circled letters":                        {"\u24d0\u24e4\u24e3\u24d7\u24dd:x", approval.ErrApproverRestyled},
	"regional indicators":                    {"\U0001f1e6\U0001f1fa\U0001f1f9\U0001f1ed\U0001f1f3:x", approval.ErrApproverRestyled},
	"a mathematical Greek small alpha":       {"\U0001d6c2uthn:x", approval.ErrApproverRestyled},
	"a mathematical italic small alpha":      {"\U0001d6fcuthn:x", approval.ErrApproverRestyled},
	"a mathematical Greek capital alpha":     {"\U0001d6a8UTHN:x", approval.ErrApproverRestyled},
	"a mathematical Greek small nu":          {"auth\U0001d6ce:x", approval.ErrApproverRestyled},
	"the Planck constant":                    {"aut\u210en:x", approval.ErrApproverRestyled},
	"the Planck constant over two pi":        {"aut\u210fn:x", approval.ErrApproverRestyled},
	"a double-struck capital n":              {"AUTH\u2115:x", approval.ErrApproverRestyled},
	"a fullwidth colon":                      {"authn\uff1ax", approval.ErrApproverRestyled},
	"a small colon":                          {"authn\ufe55x", approval.ErrApproverRestyled},
	"a vertical colon":                       {"authn\ufe13x", approval.ErrApproverRestyled},
	"a superscript n":                        {"auth\u207f:x", approval.ErrApproverRestyled},
	"a fullwidth name":                       {"\uff4a\uff4f\uff48\uff4e", approval.ErrApproverRestyled},
	"a mathematical name":                    {"\U0001d409\U0001d428\U0001d421\U0001d427", approval.ErrApproverRestyled},
	"an enclosed name":                       {"\u24bf\u24de\u24d7\u24dd", approval.ErrApproverRestyled},
	"a halfwidth Katakana name":              {"\uff76\uff80", approval.ErrApproverRestyled},
	"the intersection sign":                  {"a\u2229thn:x", approval.ErrApproverReadsAsPrefix},
	"a Latin a with a grave":                 {"\u00e0uthn:x", approval.ErrApproverReadsAsPrefix},
	"a Latin small capital u":                {"a\u1d1cthn:x", approval.ErrApproverReadsAsPrefix},
	"a combining acute after the a":          {"a\u0301uthn:x", approval.ErrApproverReadsAsPrefix},
	"the APL alpha":                          {"\u237authn:x", approval.ErrApproverReadsAsPrefix},
	"a union sign":                           {"a\u222athn:x", approval.ErrApproverReadsAsPrefix},
	"the ratio sign":                         {"authn\u2236x", approval.ErrApproverReadsAsPrefix},
	"a modifier letter colon":                {"authn\ua789x", approval.ErrApproverReadsAsPrefix},
	"a modifier letter triangular colon":     {"authn\u02d0x", approval.ErrApproverReadsAsPrefix},
	"the two dot punctuation":                {"authn\u205ax", approval.ErrApproverReadsAsPrefix},
	"a presentation form colon":              {"authn\ufe30x", approval.ErrApproverReadsAsPrefix},
	"the Z notation type colon":              {"authn\u2982x", approval.ErrApproverReadsAsPrefix},
	"a mark on a colon lookalike":            {"authn\u2236\u0307x", approval.ErrApproverReadsAsPrefix},
	"a space inside the prefix":              {"authn :x", approval.ErrApproverReadsAsPrefix},
	"an ASCII prefix with an accented colon": {"authn\u00e9:x", approval.ErrApproverReadsAsPrefix},
	"an a and five accented letters":         {"a\u00e9\u00e9\u00e9\u00e9\u00e9", approval.ErrApproverReadsAsPrefix},
}

// TestAClaimedApproverIDThatReadsAsAnAuthenticatedOneIsRefused: each claim is
// refused with the reservation's sentinel and the rule its case names.
func TestAClaimedApproverIDThatReadsAsAnAuthenticatedOneIsRefused(t *testing.T) {
	for name, c := range refusedClaims {
		err := approval.CheckClaimedApproverID(c.id)
		if !errors.Is(err, approval.ErrReservedApproverID) || !errors.Is(err, c.rule) {
			t.Errorf("%s (%+q): %v, want %v and %v", name, c.id, err, approval.ErrReservedApproverID, c.rule)
		}
	}
}

// TestEachRefusedCodePointNamesItsClass: a refused code point is named by its
// class, so a class folded into another one fails here.
func TestEachRefusedCodePointNamesItsClass(t *testing.T) {
	for id, class := range map[string]string{
		"a\U000f0000b": "private-use",
		"a\ue000b":     "private-use",
		"a\u0378b":     "unassigned",
		"a\U00040000b": "unassigned",
		"a\ufffeb":     "noncharacter",
		"a\U0010ffffb": "noncharacter",
		"a\ufdd0b":     "noncharacter",
		"a\U0001fffeb": "noncharacter",
		"a\u2800b":     "blank",
		"a\U0001d159b": "blank",
		"a\ufffcb":     "blank",
	} {
		err := approval.CheckClaimedApproverID(id)
		if !errors.Is(err, approval.ErrApproverCodePoint) || !strings.Contains(err.Error(), class) {
			t.Errorf("%+q: %v, want %v naming a %s code point", id, err, approval.ErrApproverCodePoint, class)
		}
	}
}

// blankSymbols are the symbols whose glyph is blank by design, or stands for
// an object that is not there. Each is refused anywhere in an id, alone or
// in the middle of a name.
var blankSymbols = []rune{0x2800, 0x1d159, 0xfffc}

func TestEveryBlankSymbolIsRefused(t *testing.T) {
	for _, r := range blankSymbols {
		for _, id := range []string{string(r), "zo" + string(r) + "e", "duty-officer" + string(r)} {
			if err := approval.CheckClaimedApproverID(id); !errors.Is(err, approval.ErrApproverCodePoint) {
				t.Errorf("U+%04X in %+q: %v, want %v", r, id, err, approval.ErrApproverCodePoint)
			}
		}
	}
}

// restyledBlocks are the blocks whose every character a reader may take for
// the ASCII it restyles, written out here rather than taken from the package.
var restyledBlocks = map[string]struct{ lo, hi rune }{
	"Superscripts and Subscripts":       {0x2070, 0x209f},
	"Letterlike Symbols":                {0x2100, 0x214f},
	"Enclosed Alphanumerics":            {0x2460, 0x24ff},
	"Vertical Forms":                    {0xfe10, 0xfe1f},
	"Small Form Variants":               {0xfe50, 0xfe6f},
	"Halfwidth and Fullwidth Forms":     {0xff00, 0xffef},
	"Mathematical Alphanumeric Symbols": {0x1d400, 0x1d7ff},
	"Enclosed Alphanumeric Supplement":  {0x1f100, 0x1f1ff},
}

// TestEveryCharacterOfARestyledBlockIsRefused: each assigned character of
// each block, alone, is refused by the restyling rule, and the character
// just past each block is not.
func TestEveryCharacterOfARestyledBlockIsRefused(t *testing.T) {
	for name, b := range restyledBlocks {
		seen := 0
		for r := b.lo; r <= b.hi; r++ {
			if !unicode.IsGraphic(r) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) {
				continue
			}
			seen++
			if err := approval.CheckClaimedApproverID(string(r)); !errors.Is(err, approval.ErrApproverRestyled) {
				t.Errorf("%s: U+%04X alone = %v, want %v", name, r, err, approval.ErrApproverRestyled)
			}
		}
		if seen == 0 {
			t.Errorf("%s: no assigned character was tried", name)
		}
	}
	for _, r := range []rune{0x20a0, 0x2150, 0x2500, 0xfe20, 0xfe4f, 0xfe70, 0x1d800, 0x1f200} {
		if err := approval.CheckClaimedApproverID(string(r)); err != nil {
			t.Errorf("U+%04X, past a block, alone = %v, want it accepted", r, err)
		}
	}
}

// acceptedClaims are names in one script, or in a set UTS #39 allows
// together, that resemble nothing reserved. Each is its own case, so a rule
// that refuses one fails by name.
var acceptedClaims = map[string]string{
	"a Russian given name":                  "\u0412\u043b\u0430\u0434\u0438\u043c\u0438\u0440",
	"a Russian family name":                 "\u0411\u043e\u0440\u0438\u0441\u043e\u0432",
	"a Russian name and a colon":            "\u0411\u043e\u0440\u0438\u0441:42",
	"a Japanese name in Han and Hiragana":   "\u5c71\u7530\u592a\u90ce\u3055\u3093",
	"a Japanese name in Hiragana":           "\u3084\u307e\u3060\u305f\u308d\u3046",
	"a Korean name":                         "\uae40\ubbfc\uc900",
	"a Hebrew name with a space":            "\u05d3\u05d5\u05d3 \u05db\u05d4\u05df",
	"six Hebrew letters":                    "\u05d0\u05d1\u05d2\u05d3\u05d4\u05d5",
	"a Spanish name":                        "Jos\u00e9",
	"a precomposed diaeresis":               "zo\u00eb",
	"a combining diaeresis on a letter":     "zoe\u0308",
	"duty-officer":                          "duty-officer",
	"an email address":                      "alice@example.com",
	"authenticator":                         "authenticator",
	"Latin with Han, Hiragana and Katakana": "Tanaka \u7530\u4e2d\u3055\u3093 \u30ab\u30bf",
	"Latin with Han and Bopomofo":           "Wang \u738b\u3112\u3127\u3120",
	"Latin with Han and Hangul":             "Kim \u91d1\ubbfc\uc900",
	"a Japanese name with a long vowel":     "\u30bf\u30fc\u30ca\u30fc",
	"no id at all":                          "",
	"authn alone":                           "authn",
	"one letter short of the prefix":        "auth:x",
	"a letter between":                      "authnx:y",
	"the prefix after a letter":             "xauthn:y",
	"a hyphen for the colon":                "authn-x",
	"an ASCII space for the colon":          "authn x",
	"a semicolon for the colon":             "authn;x",
	"a full stop for the colon":             "authn.x",
	"a Polish name with a colon":            "\u0141ukasz:ops",
	"Latin with a stroke":                   "aut\u0127",
	"a Hebrew name after ASCII punctuation": "-\u05e9\u05dc\u05d5\u05dd",
}

func TestAClaimedApproverIDInOneScriptIsAccepted(t *testing.T) {
	for name, id := range acceptedClaims {
		if err := approval.CheckClaimedApproverID(id); err != nil {
			t.Errorf("%s (%+q): %v, want it accepted", name, id, err)
		}
	}
}

// documentedResidue are lookalikes the rule accepts and the documentation
// names: letters wholly of one script other than Latin, with no ASCII letter
// among the first six. What holds for them is that the plane never writes
// such an id, and a machine comparing bytes never takes one for "authn:".
var documentedResidue = map[string]string{
	"Lisu letters and an ASCII colon":     "\ua4ee\ua4f4\ua4d4\ua4e7\ua4e0:\ua4e7\ua4e0",
	"Cyrillic letters and an ASCII colon": "\u0430\u0443\u0442\u04bb\u043f:\u0445",
	"Lisu capitals in place of the colon": "\ua4ee\ua4f4\ua4d4\ua4e7\ua4e0\ua4fd\ua4e7",
}

// TestTheDocumentedResidueIsAccepted names what the rule lets through, so a
// change that narrows or widens it does so on purpose.
func TestTheDocumentedResidueIsAccepted(t *testing.T) {
	for name, id := range documentedResidue {
		if err := approval.CheckClaimedApproverID(id); err != nil {
			t.Errorf("%s (%+q): %v, want it accepted as the documented residue", name, id, err)
		}
	}
}

// TestTheConstructorBuildsTheReservedSpelling: the one way to the prefix
// writes it in ASCII, joins the issuer and the subject with one colon, and
// holds the whole to the approver id's bound.
func TestTheConstructorBuildsTheReservedSpelling(t *testing.T) {
	got, err := approval.AuthenticatedApproverID("okta", "alice@example.org")
	if err != nil || got != "authn:okta:alice@example.org" {
		t.Fatalf("AuthenticatedApproverID = %q, %v; want %q", got, err, "authn:okta:alice@example.org")
	}
	for subject, want := range map[string]string{
		"user:42":                        "authn:idp:user:42",
		"\u0411\u043e\u0440\u0438\u0441": "authn:idp:\u0411\u043e\u0440\u0438\u0441",
		"ali\u0307ce":                    "authn:idp:ali\u0307ce",
		"Ivan \u0418\u0432\u0430\u043d":  "authn:idp:Ivan \u0418\u0432\u0430\u043d",
	} {
		if got, err := approval.AuthenticatedApproverID("idp", subject); err != nil || got != want {
			t.Errorf("subject %+q = %q, %v; want %q", subject, got, err, want)
		}
	}
	if got, err := approval.AuthenticatedApproverID("my idp.example-1~", "x"); err != nil || got != "authn:my idp.example-1~:x" {
		t.Errorf("printable ASCII in the issuer = %q, %v; want it built", got, err)
	}
	// "authn:" is 6 bytes, the issuer 1 and its colon 1: a 120-byte subject
	// makes 128.
	if got, err := approval.AuthenticatedApproverID("i", strings.Repeat("s", 120)); err != nil || len(got) != 128 {
		t.Errorf("an id of exactly 128 bytes = %d bytes, %v; want it built", len(got), err)
	}
}

// TestTheConstructorRefusesWhatCannotBeAnApproverID: an issuer outside
// printable ASCII or with a colon, a subject that begins with a mark, which
// would sit on the separating colon, and a subject holding a code point a
// claim may not hold, are refused.
func TestTheConstructorRefusesWhatCannotBeAnApproverID(t *testing.T) {
	for name, c := range map[string]struct{ issuer, subject string }{
		"no issuer":                          {"", "alice"},
		"no subject":                         {"okta", ""},
		"an issuer with a colon":             {"ok:ta", "alice"},
		"an issuer with a fullwidth colon":   {"okta\uff1ax", "alice"},
		"an issuer with a Tibetan colon":     {"ok\u0f7fta", "alice"},
		"an issuer with an Ethiopic colon":   {"ok\u1365ta", "alice"},
		"an issuer with a braille blank":     {"ok\u2800ta", "alice"},
		"an issuer with a Latin letter":      {"\u00f6kta", "alice"},
		"an issuer with white space":         {" okta", "alice"},
		"a subject with a control":           {"okta", "ali\nce"},
		"a subject with a format":            {"okta", "ali\u202ece"},
		"a subject beginning with a dot":     {"okta", "\u0307alice"},
		"a subject beginning with a circle":  {"okta", "\u20ddalice"},
		"a subject beginning with a visarga": {"okta", "\u0903alice"},
		"a subject with a private-use point": {"okta", "ali\U000f0000ce"},
		"a subject with an unassigned point": {"okta", "ali\u0378ce"},
		"a subject with a noncharacter":      {"okta", "ali\ufffece"},
		"a subject with a null notehead":     {"okta", "ali\U0001d159ce"},
		"a subject with a braille blank":     {"okta", "ali\u2800ce"},
		"a subject with an object character": {"okta", "ali\ufffcce"},
		"an id of 129 bytes":                 {"i", strings.Repeat("s", 121)},
	} {
		got, err := approval.AuthenticatedApproverID(c.issuer, c.subject)
		if !errors.Is(err, approval.ErrAuthenticatedApprover) || got != "" {
			t.Errorf("%s: %q, %v; want nothing and %v", name, got, err, approval.ErrAuthenticatedApprover)
		}
	}
}
