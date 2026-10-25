package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"pgregory.net/rapid"
)

// Written as literals rather than as the package constants they mirror: a test
// that reads maxDepth and MaxSafeInteger from the implementation cannot notice
// the implementation changing them.
const (
	safeMax  = 9007199254740991  // 2^53-1
	safeMin  = -9007199254740991 // -(2^53-1)
	depthMax = 32
)

func TestCanonicalizeScalars(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"null", nil, "null"},
		{"true", true, "true"},
		{"false", false, "false"},
		{"empty string", "", `""`},
		{"string", "hello", `"hello"`},
		{"int zero", 0, "0"},
		{"int negative", -1, "-1"},
		{"int64", int64(1234567890), "1234567890"},
		{"uint64", uint64(1234567890), "1234567890"},
		{"json.Number integer", json.Number("1234567890"), "1234567890"},
		{"json.Number fraction", json.Number("0.10"), "0.1"},
		{"json.Number negative zero", json.Number("-0.0"), "0"},
		{"json.Number below 1e-6", json.Number("0.00000015"), "1.5e-7"},
		{"empty array", []any{}, "[]"},
		{"empty object", map[string]any{}, "{}"},
		{"array of scalars", []any{nil, true, "a", 1}, `[null,true,"a",1]`},
		{"array of empties", []any{[]any{}, map[string]any{}}, "[[],{}]"},
		{"object of empties", map[string]any{"a": []any{}, "b": map[string]any{}}, `{"a":[],"b":{}}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertCanonical(t, tc.value, tc.want)
		})
	}
}

func TestCanonicalizeKeyOrder(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		keys []string
		want string
	}{
		{"reversed", []string{"b", "a"}, `{"a":1,"b":0}`},
		{
			// RFC 8785 section 3.2.3: on a common prefix the shorter key wins.
			"common prefix",
			[]string{"aa", "a", "ab", "", "b"},
			`{"":3,"a":1,"aa":0,"ab":2,"b":4}`,
		},
		{
			// Space 0x20, digit 0x31, upper 0x42, underscore 0x5f, lower 0x61.
			// Not "a" beside "A": two keys that fold together are refused.
			"ascii classes",
			[]string{"a", "B", "1", "_", " "},
			`{" ":4,"1":2,"B":1,"_":3,"a":0}`,
		},
		{
			// The case UTF-8 byte order gets wrong: U+1F600 is the surrogate
			// pair D83D DE00, so it sorts below U+E000 and U+FFFD as UTF-16
			// code units and above both as UTF-8 bytes.
			"astral before private use and replacement",
			[]string{"\uFFFD", "\uE000", "\U0001F600", "z"},
			"{\"z\":3,\"\U0001F600\":2,\"\uE000\":1,\"\uFFFD\":0}",
		},
		{
			"astral after bmp below the surrogate block",
			[]string{"\U0001F600", "\u4E00"},
			"{\"\u4E00\":1,\"\U0001F600\":0}",
		},
		{
			"two astral keys differ in the low surrogate",
			[]string{"\U0001F601", "\U0001F600"},
			"{\"\U0001F600\":1,\"\U0001F601\":0}",
		},
		{
			"astral against bmp after a common prefix",
			[]string{"a\uFFFD", "a\U0001F600", "a"},
			"{\"a\":2,\"a\U0001F600\":1,\"a\uFFFD\":0}",
		},
		{
			// A key is escaped exactly like any other string.
			"control character in a key",
			[]string{"a\nb", "a\tb"},
			`{"a\tb":1,"a\nb":0}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertCanonical(t, objectOf(tc.keys), tc.want)
		})
	}
}

// TestKeyOrderIsUTF16NotUTF8 is the one test a sort.Strings implementation
// fails. It refuses to run on a fixture where the two orders agree, so it
// cannot pass by accident on keys from the basic multilingual plane.
func TestKeyOrderIsUTF16NotUTF8(t *testing.T) {
	t.Parallel()

	keys := []string{"\U0001F600", "\uE000", "\uFFFD"}

	utf16Order := slices.Clone(keys)
	slices.SortFunc(utf16Order, func(a, b string) int {
		return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
	})
	utf8Order := slices.Clone(keys)
	slices.Sort(utf8Order) // Go compares strings as bytes.

	if slices.Equal(utf16Order, utf8Order) {
		t.Fatalf("degenerate fixture: UTF-16 and UTF-8 order agree on %q, so this test cannot fail", keys)
	}

	out, err := Canonicalize(objectOf(keys))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	got := keysInOrder(t, out)

	if !slices.Equal(got, utf16Order) {
		t.Errorf("key order\n got %q\nwant %q (UTF-16 code units)", got, utf16Order)
	}
	if slices.Equal(got, utf8Order) {
		t.Errorf("keys came out in UTF-8 byte order %q; RFC 8785 sorts UTF-16 code units", got)
	}
}

func TestCanonicalizeStringEscaping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"space stays literal", " ", `" "`},
		{"space inside a word", "a b", `"a b"`},
		{"solidus is not escaped", "/", `"/"`},
		{"path is not escaped", "a/b/c", `"a/b/c"`},
		// The characters an HTML-safe encoder escapes: Go's json.Marshal the
		// first three, Gson all five. RFC 8785 keeps each literal.
		{"less-than is literal", "<", `"<"`},
		{"greater-than is literal", ">", `">"`},
		{"ampersand is literal", "&", `"&"`},
		{"equals sign is literal", "=", `"="`},
		{"apostrophe is literal", "'", `"'"`},
		{"markup is literal", "<a href='x?b=1&c=2'>", `"<a href='x?b=1&c=2'>"`},
		{"quote", `a"b`, `"a\"b"`},
		{"reverse solidus", `a\b`, `"a\\b"`},
		{"escaped quote survives one round", `\"`, `"\\\""`},
		{"nul", "\x00", `"\u0000"`},
		{"u0001", "\x01", `"\u0001"`},
		{"u001f is lowercase hex", "\x1f", `"\u001f"`},
		{"u000b is not one of the five named", "\v", `"\u000b"`},
		{"u000e", "\x0e", `"\u000e"`},
		{"backspace", "\b", `"\b"`},
		{"tab", "\t", `"\t"`},
		{"newline", "\n", `"\n"`},
		{"form feed", "\f", `"\f"`},
		{"carriage return", "\r", `"\r"`},
		{"all five named controls", "\b\t\n\f\r", `"\b\t\n\f\r"`},
		{"delete is literal", "\x7f", "\"\x7f\""},
		{"latin small e with acute is literal", "\u00e9", "\"\u00e9\""},
		{"astral is literal", "\U0001F600", "\"\U0001F600\""},
		{"byte order mark is literal", "\uFEFF", "\"\uFEFF\""},
		{"line separator is literal", "\u2028", "\"\u2028\""},
		{"replacement character is literal", "\uFFFD", "\"\uFFFD\""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertCanonical(t, tc.value, tc.want)
		})
	}
}

// TestNonASCIIStaysUTF8 pins the bytes, because "the character is literal" is
// also true of an implementation that emits \u00e9 in some other encoding.
func TestNonASCIIStaysUTF8(t *testing.T) {
	t.Parallel()

	out, err := Canonicalize("\u00e9\U0001F600")
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := []byte{'"', 0xc3, 0xa9, 0xf0, 0x9f, 0x98, 0x80, '"'}
	if !bytes.Equal(out, want) {
		t.Errorf("bytes\n got % x\nwant % x", out, want)
	}
}

func TestCanonicalizeIntegerRange(t *testing.T) {
	t.Parallel()

	accepted := []struct {
		name  string
		value any
		want  string
	}{
		{"int64 upper bound", int64(safeMax), "9007199254740991"},
		{"int64 lower bound", int64(safeMin), "-9007199254740991"},
		{"uint64 upper bound", uint64(safeMax), "9007199254740991"},
		{"int64 zero", int64(0), "0"},
		{"uint64 zero", uint64(0), "0"},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertCanonical(t, tc.value, tc.want)
		})
	}

	// int reaches the same range check as int64, so the oversized cases are
	// written as int64 and stay compilable on a 32-bit platform.
	rejected := []struct {
		name  string
		value any
	}{
		{"2^53", int64(safeMax + 1)},
		{"-2^53", int64(safeMin - 1)},
		{"max int64", int64(math.MaxInt64)},
		{"min int64", int64(math.MinInt64)},
		{"uint64 2^53", uint64(safeMax + 1)},
		{"max uint64", uint64(math.MaxUint64)},
	}
	for _, tc := range rejected {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			t.Parallel()
			assertRefused(t, tc.value, ErrUnsupportedValue)
		})
	}
}

func TestCanonicalizeRejectsUnsupportedTypes(t *testing.T) {
	t.Parallel()

	type unexported struct{ A int }
	number := 1

	cases := []struct {
		name  string
		value any
	}{
		{"float with a fraction", 1.5},
		{"integral float64", float64(3)},
		{"zero float64", float64(0)},
		{"negative zero float64", math.Copysign(0, -1)},
		{"float32", float32(1.5)},
		{"nan", math.NaN()},
		{"positive infinity", math.Inf(1)},
		{"negative infinity", math.Inf(-1)},
		{"json.Number with a leading plus", json.Number("+1")},
		{"json.Number with a leading zero", json.Number("01")},
		{"json.Number with a bare fraction", json.Number(".5")},
		{"json.Number with a trailing point", json.Number("1.")},
		{"json.Number in hex", json.Number("0x10")},
		{"json.Number with an underscore", json.Number("1_000")},
		{"json.Number with a space", json.Number(" 1")},
		{"json.Number that is empty", json.Number("")},
		{"json.Number NaN", json.Number("NaN")},
		{"json.Number Infinity", json.Number("Infinity")},
		{"json.Number with an empty exponent", json.Number("1e")},
		{"json.Number over 2^53-1", json.Number("9007199254740992")},
		{"json.Number past a double", json.Number("1e400")},
		{"json.Number no double holds exactly", json.Number("4.9e-324")},
		{"int8", int8(1)},
		{"int32", int32(1)},
		{"uint", uint(1)},
		{"uint32", uint32(1)},
		{"typed string", json.RawMessage(`1`)},
		{"slice of string", []string{"a"}},
		{"map of string to string", map[string]string{"a": "b"}},
		{"non-string map key", map[int]any{1: 2}},
		{"struct", unexported{A: 1}},
		{"pointer", &number},
		{"nil pointer", (*int)(nil)},
		{"channel", make(chan int)},
		{"string that is not valid UTF-8", "\xff"},
		{"string with a truncated sequence", "a\xc3"},
		// A lone surrogate is the interesting one: a JavaScript string can hold
		// U+D800, so an implementation that let these bytes through would emit
		// something another language escapes differently, or not at all.
		{"string encoding a lone surrogate", "\xed\xa0\x80"},
		{"string with an overlong encoding", "\xc0\x80"},
		{"string beyond the Unicode maximum", "\xf4\x90\x80\x80"},
		{"key encoding a lone surrogate", map[string]any{"\xed\xa0\x80": 1}},
		{"float inside an array", []any{1.5}},
		{"float inside an object", map[string]any{"a": map[string]any{"b": 1.5}}},
		{"object key that is not valid UTF-8", map[string]any{"\xff": 1}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertRefused(t, tc.value, ErrUnsupportedValue)
		})
	}
}

// TestCanonicalizeDepthBoundary proves both sides: 32 containers encode, 33 are
// refused. A test that only checked 33 would pass with the limit set to 1.
func TestCanonicalizeDepthBoundary(t *testing.T) {
	t.Parallel()

	t.Run("arrays at the limit", func(t *testing.T) {
		t.Parallel()
		want := strings.Repeat("[", depthMax) + "1" + strings.Repeat("]", depthMax)
		assertCanonical(t, nestArrays(depthMax), want)
	})

	t.Run("objects at the limit", func(t *testing.T) {
		t.Parallel()
		want := strings.Repeat(`{"a":`, depthMax) + "1" + strings.Repeat("}", depthMax)
		assertCanonical(t, nestObjects(depthMax), want)
	})

	t.Run("arrays one past the limit", func(t *testing.T) {
		t.Parallel()
		assertRefused(t, nestArrays(depthMax+1), ErrTooDeep)
	})

	t.Run("objects one past the limit", func(t *testing.T) {
		t.Parallel()
		assertRefused(t, nestObjects(depthMax+1), ErrTooDeep)
	})

	t.Run("mixed containers one past the limit", func(t *testing.T) {
		t.Parallel()
		mixed := any(1)
		for i := 0; i < depthMax+1; i++ {
			if i%2 == 0 {
				mixed = []any{mixed}
				continue
			}
			mixed = map[string]any{"a": mixed}
		}
		assertRefused(t, mixed, ErrTooDeep)
	})

	// The decoder has a nesting limit of its own, an order of magnitude deeper.
	// Reaching it first would report a parse failure for a document this package
	// has its own answer for.
	t.Run("json deeper than the decoder's own limit", func(t *testing.T) {
		t.Parallel()
		const beyond = 10001
		deep := map[string]string{
			"arrays":  strings.Repeat("[", beyond) + "1" + strings.Repeat("]", beyond),
			"objects": strings.Repeat(`{"a":`, beyond) + "1" + strings.Repeat("}", beyond),
		}
		for shape, raw := range deep {
			if _, err := CanonicalizeJSON([]byte(raw)); !errors.Is(err, ErrTooDeep) {
				t.Errorf("CanonicalizeJSON on %d nested %s: err = %v, want ErrTooDeep", beyond, shape, err)
			}
		}
	})

	t.Run("json at and past the limit", func(t *testing.T) {
		t.Parallel()
		at := strings.Repeat("[", depthMax) + "1" + strings.Repeat("]", depthMax)
		if _, err := CanonicalizeJSON([]byte(at)); err != nil {
			t.Errorf("CanonicalizeJSON at depth %d: %v", depthMax, err)
		}
		past := strings.Repeat("[", depthMax+1) + "1" + strings.Repeat("]", depthMax+1)
		if _, err := CanonicalizeJSON([]byte(past)); !errors.Is(err, ErrTooDeep) {
			t.Errorf("CanonicalizeJSON at depth %d: err = %v, want ErrTooDeep", depthMax+1, err)
		}
	})
}

func TestRefusalNamesTheValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"root", 1.5, `at ""`},
		{"object member", map[string]any{"args": map[string]any{"temperature": 1.5}}, `at "/args/temperature"`},
		{"array element", []any{[]any{nil, 1.5}}, `at "/0/1"`},
		{"pointer escapes", map[string]any{"a/b~c": 1.5}, `at "/a~1b~0c"`},
		{"depth names the container", nestArrays(depthMax + 1), `at "` + strings.Repeat("/0", depthMax) + `"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Canonicalize(tc.value)
			if err == nil {
				t.Fatalf("Canonicalize(%v) = nil error, want a refusal", tc.value)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %s", err, tc.want)
			}
		})
	}
}

// canonicalizeJSONCases doubles as the fuzz seed corpus; see fuzz_test.go.
var canonicalizeJSONCases = []struct {
	name string
	raw  string
	want string
}{
	{"whitespace is removed", " { \"b\" : 1 , \"a\" : [ 1 , 2 ] } ", `{"a":[1,2],"b":1}`},
	{"newlines and tabs between tokens", "{\n\t\"a\"\t:\r\n1\n}", `{"a":1}`},
	{"empty containers", "[[],{}]", "[[],{}]"},
	{"null", "null", "null"},
	{"true", "true", "true"},
	{"false", "false", "false"},
	{"escaped ascii is unescaped", `"\u0041"`, `"A"`},
	{"escaped solidus is unescaped", `"\/"`, `"/"`},
	{"escaped non-ascii becomes utf-8", `"\u00e9"`, "\"\u00e9\""},
	{"surrogate pair becomes one character", `"\ud83d\ude00"`, "\"\U0001F600\""},
	{"surrogate pair in upper case hex", `"\uD83D\uDE00"`, "\"\U0001F600\""},
	{"two surrogate pairs in a row", `"\ud83d\ude00\ud83d\ude01"`, "\"\U0001F600\U0001F601\""},
	{"escape after an escape", `"\u0041\u0042"`, `"AB"`},
	// RFC 8785 does not normalize, so the composed and decomposed forms of the
	// same character are two keys. U+0065 sorts before U+00E9.
	{"no unicode normalization", "{\"\u00e9\":1,\"e\u0301\":2}", "{\"e\u0301\":2,\"\u00e9\":1}"},
	{"escaped replacement character", `"\ufffd"`, "\"\uFFFD\""},
	// The backslash is escaped, so \ud800 here is six literal characters and
	// not an escape at all: the surrogate scan must not fire on it.
	{"escaped backslash before a surrogate escape", `"\\ud800"`, `"\\ud800"`},
	{"four backslashes before ud800", `"\\\\ud800"`, `"\\\\ud800"`},
	{"control characters are re-escaped", `"\u0000\u001F\u000B"`, `"\u0000\u001f\u000b"`},
	{"named escapes are kept named", `"\b\t\n\f\r"`, `"\b\t\n\f\r"`},
	{"negative zero is zero", "-0", "0"},
	{"fraction", "1.5", "1.5"},
	{"integral fraction", "1.0", "1"},
	{"exponent", "1e3", "1000"},
	{"upper case exponent", "1E3", "1000"},
	{"negative exponent", "-1.5e-3", "-0.0015"},
	{"zero point zero", "0.0", "0"},
	{"negative zero point zero", "-0.0", "0"},
	{"below 1e-6 the exponent form", "0.00000015", "1.5e-7"},
	{"fraction in a nested object", `{"a":{"b":1.5}}`, `{"a":{"b":1.5}}`},
	{"fraction in an array", `[1,2.5]`, `[1,2.5]`},
	{"upper bound integer", "9007199254740991", "9007199254740991"},
	{"lower bound integer", "-9007199254740991", "-9007199254740991"},
	{"astral keys sort by code unit", "{\"\uFFFD\":0,\"\uE000\":1,\"\U0001F600\":2}", "{\"\U0001F600\":2,\"\uE000\":1,\"\uFFFD\":0}"},
	{"nested objects sort at every level", `{"b":{"d":1,"c":2},"a":3}`, `{"a":3,"b":{"c":2,"d":1}}`},
	{"array order is preserved", `[3,1,2]`, `[3,1,2]`},
}

func TestCanonicalizeJSON(t *testing.T) {
	t.Parallel()

	for _, tc := range canonicalizeJSONCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := CanonicalizeJSON([]byte(tc.raw))
			if err != nil {
				t.Fatalf("CanonicalizeJSON(%q): %v", tc.raw, err)
			}
			if string(got) != tc.want {
				t.Errorf("CanonicalizeJSON(%q)\n got %q\nwant %q", tc.raw, got, tc.want)
			}
		})
	}
}

// canonicalizeJSONRejections also seeds the fuzz target: refused inputs are
// where a panic would live.
var canonicalizeJSONRejections = []struct {
	name     string
	raw      string
	sentinel error // nil means any error, for the parse failures
}{
	{"fraction no double holds exactly", "0.30000000000000001", ErrUnsupportedValue},
	{"integral fraction over 2^53-1", "9007199254740992.0", ErrUnsupportedValue},
	{"exponent over 2^53-1", "1e16", ErrUnsupportedValue},
	{"upper case exponent over 2^53-1", "1E16", ErrUnsupportedValue},
	{"negative exponent below a double", "-1.5e-400", ErrUnsupportedValue},
	{"below the smallest double's shortest decimal", "4.9e-324", ErrUnsupportedValue},
	{"2^53", "9007199254740992", ErrUnsupportedValue},
	{"-2^53", "-9007199254740992", ErrUnsupportedValue},
	{"beyond int64", "123456789012345678901234567890", ErrUnsupportedValue},
	{"inexact fraction in a nested object", `{"a":{"b":0.10000000000000001}}`, ErrUnsupportedValue},
	{"number past a double in an array", `[1,2.5e400]`, ErrUnsupportedValue},
	// encoding/json turns each of these into U+FFFD; JavaScript and Python keep
	// the code unit, so the document has two canonical forms and is refused.
	{"unpaired high surrogate escape", `"\ud800"`, ErrUnsupportedValue},
	{"unpaired low surrogate escape", `"\udc00"`, ErrUnsupportedValue},
	{"unpaired surrogate in upper case hex", `"\uD800"`, ErrUnsupportedValue},
	{"high surrogate followed by another high surrogate", `"\ud83d\ud83d"`, ErrUnsupportedValue},
	{"high surrogate at the end of a string", `"\ud83d"`, ErrUnsupportedValue},
	{"surrogate escape in a key", `{"\ud800":1}`, ErrUnsupportedValue},
	{"odd run of backslashes before a surrogate escape", `"\\\ud800"`, ErrUnsupportedValue},
	// A skip that is one byte too wide after a pair, or after any \u escape,
	// walks past the start of the next one and lets it through.
	{"valid pair then an unpaired surrogate", `"\ud83d\ude00\ud800"`, ErrUnsupportedValue},
	{"unpaired surrogate after a pair in a key", `{"\ud83d\ude00\ud800":1}`, ErrUnsupportedValue},
	{"unpaired surrogate after a plain escape", `"\u0041\ud800"`, ErrUnsupportedValue},
	{"escaped backslash then an unpaired low surrogate", `"\\ud83d\ude00"`, ErrUnsupportedValue},
	// Two documents with one canonical form is the only collision this package
	// can produce, so the second occurrence of a key is refused, not resolved.
	{"duplicate key", `{"a":1,"a":2}`, ErrUnsupportedValue},
	{"duplicate key with different magnitudes", `{"amount":1,"amount":1000000}`, ErrUnsupportedValue},
	{"duplicate key holding objects", `{"a":{"x":1},"a":{"y":2}}`, ErrUnsupportedValue},
	{"duplicate key nested one level down", `{"a":{"b":1,"b":2}}`, ErrUnsupportedValue},
	{"duplicate empty key", `{"":1,"":2}`, ErrUnsupportedValue},
	{"duplicate key with identical values", `{"a":1,"a":1}`, ErrUnsupportedValue},
	{"input that is not valid UTF-8", "\"\xff\"", nil},
	{"key that is not valid UTF-8", "{\"\xff\":1}", nil},
	{"empty input", "", nil},
	{"only whitespace", "   ", nil},
	{"unterminated object", "{", nil},
	{"unterminated array", "[1,", nil},
	{"truncated literal", "nul", nil},
	{"bare word", "abc", nil},
	{"trailing value", `{"a":1}{"b":2}`, nil},
	{"trailing garbage", `{"a":1}x`, nil},
	{"trailing array", `[1] [2]`, nil},
	{"single quotes", `{'a':1}`, nil},
	{"trailing comma", `{"a":1,}`, nil},
}

func TestCanonicalizeJSONRejects(t *testing.T) {
	t.Parallel()

	for _, tc := range canonicalizeJSONRejections {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := CanonicalizeJSON([]byte(tc.raw))
			if err == nil {
				t.Fatalf("CanonicalizeJSON(%q) = %q, want a refusal", tc.raw, got)
			}
			if got != nil {
				t.Errorf("CanonicalizeJSON(%q) returned %q with an error", tc.raw, got)
			}
			if tc.sentinel != nil && !errors.Is(err, tc.sentinel) {
				t.Errorf("CanonicalizeJSON(%q): err = %v, want %v", tc.raw, err, tc.sentinel)
			}
		})
	}
}

// TestCanonicalizeJSONNamesTheValue checks the reason as well as the pointer.
// A float reported as an out-of-range integer sends whoever is debugging a
// refused envelope after the wrong thing, and the two rules have different
// answers: an argument gets rounded, an identifier gets sent as a string.
func TestCanonicalizeJSONNamesTheValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		pointer string
		reason  string
	}{
		{"inexact fraction argument", `{"b":1,"args":{"temperature":0.70000000000000001}}`, `at "/args/temperature"`, "not exactly the shortest decimal of a double"},
		{"integral fraction over 2^53-1", `{"a":[9007199254740992.0]}`, `at "/a/0"`, "outside the JSON-safe range"},
		{"exponent past a double", `{"a":1e400}`, `at "/a"`, "outside the range of a double"},
		{"exponent below a double", `{"a":1e-400}`, `at "/a"`, "outside the range of a double"},
		{"oversized integer", `{"budgets":{"tokens":9007199254740992}}`, `at "/budgets/tokens"`, "outside the JSON-safe range"},
		{"integer beyond int64", `[123456789012345678901234567890]`, `at "/0"`, "outside the JSON-safe range"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := CanonicalizeJSON([]byte(tc.raw))
			if err == nil {
				t.Fatalf("CanonicalizeJSON(%q) = nil error, want a refusal", tc.raw)
			}
			if !strings.Contains(err.Error(), tc.pointer) {
				t.Errorf("error %q does not name %s", err, tc.pointer)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("error %q does not give the reason %q", err, tc.reason)
			}
		})
	}
}

// TestCanonicalizeIsIdempotent runs the value through both entry points:
// parsing canonical output and canonicalizing it again must return the same
// bytes, or the form is not a fixed point and no digest over it is stable.
func TestCanonicalizeIsIdempotent(t *testing.T) {
	t.Parallel()

	values := []any{
		nil,
		true,
		"a\tb\u00e9\U0001F600",
		int64(safeMax),
		int64(safeMin),
		json.Number("0.7"),
		json.Number("5e-324"),
		[]any{},
		map[string]any{},
		map[string]any{"\uFFFD": 1, "\uE000": 2, "\U0001F600": 3, "a": []any{nil, "\x00", int64(0)}},
		nestArrays(depthMax),
		nestObjects(depthMax),
	}

	for i, v := range values {
		first, err := Canonicalize(v)
		if err != nil {
			t.Fatalf("value %d: Canonicalize: %v", i, err)
		}
		second, err := CanonicalizeJSON(first)
		if err != nil {
			t.Fatalf("value %d: CanonicalizeJSON(%q): %v", i, first, err)
		}
		if !bytes.Equal(first, second) {
			t.Errorf("value %d is not a fixed point\n first %q\nsecond %q", i, first, second)
		}
	}
}

// TestRefusalIsDeterministic pins which value a refusal names when one object
// holds several that could be refused. The encoder walks canonical key order,
// the parser walks document order, and both are fixed by the input; a walk over
// a Go map would name a different one from run to run.
func TestRefusalIsDeterministic(t *testing.T) {
	t.Parallel()

	const runs = 200

	t.Run("encoder names the first key in canonical order", func(t *testing.T) {
		t.Parallel()
		for range runs {
			_, err := Canonicalize(map[string]any{"b": 1.5, "a": 2.5, "c": 3.5})
			if err == nil {
				t.Fatal("Canonicalize accepted an object of floats")
			}
			if !strings.Contains(err.Error(), `at "/a"`) {
				t.Fatalf("refusal %q does not name /a, the first key in canonical order", err)
			}
		}
	})

	t.Run("parser names the first key in document order", func(t *testing.T) {
		t.Parallel()
		for range runs {
			_, err := CanonicalizeJSON([]byte(`{"b":1e400,"a":2e400,"c":3e400}`))
			if err == nil {
				t.Fatal("CanonicalizeJSON accepted an object of numbers past a double")
			}
			if !strings.Contains(err.Error(), `at "/b"`) {
				t.Fatalf("refusal %q does not name /b, the first key in document order", err)
			}
		}
	})
}

// TestRefusalCarriesNoContent keeps the refused value out of the message. A
// refusal travels into logs and evidence, where captured content does not
// belong by default (invariant 9), and neither a number literal nor a string
// has a length limit.
func TestRefusalCarriesNoContent(t *testing.T) {
	t.Parallel()

	const (
		secret   = "CONTENT-THAT-MUST-NEVER-REACH-A-REFUSAL"
		maxBytes = 200
	)
	long := strings.Repeat("9", 100001)

	cases := []struct {
		name  string
		fail  func() error
		avoid string
	}{
		{
			"string that is not valid UTF-8",
			func() error { _, err := Canonicalize(map[string]any{"token": secret + "\xff"}); return err },
			secret,
		},
		{
			"object key that is not valid UTF-8",
			func() error { _, err := Canonicalize(map[string]any{secret + "\xff": 1}); return err },
			secret,
		},
		{
			"long string that is not valid UTF-8",
			func() error { _, err := Canonicalize(strings.Repeat("a", 60000) + "\xff"); return err },
			strings.Repeat("a", 64),
		},
		{
			"integer out of range",
			func() error { _, err := Canonicalize(int64(math.MaxInt64)); return err },
			"9223372036854775807",
		},
		{
			"long number literal",
			func() error { _, err := CanonicalizeJSON([]byte(`{"n":` + long + `}`)); return err },
			strings.Repeat("9", 64),
		},
		{
			"inexact fraction literal",
			func() error {
				_, err := CanonicalizeJSON([]byte(`{"temperature":0.70000000000000001}`))
				return err
			},
			"0.7",
		},
		{
			"long inexact fraction literal",
			func() error { _, err := CanonicalizeJSON([]byte(`{"n":0.` + long + `}`)); return err },
			strings.Repeat("9", 64),
		},
		{
			"long exponent",
			func() error { _, err := CanonicalizeJSON([]byte(`{"n":1e-` + long + `}`)); return err },
			strings.Repeat("9", 64),
		},
		{
			"duplicate key",
			func() error {
				_, err := CanonicalizeJSON([]byte(`{"` + secret + `":1,"` + secret + `":2}`))
				return err
			},
			secret,
		},
		{
			"unpaired surrogate escape",
			func() error { _, err := CanonicalizeJSON([]byte(`{"a":"` + secret + `\ud800"}`)); return err },
			secret,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.fail()
			if err == nil {
				t.Fatal("want a refusal")
			}
			if strings.Contains(err.Error(), tc.avoid) {
				t.Errorf("refusal %q carries the refused content", err)
			}
			if len(err.Error()) > maxBytes {
				t.Errorf("refusal is %d bytes, want at most %d: %q", len(err.Error()), maxBytes, err)
			}
		})
	}
}

// TestDuplicateKeyRefusalNamesThePosition checks the object and the member
// ordinal, which is what a reader needs to find the second occurrence without
// the message repeating the key back.
func TestDuplicateKeyRefusalNamesThePosition(t *testing.T) {
	t.Parallel()

	_, err := CanonicalizeJSON([]byte(`{"args":{"a":1,"b":2,"a":3}}`))
	if err == nil {
		t.Fatal("CanonicalizeJSON accepted a duplicate key")
	}
	if !errors.Is(err, ErrUnsupportedValue) {
		t.Errorf("err = %v, want ErrUnsupportedValue", err)
	}
	for _, want := range []string{`at "/args"`, "duplicate object key at member 2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not carry %q", err, want)
		}
	}
}

// interestingRunes seeds the generated strings with the characters the rules
// single out, so the property test does not spend its budget on letters.
var interestingRunes = []rune{
	' ', '"', '\\', '/', '~', 0x00, 0x01, 0x1f, '\b', '\t', '\n', '\f', '\r',
	0x7f, 'a', 'A', '0', '\u00e9', '\u4e00', '\uE000', '\uFEFF', '\uFFFD',
	'\U0001F600', '\U0001F601', '\U00010000', '\U0010FFFF',
}

func TestCanonicalizeProperties(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		value := drawValue(rt, 0)

		out, err := Canonicalize(value)
		if err != nil {
			rt.Fatalf("Canonicalize refused a supported value: %v", err)
		}
		if !json.Valid(out) {
			rt.Fatalf("output is not valid JSON: %q", out)
		}

		again, err := CanonicalizeJSON(out)
		if err != nil {
			rt.Fatalf("CanonicalizeJSON refused canonical output %q: %v", out, err)
		}
		if !bytes.Equal(out, again) {
			rt.Fatalf("not a fixed point\n first %q\nsecond %q", out, again)
		}
		if bytes.ContainsAny(out, "\n\t\r") {
			rt.Fatalf("output carries whitespace between tokens: %q", out)
		}
	})
}

func drawValue(rt *rapid.T, depth int) any {
	kinds := []string{"null", "bool", "int64", "uint64", "string"}
	if depth < 3 {
		kinds = append(kinds, "array", "object")
	}

	switch rapid.SampledFrom(kinds).Draw(rt, "kind") {
	case "null":
		return nil
	case "bool":
		return rapid.Bool().Draw(rt, "bool")
	case "int64":
		return rapid.Int64Range(safeMin, safeMax).Draw(rt, "int64")
	case "uint64":
		return rapid.Uint64Range(0, safeMax).Draw(rt, "uint64")
	case "string":
		return drawString(rt)
	case "array":
		items := make([]any, rapid.IntRange(0, 4).Draw(rt, "len"))
		for i := range items {
			items[i] = drawValue(rt, depth+1)
		}
		return items
	default:
		members := map[string]any{}
		for range rapid.IntRange(0, 4).Draw(rt, "size") {
			key := drawString(rt)
			// Keys that fold together are refused; this property is about
			// the values the canonical form accepts.
			if foldsWithAny(members, key) {
				continue
			}
			members[key] = drawValue(rt, depth+1)
		}
		return members
	}
}

// foldsWithAny is written with strings.EqualFold rather than the package's own
// fold key, so the generator does not share the rule it feeds.
func foldsWithAny(members map[string]any, key string) bool {
	for existing := range members {
		if existing != key && strings.EqualFold(existing, key) {
			return true
		}
	}
	return false
}

func drawString(rt *rapid.T) string {
	return rapid.OneOf(
		rapid.StringOf(rapid.SampledFrom(interestingRunes)),
		rapid.String(),
	).Draw(rt, "string")
}

func assertCanonical(t *testing.T, value any, want string) {
	t.Helper()

	got, err := Canonicalize(value)
	if err != nil {
		t.Fatalf("Canonicalize(%#v): %v", value, err)
	}
	if string(got) != want {
		t.Errorf("Canonicalize(%#v)\n got %q\nwant %q", value, got, want)
	}
	if !json.Valid(got) {
		t.Errorf("Canonicalize(%#v) = %q, which is not valid JSON", value, got)
	}
}

func assertRefused(t *testing.T, value any, want error) {
	t.Helper()

	got, err := Canonicalize(value)
	if err == nil {
		t.Fatalf("Canonicalize(%#v) = %q, want a refusal", value, got)
	}
	if !errors.Is(err, want) {
		t.Errorf("Canonicalize(%#v): err = %v, want %v", value, err, want)
	}
	if got != nil {
		t.Errorf("Canonicalize(%#v) returned %q with an error", value, got)
	}
}

// objectOf builds an object whose value at keys[i] is i, so the expected
// output records where each key moved to.
func objectOf(keys []string) map[string]any {
	m := make(map[string]any, len(keys))
	for i, key := range keys {
		m[key] = i
	}
	return m
}

func nestArrays(n int) any {
	var v any = 1
	for range n {
		v = []any{v}
	}
	return v
}

func nestObjects(n int) any {
	var v any = 1
	for range n {
		v = map[string]any{"a": v}
	}
	return v
}

// keysInOrder returns the keys of a JSON object in the order they appear, read
// with the token stream because a map would lose exactly what is under test.
func keysInOrder(t testing.TB, raw []byte) []string {
	t.Helper()

	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("keysInOrder: %q does not start an object (%v, %v)", raw, tok, err)
	}

	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("keysInOrder: reading a key of %q: %v", raw, err)
		}
		key, ok := tok.(string)
		if !ok {
			t.Fatalf("keysInOrder: key of %q is %T, not a string", raw, tok)
		}
		keys = append(keys, key)

		var discard any
		if err := dec.Decode(&discard); err != nil {
			t.Fatalf("keysInOrder: reading the value at %q of %q: %v", key, raw, err)
		}
	}
	return keys
}
