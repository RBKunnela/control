package testreport

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// ErrExpectedSkips is returned for a list of expected skips that is not one
// entry per line, or that names a test twice.
var ErrExpectedSkips = errors.New("testreport: a malformed list of expected skips")

// Skip names one test, subtest or fuzz seed of one package.
type Skip struct {
	Package, Test string
}

// ExpectedSkips maps each test the repository expects some run to skip to
// text its skip message holds, so a test that starts skipping for another
// reason is refused like an unlisted one. A nil or empty set expects none.
type ExpectedSkips map[Skip]string

// testPrefixes are the names go test runs; anything else in the test column
// is a swapped or mistyped field.
var testPrefixes = []string{"Test", "Fuzz", "Example", "Benchmark"}

// ParseExpectedSkips reads one entry per line, "<import path> <test name>
// <message>" with a single space between the fields and the message the rest
// of the line: text the test's skip message must hold. A line that starts with "#" and a blank line are ignored. A line
// with an empty field, white space inside the import path or the test name, a
// test name go test does not give, or a test named a second time is refused
// with ErrExpectedSkips.
func ParseExpectedSkips(text []byte) (ExpectedSkips, error) {
	set := ExpectedSkips{}
	n := 0
	for line := range strings.Lines(string(text)) {
		n++
		line = strings.TrimSuffix(line, "\n")
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		pkg, rest, _ := strings.Cut(line, " ")
		test, reason, _ := strings.Cut(rest, " ")
		reason = strings.TrimSpace(reason)
		switch {
		case pkg == "" || test == "" || reason == "":
			return nil, fmt.Errorf("%w: line %d is not <import path> <test name> <reason>", ErrExpectedSkips, n)
		case strings.ContainsFunc(pkg+test, unicode.IsSpace):
			return nil, fmt.Errorf("%w: line %d holds white space in its import path or test name", ErrExpectedSkips, n)
		case !hasTestPrefix(test):
			return nil, fmt.Errorf("%w: line %d names %q, which is no test go test runs", ErrExpectedSkips, n, test)
		}
		key := Skip{pkg, test}
		if _, ok := set[key]; ok {
			return nil, fmt.Errorf("%w: line %d names %s %s a second time", ErrExpectedSkips, n, pkg, test)
		}
		set[key] = reason
	}
	return set, nil
}

func hasTestPrefix(test string) bool {
	for _, p := range testPrefixes {
		if strings.HasPrefix(test, p) {
			return true
		}
	}
	return false
}

// skipLine is the last line test printed before it skipped, which is what
// t.Skip wrote; a line t.Log wrote earlier says nothing about why it skipped.
func (p *pkgState) skipLine(test string) string {
	parts := p.outputOf(test)
	if len(parts) == 0 {
		return "(no message)"
	}
	return parts[len(parts)-1]
}

// skip records one skipped test and judges it, by the line it skipped with,
// against the expected set.
func (rep *reporter) skip(pkg, test, message, line string) {
	rep.sum.Skipped++
	rep.skips = append(rep.skips, skipped{pkg, test, message})
	key := Skip{pkg, test}
	rep.didSkip[key] = true
	switch want, ok := rep.expected[key]; {
	case !ok:
		rep.sum.Unexpected++
		rep.surprises = append(rep.surprises, pkg+" "+test)
	case !strings.Contains(line, want):
		rep.sum.Unexpected++
		rep.surprises = append(rep.surprises, fmt.Sprintf("%s %s, whose message does not hold %q", pkg, test, want))
	}
}

// writeExpectedRan names, in order, each expected skip whose package reached
// a result in this stream without that test skipping: one that ran, and one
// that never started, which a rename, a removal or a platform's build leaves.
// A package the stream never reached says nothing about its tests, so it is
// not named.
func (rep *reporter) writeExpectedRan() {
	var lines []string
	for key := range rep.expected {
		switch {
		case !rep.finished[key.Package] || rep.didSkip[key]:
		case rep.seen[key]:
			lines = append(lines, "RAN "+key.Package+" "+key.Test)
		default:
			lines = append(lines, "ABSENT "+key.Package+" "+key.Test)
		}
	}
	slices.Sort(lines)
	for _, l := range lines {
		rep.write(fmt.Sprintf("%sEXPECTED SKIP %s\n", label, l))
	}
}
