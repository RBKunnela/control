package testreport

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

var (
	// ErrExpectedRuns is returned for a list of expected runs that is not one
	// entry per line, that names a test twice, or that names none.
	ErrExpectedRuns = errors.New("testreport: a malformed list of expected runs")
	// ErrNotRun is returned when a test the expected runs name did not pass
	// in the stream: it skipped, failed, never started, or its package never
	// reached the stream.
	ErrNotRun = errors.New("testreport: a test the expected runs name did not pass")
)

// Run names one top-level test of one package.
type Run struct {
	Package, Test string
}

// ExpectedRuns is every test a run has to pass, in the order the list
// gives them.
type ExpectedRuns []Run

// ParseExpectedRuns reads one entry per line, "<import path> <test name>",
// with a single space between the two. A line that starts with "#" and a
// blank line are ignored. A line with an empty or a third field, white space
// inside a field, a test name go test does not give, a subtest, a test named
// a second time, or a list that names no test at all is refused with
// ErrExpectedRuns: a list that names nothing would let a run that ran nothing
// pass.
func ParseExpectedRuns(text []byte) (ExpectedRuns, error) {
	var list ExpectedRuns
	seen := map[Run]bool{}
	n := 0
	for line := range strings.Lines(string(text)) {
		n++
		line = strings.TrimSuffix(line, "\n")
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		pkg, test, _ := strings.Cut(line, " ")
		switch {
		case pkg == "" || test == "":
			return nil, fmt.Errorf("%w: line %d is not <import path> <test name>", ErrExpectedRuns, n)
		case strings.ContainsFunc(pkg+test, unicode.IsSpace):
			return nil, fmt.Errorf("%w: line %d holds white space in a field or a third field", ErrExpectedRuns, n)
		case !strings.HasPrefix(test, "Test"):
			return nil, fmt.Errorf("%w: line %d names %q, which is no test go test runs", ErrExpectedRuns, n, test)
		case strings.Contains(test, "/"):
			return nil, fmt.Errorf("%w: line %d names the subtest %q; name its top-level test", ErrExpectedRuns, n, test)
		}
		key := Run{pkg, test}
		if seen[key] {
			return nil, fmt.Errorf("%w: line %d names %s %s a second time", ErrExpectedRuns, n, pkg, test)
		}
		seen[key] = true
		list = append(list, key)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%w: it names no test", ErrExpectedRuns)
	}
	return list, nil
}

// SummarizeRuns judges a stream in which every test of expected has to
// pass. It writes what Summarize writes, then one line per expected test,
// "PASSED" or "NOT PASSED". Every rule of Summarize holds, with no generated
// package exempt and no skip admitted, so a skip anywhere in the stream
// fails it; on top of them, each expected test that did not pass is named
// with ErrNotRun. An empty expected list is refused, never passed.
func SummarizeRuns(r io.Reader, w io.Writer, expected ExpectedRuns) (Summary, error) {
	if len(expected) == 0 {
		return Summary{}, fmt.Errorf("%w: it names no test", ErrExpectedRuns)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return Summary{}, fmt.Errorf("testreport: reading the stream: %w", err)
	}
	sum, err := Summarize(bytes.NewReader(raw), w, "", nil)
	passed := passes(raw)
	var missing []string
	for _, want := range expected {
		verdict := "PASSED"
		if !passed[want] {
			verdict = "NOT PASSED"
			missing = append(missing, want.Package+" "+want.Test)
		}
		if _, werr := fmt.Fprintf(w, "%s%s %s %s\n", label, verdict, want.Package, want.Test); werr != nil {
			err = errors.Join(err, fmt.Errorf("testreport: writing the transcript: %w", werr))
		}
	}
	if len(missing) > 0 {
		err = errors.Join(err, fmt.Errorf("%w: %s", ErrNotRun, strings.Join(missing, ", ")))
	}
	return sum, err
}

// passes is every test whose last result in the stream is a pass, read
// with the parser Summarize uses, so a line it refuses counts for nothing.
func passes(raw []byte) map[Run]bool {
	last := map[Run]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(nil, len(raw)+1)
	for sc.Scan() {
		e, ok := parse(sc.Text())
		if !ok || e.Test == "" {
			continue
		}
		switch e.Action {
		case "pass", "fail", "skip":
			last[Run{e.Package, e.Test}] = e.Action
		}
	}
	out := map[Run]bool{}
	for k, v := range last {
		if v == "pass" {
			out[k] = true
		}
	}
	return out
}
