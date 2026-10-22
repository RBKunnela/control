package testreport

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The label every line Summarize adds starts with: the gate target's own.
const label = "test: "

var (
	// ErrNoEvents is returned for a stream that held no event at all.
	ErrNoEvents = errors.New("testreport: no test2json event read")
	// ErrNotEvent is returned when a line is not a test2json event.
	ErrNotEvent = errors.New("testreport: a line is not a test2json event")
	// ErrNoPackages is returned when events were read but no package result.
	ErrNoPackages = errors.New("testreport: no package result read")
	// ErrUnfinished is returned when the stream ends before a package's result,
	// or a package passes while a test it started has no result, as when the
	// test ended the process with exit status 0.
	ErrUnfinished = errors.New("testreport: a package or a test has no result")
	// ErrFailed is returned when a build, a package or a test failed.
	ErrFailed = errors.New("testreport: a build, package or test failed")
	// ErrNoTestsRun is returned when a package with test files passed without
	// running a test, as when a -run filter matched none of them or a TestMain
	// exited before calling m.Run.
	ErrNoTestsRun = errors.New("testreport: a package ran no test")
	// ErrNoTestFiles is returned when a package outside the generated code
	// has no test files, which go test reports as a skip of the package.
	ErrNoTestFiles = errors.New("testreport: a package has no test files")
	// ErrModulePath is returned when a go.mod holds no single module path.
	ErrModulePath = errors.New("testreport: no single module path in go.mod")
)

// Summary counts what one stream reported.
type Summary struct {
	Events         int // test2json events read
	Packages       int // packages that reached a result
	FailedPackages int
	FailedTests    int // tests, subtests and benchmarks that failed
	BuildFailures  int
	Skipped        int // tests and subtests that skipped
	NoTestsRun     int // packages that passed without a test's run event
	NoTestFiles    int // packages outside the generated code with no test files
	Unfinished     int // tests that started in a passing package and reached no result
}

type event struct {
	Action     string
	Package    string
	Test       string
	Output     string
	ImportPath string
}

type output struct {
	test, text string
}

type pkgState struct {
	lines   []output
	results map[string]string
	started []string
	ran     bool
}

type skipped struct {
	pkg, test, message string
}

type reporter struct {
	w         io.Writer
	sum       Summary
	pkgs      map[string]*pkgState
	order     []string
	skips     []skipped
	noTests   []string
	noFiles   []string
	open      []string
	badLines  []int
	writeErr  error
	generated string
}

// Summarize reads the output of `go test -json` from r and writes to w each
// passing package's result line and, for a failing package, its own lines and
// the output of each test that failed, in the order the stream carried them.
// After the last event it writes one line per skipped test and the skip count.
// A line that is not an event is written through as it came.
//
// The error is nil only when the stream held at least one package result, every
// line was an event, every package reached a result, every test a passing
// package started reached one too, nothing failed, no package with test files
// passed without running one, and every package with no test files, which go
// test reports as a skip of the package, is under generated: the import path
// prefix, ending in a slash, of the generated packages (GeneratedPrefix). An
// empty generated exempts no package.
func Summarize(r io.Reader, w io.Writer, generated string) (Summary, error) {
	rep := &reporter{w: w, pkgs: map[string]*pkgState{}, generated: generated}
	br := bufio.NewReader(r)
	for n := 1; ; n++ {
		raw, err := br.ReadString('\n')
		if raw != "" {
			rep.line(n, strings.TrimSuffix(raw, "\n"))
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return rep.sum, fmt.Errorf("testreport: reading the stream: %w", err)
		}
	}
	return rep.sum, rep.finish()
}

func (rep *reporter) line(n int, text string) {
	e, ok := parse(text)
	if !ok {
		rep.badLines = append(rep.badLines, n)
		rep.write(text + "\n")
		return
	}
	rep.sum.Events++
	switch e.Action {
	case "build-output":
		rep.write(e.Output)
		return
	case "build-fail":
		rep.sum.BuildFailures++
		return
	}
	p := rep.pkg(e.Package)
	switch e.Action {
	case "run":
		if e.Test != "" {
			p.ran = true
			p.started = append(p.started, e.Test)
		}
	case "output":
		p.lines = append(p.lines, output{e.Test, e.Output})
	case "pass", "fail", "skip", "bench":
		if e.Test == "" {
			if e.Action != "bench" {
				rep.result(e.Package, p, e.Action)
			}
			return
		}
		p.results[e.Test] = e.Action
		switch e.Action {
		case "fail":
			rep.sum.FailedTests++
		case "skip":
			rep.sum.Skipped++
			rep.skips = append(rep.skips, skipped{e.Package, e.Test, p.skipMessage(e.Test)})
		}
	}
}

// parse accepts exactly the actions test2json and `go test -json` emit, so
// that a stream from a newer go command that means something new fails loudly.
func parse(text string) (event, bool) {
	var e event
	if err := json.Unmarshal([]byte(text), &e); err != nil {
		return e, false
	}
	switch e.Action {
	case "build-output", "build-fail":
		return e, e.ImportPath != ""
	case "start", "run", "pause", "cont", "pass", "bench", "fail", "output", "skip", "attr", "artifacts":
		return e, e.Package != ""
	}
	return e, false
}

// isGenerated reports whether the package is under the generated prefix. A
// prefix that does not end in a slash exempts nothing, so "api/gen" cannot
// admit "api/generated".
func (rep *reporter) isGenerated(name string) bool {
	return strings.HasSuffix(rep.generated, "/") && strings.HasPrefix(name, rep.generated)
}

func (rep *reporter) pkg(name string) *pkgState {
	p, ok := rep.pkgs[name]
	if !ok {
		p = &pkgState{results: map[string]string{}}
		rep.pkgs[name] = p
		rep.order = append(rep.order, name)
	}
	return p
}

func (rep *reporter) result(name string, p *pkgState, action string) {
	delete(rep.pkgs, name)
	rep.sum.Packages++
	if action == "fail" {
		rep.sum.FailedPackages++
		rep.writeFailed(p)
		return
	}
	line := p.resultLine(name)
	if action == "pass" && !p.ran {
		rep.sum.NoTestsRun++
		rep.noTests = append(rep.noTests, name)
	}
	if action == "skip" && !rep.isGenerated(name) {
		rep.sum.NoTestFiles++
		rep.noFiles = append(rep.noFiles, name)
	}
	if action == "pass" {
		for _, test := range p.started {
			if p.results[test] == "" {
				rep.sum.Unfinished++
				rep.open = append(rep.open, name+" "+test)
			}
		}
	}
	rep.write(line)
}

// writeFailed writes the package's own lines and those of every test that
// failed or never reached a result, in the order they came, without the
// "=== RUN" style framing a run without -v does not print.
func (rep *reporter) writeFailed(p *pkgState) {
	for _, l := range p.lines {
		if strings.HasPrefix(l.text, "=== ") {
			continue
		}
		if r := p.results[l.test]; l.test == "" || r == "" || r == "fail" {
			rep.write(l.text)
		}
	}
}

func (p *pkgState) resultLine(name string) string {
	for i := len(p.lines) - 1; i >= 0; i-- {
		if l := p.lines[i]; l.test == "" && strings.TrimSpace(l.text) != "" {
			return l.text
		}
	}
	return "ok  \t" + name + "\n"
}

func (p *pkgState) skipMessage(test string) string {
	var parts []string
	for _, l := range p.lines {
		if l.test != test {
			continue
		}
		text := strings.TrimSpace(l.text)
		if text == "" || strings.HasPrefix(text, "=== ") || strings.HasPrefix(text, "--- ") {
			continue
		}
		parts = append(parts, text)
	}
	if len(parts) == 0 {
		return "(no message)"
	}
	return strings.Join(parts, "; ")
}

func (rep *reporter) finish() error {
	var errs []error
	var unfinished []string
	for _, name := range rep.order {
		if p, ok := rep.pkgs[name]; ok {
			delete(rep.pkgs, name)
			unfinished = append(unfinished, name)
			rep.writeFailed(p)
		}
	}
	if rep.sum.Events > 0 {
		rep.writeTail()
	}
	if len(rep.badLines) > 0 {
		errs = append(errs, fmt.Errorf("%w: %d line(s), the first at line %d", ErrNotEvent, len(rep.badLines), rep.badLines[0]))
	}
	switch {
	case rep.sum.Events == 0:
		errs = append(errs, ErrNoEvents)
	case rep.sum.Packages == 0:
		errs = append(errs, ErrNoPackages)
	}
	if len(unfinished) > 0 {
		errs = append(errs, fmt.Errorf("%w: package %s", ErrUnfinished, strings.Join(unfinished, ", ")))
	}
	if len(rep.open) > 0 {
		errs = append(errs, fmt.Errorf("%w: a passing package's test %s", ErrUnfinished, strings.Join(rep.open, ", ")))
	}
	if s := rep.sum; s.FailedPackages+s.FailedTests+s.BuildFailures > 0 {
		errs = append(errs, fmt.Errorf("%w: %d package(s), %d test(s), %d build(s)",
			ErrFailed, s.FailedPackages, s.FailedTests, s.BuildFailures))
	}
	errs = append(errs, rep.untestedErrors()...)
	if rep.writeErr != nil {
		errs = append(errs, fmt.Errorf("testreport: writing the transcript: %w", rep.writeErr))
	}
	return errors.Join(errs...)
}

// untestedErrors names the packages that passed without running a test and
// those outside the generated code that have no test files.
func (rep *reporter) untestedErrors() []error {
	var errs []error
	if len(rep.noTests) > 0 {
		errs = append(errs, fmt.Errorf("%w: %s", ErrNoTestsRun, strings.Join(rep.noTests, ", ")))
	}
	if len(rep.noFiles) > 0 {
		errs = append(errs, fmt.Errorf("%w: %s", ErrNoTestFiles, strings.Join(rep.noFiles, ", ")))
	}
	return errs
}

// writeTail writes every test that never ended, every skip and the skip count.
func (rep *reporter) writeTail() {
	for _, test := range rep.open {
		rep.write(fmt.Sprintf("%sUNFINISHED %s\n", label, test))
	}
	for _, s := range rep.skips {
		rep.write(fmt.Sprintf("%sSKIP %s %s: %s\n", label, s.pkg, s.test, s.message))
	}
	rep.write(fmt.Sprintf("%s%d skipped\n", label, rep.sum.Skipped))
}

func (rep *reporter) write(s string) {
	if rep.writeErr != nil {
		return
	}
	_, rep.writeErr = io.WriteString(rep.w, s)
}
