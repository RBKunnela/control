package impact

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Runner runs git with the arguments and returns its standard output. The
// tool hands in one that executes the binary; a test hands in a table. An
// error is whatever stopped git: the binary absent, the tree no repository.
type Runner func(args ...string) ([]byte, error)

// ErrNotMeasured is wrapped by every result git could not produce. The
// caller prints it as NOT MEASURED with the reason and exits non-zero: an
// absent git never reads as "no change" or "no commit".
var ErrNotMeasured = errors.New("NOT MEASURED")

// notMeasured wraps what stopped a git step, keeping a reason that already
// says NOT MEASURED as it is.
func notMeasured(step string, err error) error {
	if errors.Is(err, ErrNotMeasured) {
		return err
	}
	return fmt.Errorf("%w: %s: %w", ErrNotMeasured, step, err)
}

// Commit is one commit of the log, with the paths it touched.
type Commit struct {
	Hash    string
	Subject string
	Files   []string
}

// Staleness is what the log says about one page: the commit that last
// touched it and every later commit touching a path under its covers.
type Staleness struct {
	Page        string
	LastCommit  string
	Since       []Commit
	Uncommitted bool
}

// logArgs asks for each commit as one NUL-prefixed header line, so a header
// is never mistaken for a path, followed by the paths the commit touched. A
// merge commit lists what it brought against its first parent, since it
// prints nothing otherwise, and no signature is printed, since that would be
// read as a path.
var logArgs = []string{"log", "--format=%x00%h %s", "--name-only", "--diff-merges=first-parent", "--no-show-signature"}

// Changed asks git for the paths a range changed. A range spelled like an
// option is refused before git sees it.
func Changed(run Runner, rng string) ([]string, error) {
	if rng == "" || strings.HasPrefix(rng, "-") {
		return nil, fmt.Errorf("%w: %q is not a revision range", ErrInvalid, rng)
	}
	out, err := run("diff", "--name-only", rng, "--")
	if err != nil {
		return nil, notMeasured("git diff", err)
	}
	return ParseNameOnly(out)
}

// ParseNameOnly reads the output of `git diff --name-only`: one clean path
// per line, none twice. A path git quoted holds a character the walk would
// refuse too, so the line is refused rather than unquoted.
func ParseNameOnly(out []byte) ([]string, error) {
	if len(out) == 0 {
		return nil, nil
	}
	if strings.Contains(string(out), "\r") {
		return nil, fmt.Errorf("%w: git's output holds a carriage return", ErrInvalid)
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	paths := make([]string, 0, len(lines))
	for i, line := range lines {
		if err := checkGitPath(line); err != nil {
			return nil, fmt.Errorf("%w: line %d: %w", ErrInvalid, i+1, err)
		}
		if slices.Contains(paths, line) {
			return nil, fmt.Errorf("%w: line %d: %s is listed twice", ErrInvalid, i+1, line)
		}
		paths = append(paths, line)
	}
	return paths, nil
}

// Files is the list of files the tree holds and where it came from, so the
// count printed beside it says what was examined.
type Files struct {
	Paths  []string
	Source string
}

// ListFiles asks git for the files it tracks or would track, less the
// tracked files deleted from disk, so a file .gitignore hides or one that is
// gone never keeps a covers glob alive. Where git cannot answer, the walk
// stands in and the source says so: an export with no repository is judged
// the same as the work tree.
func ListFiles(run Runner, walk func() ([]string, error)) (Files, error) {
	return listFiles(run, func() ([]string, string, error) {
		paths, err := walk()
		return paths, "a walk of the tree", err
	})
}

// listFiles is ListFiles with a fallback that names its own source.
func listFiles(run Runner, fallback func() ([]string, string, error)) (Files, error) {
	paths, err := gitFiles(run)
	if errors.Is(err, ErrInvalid) {
		return Files{}, err
	}
	if err != nil {
		paths, source, fallbackErr := fallback()
		if fallbackErr != nil {
			return Files{}, fmt.Errorf("%w; git ls-files: %w", fallbackErr, err)
		}
		return Files{Paths: paths, Source: fmt.Sprintf("%s; git ls-files: %v", source, err)}, nil
	}
	return Files{Paths: paths, Source: "git ls-files"}, nil
}

func gitFiles(run Runner) ([]string, error) {
	out, err := run("ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	listed, err := parseZ(out)
	if err != nil {
		return nil, fmt.Errorf("%w: git ls-files: %w", ErrInvalid, err)
	}
	out, err = run("ls-files", "-z", "--deleted")
	if err != nil {
		return nil, err
	}
	deleted, err := parseZ(out)
	if err != nil {
		return nil, fmt.Errorf("%w: git ls-files --deleted: %w", ErrInvalid, err)
	}
	for _, d := range deleted {
		if !slices.Contains(listed, d) {
			return nil, fmt.Errorf("%w: git ls-files --deleted: %s is not listed as tracked", ErrInvalid, d)
		}
	}
	paths := slices.DeleteFunc(listed, func(p string) bool { return slices.Contains(deleted, p) })
	if len(paths) == 0 {
		return nil, fmt.Errorf("%w: git ls-files: git listed no file", ErrInvalid)
	}
	return paths, nil
}

// parseZ reads NUL-terminated paths, as `git ls-files -z` prints them: git
// quotes nothing in that form, so every byte is the path's own.
func parseZ(out []byte) ([]string, error) {
	if len(out) == 0 {
		return nil, nil
	}
	entries := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	paths := make([]string, 0, len(entries))
	for i, entry := range entries {
		if err := checkPath(entry); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		if slices.Contains(paths, entry) {
			return nil, fmt.Errorf("entry %d: %s is listed twice", i+1, entry)
		}
		paths = append(paths, entry)
	}
	return paths, nil
}

// Stale asks git for the whole log, newest first, and judges every page
// against it. A shallow clone holds part of the log, so a page's own commit
// may be missing from it and every count would be wrong: it is not measured.
func Stale(run Runner, pages []Page) ([]Staleness, error) {
	ps, err := compilePages(pages)
	if err != nil {
		return nil, err
	}
	if err := checkDepth(run); err != nil {
		return nil, err
	}
	out, err := run(logArgs...)
	if err != nil {
		return nil, notMeasured("git log", err)
	}
	commits, err := ParseLog(out)
	if err != nil {
		return nil, err
	}
	rows := make([]Staleness, 0, len(ps))
	for _, p := range ps {
		rows = append(rows, staleness(p, commits))
	}
	return rows, nil
}

func checkDepth(run Runner) error {
	out, err := run("rev-parse", "--is-shallow-repository")
	if err != nil {
		return notMeasured("git rev-parse", err)
	}
	switch answer := strings.TrimSpace(string(out)); answer {
	case "false":
		return nil
	case "true":
		return fmt.Errorf("%w: a shallow clone holds part of the log", ErrNotMeasured)
	default:
		return fmt.Errorf("%w: git could not say whether the clone is shallow: %q", ErrNotMeasured, answer)
	}
}

func staleness(p page, commits []Commit) Staleness {
	last := slices.IndexFunc(commits, func(c Commit) bool { return slices.Contains(c.Files, p.path) })
	if last < 0 {
		return Staleness{Page: p.path, Uncommitted: true}
	}
	row := Staleness{Page: p.path, LastCommit: commits[last].Hash}
	for _, c := range commits[:last] {
		if len(matching(p.covers, c.Files)) > 0 {
			row.Since = append(row.Since, c)
		}
	}
	return row
}

// FormatStale spells the rows with the count behind them.
func FormatStale(rows []Staleness) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d pages examined\n", len(rows))
	for _, r := range rows {
		if r.Uncommitted {
			fmt.Fprintf(&b, "  %s: not committed yet\n", r.Page)
			continue
		}
		fmt.Fprintf(&b, "  %s: last commit %s, %d commits since touching its covers\n", r.Page, r.LastCommit, len(r.Since))
		for _, c := range r.Since {
			fmt.Fprintf(&b, "    %s %s\n", c.Hash, c.Subject)
		}
	}
	return b.String()
}

// ParseLog reads the output of `git log --format=%x00%h %s --name-only`: a
// header line per commit, then the paths it touched, blank lines between.
func ParseLog(out []byte) ([]Commit, error) {
	if strings.Contains(string(out), "\r") {
		return nil, fmt.Errorf("%w: git's output holds a carriage return", ErrInvalid)
	}
	var commits []Commit
	for i, line := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "\x00"):
			c, err := parseHeader(line[1:], commits)
			if err != nil {
				return nil, fmt.Errorf("%w: line %d: %w", ErrInvalid, i+1, err)
			}
			commits = append(commits, c)
		case len(commits) == 0:
			return nil, fmt.Errorf("%w: line %d: a path before any commit header", ErrInvalid, i+1)
		default:
			if err := checkGitPath(line); err != nil {
				return nil, fmt.Errorf("%w: line %d: %w", ErrInvalid, i+1, err)
			}
			last := &commits[len(commits)-1]
			last.Files = append(last.Files, line)
		}
	}
	if len(commits) == 0 {
		return nil, fmt.Errorf("%w: the log holds no commit", ErrInvalid)
	}
	return commits, nil
}

// parseHeader reads "hash subject". A commit may carry an empty subject, so
// only a missing hash is malformed.
func parseHeader(header string, seen []Commit) (Commit, error) {
	hash, subject, _ := strings.Cut(header, " ")
	switch {
	case hash == "":
		return Commit{}, errors.New("a commit header has no hash")
	case slices.ContainsFunc(seen, func(c Commit) bool { return c.Hash == hash }):
		return Commit{}, fmt.Errorf("commit %s is listed twice", hash)
	}
	return Commit{Hash: hash, Subject: subject}, nil
}

func checkGitPath(line string) error {
	if strings.HasPrefix(line, "\"") {
		return fmt.Errorf("git quoted the path %s; it holds a character the walk refuses", line)
	}
	return checkPath(line)
}
