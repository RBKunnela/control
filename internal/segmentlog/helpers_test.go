package segmentlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"
)

// testLive is the plainest live file: appends synced at the end, and what
// follows the last newline cut at open, as a crash leaves it.
type testLive struct{ f *os.File }

func openTestLive(root *os.Root, name string) (LiveFile, error) {
	f, err := root.OpenFile(name, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	raw, err := root.ReadFile(name)
	if err == nil {
		err = f.Truncate(int64(bytes.LastIndexByte(raw, '\n') + 1))
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return testLive{f}, nil
}

func (l testLive) AppendLines(_ context.Context, lines []byte) error {
	if _, err := l.f.Write(lines); err != nil {
		return err
	}
	return l.f.Sync()
}

func (testLive) Check() error { return nil }

func (l testLive) Close() error { return l.f.Close() }

// clockAt is a clock that stands at one second.
func clockAt(sec int64) func() time.Time { return func() time.Time { return time.Unix(sec, 0) } }

func config(dir string, segmentBytes, maxBytes int64) Config {
	return Config{Kind: KindSegments, Dir: dir, Tenant: "t1", Project: "p1", SegmentBytes: segmentBytes,
		MaxBytes: maxBytes, MaxLineBytes: 1 << 10, OpenLive: openTestLive, Now: clockAt(1_800_000_000)}
}

func logDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "log")
}

func openLog(t *testing.T, cfg Config) *segments {
	t.Helper()
	l, err := openSegments(cfg)
	if err != nil {
		t.Fatalf("opening the log: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func mustAppend(t *testing.T, l RecordLog, lines ...string) {
	t.Helper()
	if err := l.Append(context.Background(), []byte(joinLines(lines...))); err != nil {
		t.Fatalf("Append(%q) = %v", lines, err)
	}
}

func joinLines(lines ...string) string {
	var b bytes.Buffer
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return b.String()
}

// sum is the digest of a line as the log takes it, spelled out apart from
// the package's own scan.
func sum(line string) Digest { return sha256.Sum256([]byte(line + "\n")) }

// key is what names segment seq beginning with line.
func key(seq int, line string) Digest { return SegmentKey(seq, sum(line)) }

// visited opens the log with a visitor and returns what it was handed.
func visited(t *testing.T, cfg Config) ([]string, *segments) {
	t.Helper()
	var seen []string
	cfg.Visit = func(line []byte) error {
		seen = append(seen, string(bytes.TrimSuffix(line, []byte("\n"))))
		return nil
	}
	l := openLog(t, cfg)
	return seen, l
}

// dirNames is every name in dir, sorted.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func fileText(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func states(m Manifest) []State {
	var out []State
	for _, s := range m.Segments {
		out = append(out, s.State)
	}
	return slices.Clip(out)
}
