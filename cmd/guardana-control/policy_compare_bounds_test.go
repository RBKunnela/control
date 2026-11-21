package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// padTo writes body with spaces after it to exactly n bytes, which a JSON
// reader skips.
func padTo(t *testing.T, path, body string, n int) {
	t.Helper()
	if len(body) > n {
		t.Fatalf("%d bytes do not fit in %d", len(body), n)
	}
	writeFixture(t, path, body+strings.Repeat(" ", n-len(body)))
}

func corpusCase(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(corpusPath("cases", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// A directory of 4096 case files is compared; one of 4097 is refused for the
// count before any file is read. Every file is a valid case, so the 4096
// are refused by nothing but the bound.
func TestPolicyCompareCaseCountBound(t *testing.T) {
	body := corpusCase(t, "read-order.json")
	for _, n := range []int{4096, 4097} {
		dir := t.TempDir()
		for i := range n {
			writeFixture(t, filepath.Join(dir, fmt.Sprintf("c%04d.json", i)), body)
		}
		report := filepath.Join(t.TempDir(), "r.json")
		code, stdout, stderr := invoke(t, compareArgsFor(report, "--cases", dir)...)
		if n == 4096 && (code != exitOK || !strings.Contains(stdout, "read: 4096 (4096 case, 0 evidence)")) {
			t.Errorf("%d files: exit %d, %q %q, want 0 and every file read", n, code, stdout, stderr)
		}
		if n == 4097 && (code != exitUsage || !strings.Contains(stderr, "4097 case files, at most 4096")) {
			t.Errorf("%d files: exit %d, %q, want the count refused", n, code, stderr)
		}
	}
}

// A case file of 2 MiB is read; one byte more is refused for its size.
func TestPolicyCompareCaseFileBound(t *testing.T) {
	body := corpusCase(t, "read-order.json")
	for _, n := range []int{maxReadBytes, maxReadBytes + 1} {
		dir := t.TempDir()
		padTo(t, filepath.Join(dir, "read-order.json"), body, n)
		report := filepath.Join(t.TempDir(), "r.json")
		code, _, stderr := invoke(t, compareArgsFor(report, "--cases", dir)...)
		if n == maxReadBytes && code != exitOK {
			t.Errorf("%d bytes: exit %d, %q, want 0", n, code, stderr)
		}
		if n > maxReadBytes && (code != exitUsage || !strings.Contains(stderr, "over the size bound") || !strings.Contains(stderr, "read-order.json")) {
			t.Errorf("%d bytes: exit %d, %q, want the size refused", n, code, stderr)
		}
	}
}

// A labels file of 1 MiB is read; one byte more is refused for its size.
func TestPolicyCompareLabelsFileBound(t *testing.T) {
	body := `{"kind":"policy-case-labels/v1alpha1","labeller":"x","labels":[{"case":"case:read-order.json","label":"legitimate"}]}`
	cases := compareCasesDir(t, "read-order.json")
	for _, n := range []int{maxLabelsBytes, maxLabelsBytes + 1} {
		labels := filepath.Join(t.TempDir(), "labels.json")
		padTo(t, labels, body, n)
		report := filepath.Join(t.TempDir(), "r.json")
		code, _, stderr := invoke(t, compareArgsFor(report, "--cases", cases, "--labels", labels)...)
		if n == maxLabelsBytes && code != exitOK {
			t.Errorf("%d bytes: exit %d, %q, want 0", n, code, stderr)
		}
		if n > maxLabelsBytes && (code != exitUsage || !strings.Contains(stderr, "over the size bound")) {
			t.Errorf("%d bytes: exit %d, %q, want the size refused", n, code, stderr)
		}
	}
}

// An export of 32 MiB is read and one byte more is refused for its size,
// before any of it is parsed. The files are sparse, so the test writes no
// such volume; zero bytes are no export, so the one at the bound is refused
// for its content instead.
func TestPolicyCompareExportBound(t *testing.T) {
	for _, n := range []int64{32 << 20, 32<<20 + 1} {
		export := filepath.Join(t.TempDir(), "export.jsonl")
		f, err := os.OpenFile(export, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600) //nolint:gosec // G304: the test's own file
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(n); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		report := filepath.Join(t.TempDir(), "r.json")
		code, _, stderr := invoke(t, compareArgsFor(report, "--evidence", export)...)
		size := strings.Contains(stderr, "over the size bound")
		if code != exitUsage || !strings.Contains(stderr, "--evidence") || size != (n > 32<<20) {
			t.Errorf("%d bytes: exit %d, %q, want refused, for its size only over 32 MiB", n, code, stderr)
		}
	}
}
