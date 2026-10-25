package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
)

const exampleDocument = "../../testdata/policy/documents/example.json"

// write puts content in a file of the test's own directory and returns its
// path.
func write(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

func TestLintAcceptsTheExampleDocument(t *testing.T) {
	code, stdout, stderr := invoke(t, "policy", "lint", exampleDocument)
	if code != 0 {
		t.Errorf("exit %d, want 0; stderr %q", code, stderr)
	}
	if stdout != "" || stderr != "" {
		t.Errorf("stdout %q stderr %q, want nothing on either", stdout, stderr)
	}
}

func TestLintRefusesWithTheFirstRefusalOnOneLine(t *testing.T) {
	for name, tc := range map[string]struct {
		document string
		want     string // a substring of the one stderr line
	}{
		"unknown key": {
			`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"p","version":"1","serial":1,"maxStaleSeconds":300},"rules":[{"id":"r","effect":"ALLOW","when":{"action":{"effect":["READ"]}},"comment":"x"}]}`,
			`rule "r" "rules[0]": "rules: a key this document format does not have"`,
		},
		"two refusals, the first in document order": {
			`{"apiVersion":"agent-policy/v2","bundle":{"id":"p","version":"1","serial":-1,"maxStaleSeconds":300},"rules":[]}`,
			`"apiVersion": "rules: an apiVersion this build does not read`,
		},
		"not json": {
			`{"apiVersion":`,
			`rules: not strict JSON`,
		},
		"obligation outside the catalogue": {
			`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"p","version":"1","serial":1,"maxStaleSeconds":300},"rules":[{"id":"r","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"cap_amounts"}],"when":{"action":{"effect":["READ"]}}}]}`,
			`rules: an obligation type outside the catalogue`,
		},
		"a parameter its type does not declare": {
			`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"p","version":"1","serial":1,"maxStaleSeconds":300},"rules":[{"id":"r","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"cap_rate","params":{"per_minute":"60"},"advisory":true}],"when":{"action":{"effect":["READ"]}}}]}`,
			`rule "r" "rules[0].obligations[0].params[0].key": "rules: a parameter the obligation's type does not declare or requires: cap_rate takes no parameters"`,
		},
		"a value its type cannot apply": {
			`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"p","version":"1","serial":1,"maxStaleSeconds":300},"rules":[{"id":"r","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"shorten_timeout","params":{"ms":"0"}}],"when":{"action":{"effect":["READ"]}}}]}`,
			`rule "r" "rules[0].obligations[0].params[0]": "rules: a parameter value the obligation's type cannot apply`,
		},
		"restrict_resources with neither ids nor prefix": {
			`{"apiVersion":"agent-policy/v1alpha1","bundle":{"id":"p","version":"1","serial":1,"maxStaleSeconds":300},"rules":[{"id":"r","effect":"ALLOW_WITH_OBLIGATIONS","obligations":[{"type":"restrict_resources"}],"when":{"action":{"effect":["READ"]}}}]}`,
			`rule "r" "rules[0].obligations[0].params": "rules: a parameter the obligation's type does not declare or requires: restrict_resources requires one of \"ids\", \"prefix\""`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := write(t, "policy.json", []byte(tc.document))
			code, stdout, stderr := invoke(t, "policy", "lint", path)
			if code != 1 {
				t.Errorf("exit %d, want 1", code)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want nothing", stdout)
			}
			line := oneStderrLine(t, stderr)
			if !strings.HasPrefix(line, brand.CLI+": policy lint: ") || !strings.Contains(line, tc.want) {
				t.Errorf("stderr = %q, want the prefix and %q", line, tc.want)
			}
		})
	}
}

// The refusal names the file, and a name that holds a control character is
// quoted, so the line stays one line. The command is reached past the
// dispatcher, which would refuse that name first.
func TestLintReportsAFileItCannotReadOnOneLine(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct{ path, want string }{
		"missing file":          {filepath.Join(dir, "missing.json"), "open "},
		"a directory":           {dir, dir + ": files: not a regular file: a directory"},
		"a newline in the name": {filepath.Join(dir, "a\nb.json"), `"open `},
	} {
		t.Run(name, func(t *testing.T) {
			var stderrBuf bytes.Buffer
			code, stderr := lint(tc.path, &stderrBuf), stderrBuf.String()
			if code != 1 {
				t.Errorf("exit %d, want 1", code)
			}
			if line := oneStderrLine(t, stderr); !strings.HasPrefix(line, brand.CLI+": policy lint: "+tc.want) {
				t.Errorf("stderr = %q, want the prefix and %q", line, tc.want)
			}
		})
	}
}

// padded is the example document followed by spaces, size bytes in all.
func padded(t *testing.T, size int) []byte {
	t.Helper()
	doc, err := os.ReadFile(exampleDocument)
	if err != nil {
		t.Fatalf("reading the example: %v", err)
	}
	doc = bytes.TrimRight(doc, "\n")
	if size < len(doc) {
		t.Fatalf("size %d is below the document's %d bytes", size, len(doc))
	}
	return append(doc, bytes.Repeat([]byte{' '}, size-len(doc))...)
}

// The parser's bound is the one an over-long document meets, and the
// program's own read bound sits above it: a document at the parser's limit
// lints, one byte over is refused with the parser's refusal, not a truncated
// read's.
func TestLintHoldsTheDocumentToTheParsersBound(t *testing.T) {
	const parserBound = 1 << 20
	if code, _, stderr := invoke(t, "policy", "lint", write(t, "at.json", padded(t, parserBound))); code != 0 {
		t.Errorf("at the bound: exit %d, want 0; stderr %q", code, stderr)
	}
	code, _, stderr := invoke(t, "policy", "lint", write(t, "over.json", padded(t, parserBound+1)))
	if code != 1 {
		t.Errorf("one over the bound: exit %d, want 1", code)
	}
	if line := oneStderrLine(t, stderr); !strings.Contains(line, "rules: over a bound") {
		t.Errorf("one over the bound: stderr = %q, want the parser's bound refusal", line)
	}
}

func TestReadBoundedRefusesOneByteOverItsLimit(t *testing.T) {
	at := write(t, "at.bin", bytes.Repeat([]byte{'x'}, maxReadBytes))
	if got, err := readBounded(at); err != nil || len(got) != maxReadBytes {
		t.Errorf("at the limit: %d bytes, %v; want %d bytes and no error", len(got), err, maxReadBytes)
	}
	over := write(t, "over.bin", bytes.Repeat([]byte{'x'}, maxReadBytes+1))
	if got, err := readBounded(over); err == nil {
		t.Errorf("one over the limit: %d bytes and no error, want a refusal", len(got))
	} else if !strings.Contains(err.Error(), "over") {
		t.Errorf("one over the limit: %v, want a refusal naming the bound", err)
	}
}
