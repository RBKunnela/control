package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// TestAFlagRefusalQuotesWhatBreaksALine: the flag package names an undefined
// flag as it was given, and a separator, a bidirectional control or a format
// character in that name reaches stderr quoted, from every command whose flag
// set prints.
func TestAFlagRefusalQuotesWhatBreaksALine(t *testing.T) {
	for _, code := range []rune{0x2028, 0x2029, 0x202e, 0x200b} {
		r, escaped := string(code), fmt.Sprintf(`\u%04x`, code)
		want := `"flag provided but not defined: -x` + escaped + `y"`
		for _, args := range [][]string{
			{"pause", "add", "--x" + r + "y"},
			{"pause", "remove", "--x" + r + "y"},
			{"approvals", "approve", "--x" + r + "y"},
			{"approvals", "reject", "--x" + r + "y"},
			{"policy", "keygen", "--x" + r + "y"},
			{"policy", "sign", "--x" + r + "y"},
			{"policy", "renew", "--x" + r + "y"},
			{"policy", "state", "init", "--x" + r + "y"},
			{"policy", "state", "reset", "--x" + r + "y"},
			{"console", "--x" + r + "y"},
		} {
			var stdout, stderr bytes.Buffer
			status := run(args, &stdout, &stderr)
			if status != exitUsage || strings.Contains(stderr.String(), r) {
				t.Errorf("%q: exit %d, stderr %q, want %d and U+%04X quoted", args, status, stderr.String(), exitUsage, code)
			}
			if args[0] != "policy" && !strings.HasPrefix(stderr.String(), want+"\n") {
				t.Errorf("%q: stderr %q does not begin with %q", args, stderr.String(), want)
			}
		}
	}
}

// TestAFlagRefusalKeepsItsHelp: what the flag package prints for -h is the
// command's help as it always was, newlines and tabs included.
func TestAFlagRefusalKeepsItsHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if status := run([]string{"pause", "remove", "-h"}, &stdout, &stderr); status != exitUsage {
		t.Errorf("pause remove -h: exit %d, want %d", status, exitUsage)
	}
	want := "Usage of " + pauseRemoveFlagSet(pauseRemoveName, &bytes.Buffer{}).Name() + ":\n  -key string\n    \tthe operator's private key file"
	if help := stderr.String(); !strings.HasPrefix(help, want) || strings.Contains(help, `\t`) {
		t.Errorf("pause remove -h printed %q, want it to begin %q", help, want)
	}
	stderr.Reset()
	run([]string{"approvals", "approve", "-h"}, &stdout, &stderr)
	if help := stderr.String(); !strings.Contains(help, "  -approver-id string\n    \twho is answering") || strings.Contains(help, `\t`) {
		t.Errorf("approvals approve -h printed %q", help)
	}
}
