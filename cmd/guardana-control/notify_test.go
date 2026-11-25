package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/notify"
)

// notifyHelperArg makes the test binary the program notify delivers to.
const notifyHelperArg = "-notify-cli-test-helper"

func TestMain(m *testing.M) {
	if len(os.Args) == 4 && os.Args[1] == notifyHelperArg {
		os.Exit(notifyHelper(os.Args[2], os.Args[3]))
	}
	os.Exit(m.Run())
}

// notifyHelper appends its standard input to dir/received, writes a word to
// each of its outputs, and exits 0 in mode "ok" and 1 in mode "fail". Mode
// "env" first writes its environment to dir/env, one variable a line.
func notifyHelper(mode, dir string) int {
	if mode == "env" && os.WriteFile(filepath.Join(dir, "env"), []byte(strings.Join(os.Environ(), "\n")+"\n"), 0o600) != nil {
		return 9
	}
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		return 9
	}
	f, err := os.OpenFile(filepath.Join(dir, "received"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) //nolint:gosec // G304: the directory the test that started this helper named
	if err != nil {
		return 9
	}
	if _, err := f.Write(in); err != nil || f.Close() != nil {
		return 9
	}
	_, _ = os.Stdout.WriteString("helper-stdout\n")
	_, _ = os.Stderr.WriteString("helper-stderr\n")
	if mode == "fail" {
		return 1
	}
	return 0
}

// TestNotifyRefusesItsOwnArgumentsBeforeAnyDelivery: each malformed command
// line is a usage error, printing nothing on standard output and running no
// program.
func TestNotifyRefusesItsOwnArgumentsBeforeAnyDelivery(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "record")
	if err := os.Mkdir(record, 0o700); err != nil {
		t.Fatal(err)
	}
	self, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	prog := []string{self, notifyHelperArg, "ok", record}
	base := []string{"--findings", dir, "--state", dir, "--init"}
	for name, args := range map[string][]string{
		"no separator and no program":  base,
		"a separator and no program":   append(slices.Clone(base), "--"),
		"a program with no separator":  append(slices.Clone(base), prog...),
		"a zero timeout":               append(append(slices.Clone(base), "--timeout", "0s", "--"), prog...),
		"a negative timeout":           append(append(slices.Clone(base), "--timeout", "-1s", "--"), prog...),
		"a timeout that is not one":    append(append(slices.Clone(base), "--timeout", "soon", "--"), prog...),
		"no findings":                  append([]string{"--state", dir, "--init", "--"}, prog...),
		"no state":                     append([]string{"--findings", dir, "--init", "--"}, prog...),
		"the state twice":              append(append(slices.Clone(base), "--state", dir, "--"), prog...),
		"the findings twice":           append(append(slices.Clone(base), "--findings", dir, "--"), prog...),
		"a bare argument before --":    append(append(slices.Clone(base), "extra", "--"), prog...),
		"a flag value taken by the --": append([]string{"--findings", dir, "--state", "--"}, prog...),
	} {
		var stdout, stderr bytes.Buffer
		status := run(append([]string{"notify"}, args...), &stdout, &stderr)
		if want := brand.CLI + ": notify: "; status != exitUsage || stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), want) {
			t.Errorf("%s: status %d, stdout %q, stderr %q; want %d, nothing, and a line starting %q",
				name, status, stdout.String(), stderr.String(), exitUsage, want)
		}
	}
	if _, err := os.Stat(filepath.Join(record, "received")); !os.IsNotExist(err) {
		t.Errorf("a refused command line ran the program: %v", err)
	}
}

// TestNotifyStartedTellsARefusalFromAStoppedRun: a run that stopped after a
// program ran is reported with what it did, never as a refusal that ran
// nothing.
func TestNotifyStartedTellsARefusalFromAStoppedRun(t *testing.T) {
	for _, c := range []struct {
		name string
		sum  notify.Summary
		err  error
		want bool
	}{
		{"a refused state", notify.Summary{}, notify.ErrNotInitialised, false},
		{"another log after already delivered ones", notify.Summary{AlreadyDelivered: 2, Inform: 1}, notify.ErrOtherLog, false},
		{"a failed mark of the first delivery", notify.Summary{}, fmt.Errorf("x: %w", notify.ErrMark), true},
		{"an interrupt during the first delivery", notify.Summary{}, context.Canceled, true},
		{"a change after a delivery", notify.Summary{Delivered: 1}, notify.ErrChanged, true},
		{"a change after a failure", notify.Summary{Failed: 1}, notify.ErrChanged, true},
	} {
		if got := notifyStarted(c.sum, c.err); got != c.want {
			t.Errorf("%s: notifyStarted = %v, want %v", c.name, got, c.want)
		}
	}
}
