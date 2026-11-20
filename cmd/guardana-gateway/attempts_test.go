package main

import (
	"bytes"
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/guardana/control/internal/attempts"
	"github.com/guardana/control/internal/brand"
)

// The dispatch test's answers for attempts: bare, it names the one thing to
// do; with a manifest that does not exist it could not run, exit 2.
func init() {
	answers["attempts"] = answer{
		bare: brand.Gateway + " attempts: the one thing to do with attempts is run them: " + brand.Gateway + " attempts " + attemptsForm + "\n",
		refused: func(missing string) []string {
			return []string{"run", "--manifest", missing, "--report", missing + ".report"}
		},
		refusal: brand.Gateway + ": attempts: could not run: ",
		status:  exitCouldNotRun,
	}
}

func TestAttemptsUsage(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"attempts", "run", "--report", "r"}, brand.Gateway + " attempts: --manifest names the attempt manifest to run\n"},
		{[]string{"attempts", "run", "--manifest", "m"}, brand.Gateway + " attempts: --report names the report to write\n"},
		{[]string{"attempts", "run", "--manifest", "m", "--report", "r", "extra"}, brand.Gateway + " attempts: unexpected argument extra\n"},
		{[]string{"attempts", "count"}, brand.Gateway + " attempts: the one thing to do with attempts is run them: " + brand.Gateway + " attempts " + attemptsForm + "\n"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), c.args, &stdout, &stderr); code != exitUsage || stderr.String() != c.want || stdout.Len() != 0 {
			t.Errorf("%q: exit %d, stderr %q; want %d and %q", c.args, code, stderr.String(), exitUsage, c.want)
		}
	}
}

// TestAPlaneModeIsSetOverTheDemos: the mode an attempt's plane names is the
// plane's, whatever the demo's file says, and with none the file's stands.
func TestAPlaneModeIsSetOverTheDemos(t *testing.T) {
	demo := filepath.Join("..", "..", "examples", "vulnerable-mcp-agent", "demo.yaml")
	for _, c := range []struct{ mode, want string }{{"OBSERVE", "OBSERVE"}, {"APPROVE", "APPROVE"}, {"", "ENFORCE"}} {
		cfg, err := demoConfig(devInputs{config: demo, silent: true, mode: c.mode})
		if err != nil {
			t.Fatalf("mode %q: %v", c.mode, err)
		}
		if cfg.ModeName != c.want {
			t.Errorf("mode %q: the plane runs in %s, want %s", c.mode, cfg.ModeName, c.want)
		}
	}
	if _, err := demoConfig(devInputs{config: demo, silent: true, mode: "SOMETIMES"}); err == nil {
		t.Error("a mode the plane does not know was taken")
	}
}

// TestMissingInputsNameEveryGap: a journal that cannot be judged, a step not
// sent, an action that did not run and a failed clean-up are each named, and
// a run that never started names none of its steps.
func TestMissingInputsNameEveryGap(t *testing.T) {
	r := &attempts.Run{Attempt: "approval", Plane: "observe", Started: true, Unfinished: "closing the session: EOF",
		JournalUnknown: map[string]string{"web": "it has 2 names"},
		Steps: []attempts.StepRun{
			{Step: 0, Kind: "call", Sent: true},
			{Step: 1, Kind: "approve", NotRun: "nothing is held"},
			{Step: 2, Kind: "call", NotSent: "input missing: step[1]"},
			{Step: 3, Kind: "approve", Ran: true},
		}}
	want := []string{"journal: it has 2 names", "approval step 1 did not run on observe: nothing is held",
		"approval step 2 not sent on observe: input missing: step[1]", "unfinished: closing the session: EOF"}
	if got := missingOf(r); !slices.Equal(got, want) {
		t.Errorf("missing %q,\nwant %q", got, want)
	}
	r.Started, r.Unfinished, r.JournalUnknown = false, "", nil
	if got := missingOf(r); len(got) != 0 {
		t.Errorf("a run not started: missing %q", got)
	}
}
