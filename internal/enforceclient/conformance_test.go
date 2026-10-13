package enforceclient_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/enforceclient"
)

// runCase runs one client case with mk and returns every way the client
// departed from expect.json; none means it passed.
func runCase(t *testing.T, mk newCaller, id string) []string {
	t.Helper()
	dir := filepath.Join(casesDir, "client", id)
	var call callFile
	readJSON(t, filepath.Join(dir, "call.json"), &call)
	var want expectFile
	readJSON(t, filepath.Join(dir, "expect.json"), &want)
	answers := loadAnswers(t, dir)

	ctx, cancel, expire := callerContext(t, id, call.DeadlineMS, answers)
	r := &receiver{answers: answers, cancel: cancel, expire: expire, callerDone: ctx.Done()}
	c := mk(t, serve(t, r), call.RunToken)

	var reached bool
	var received []byte
	exec := func(ctx context.Context, authorized []byte) (enforceclient.Result, error) {
		if call.ToolDoes.Error == "not_sent" {
			return enforceclient.Result{}, fmt.Errorf("dialling the tool: %w", enforceclient.ErrNotSent)
		}
		reached, received = true, slices.Clone(authorized)
		if call.ToolDoes.CancelCaller {
			cancel()
		}
		switch call.ToolDoes.Error {
		case "timed_out":
			return enforceclient.Result{}, fmt.Errorf("waiting for the tool: %w", context.DeadlineExceeded)
		case "context":
			return enforceclient.Result{}, ctx.Err()
		case "":
		default:
			t.Fatalf("%s: tool_does.error %q", id, call.ToolDoes.Error)
		}
		return toolResult(t, call.ToolDoes), nil
	}
	answer, err := c(ctx, call.Tool, []byte(call.Arguments), exec)

	var miss []string
	if reached != want.ToolReached {
		miss = append(miss, fmt.Sprintf("tool reached %v, want %v", reached, want.ToolReached))
	}
	if want.ToolReceived != nil && string(received) != *want.ToolReceived {
		miss = append(miss, fmt.Sprintf("tool received %q, want %q", received, *want.ToolReceived))
	}
	miss = append(miss, compareRequests(r.requests(), call.RunToken, want)...)
	miss = append(miss, compareReturns(answer, err, want.Returns)...)
	return miss
}

// callerContext is the context a case's call runs under, the function that
// cancels it, and the one that makes its deadline pass.
func callerContext(t *testing.T, id string, deadlineMS int, answers []scripted) (context.Context, context.CancelFunc, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	awaits := slices.ContainsFunc(answers, func(a scripted) bool { return a.Then == "await_caller" })
	switch {
	case awaits && deadlineMS <= 0:
		t.Fatalf("%s: await_caller needs deadline_ms", id)
	case awaits:
		// The deadline passes when the receiver has the request, not on the
		// clock, which a loaded machine can overrun before the request is sent.
		d := newExpiring(ctx, time.Duration(deadlineMS)*time.Millisecond)
		return d, cancel, d.expire
	case deadlineMS > 0:
		ctx, cancel = context.WithTimeout(ctx, time.Duration(deadlineMS)*time.Millisecond)
		t.Cleanup(cancel)
	}
	return ctx, cancel, func() {}
}

func toolResult(t *testing.T, d toolDoes) enforceclient.Result {
	t.Helper()
	res := enforceclient.Result{
		Status:                 enforcev1alpha1.CompletionStatus(enforcev1alpha1.CompletionStatus_value[d.Status]),
		ResultHash:             d.ResultHash,
		SideEffectConfirmation: d.SideEffectConfirmation,
	}
	for _, f := range []struct {
		text string
		into *time.Time
	}{{d.StartedAt, &res.StartedAt}, {d.EndedAt, &res.EndedAt}} {
		if f.text == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339, f.text)
		if err != nil {
			t.Fatalf("tool_does time %q: %v", f.text, err)
		}
		*f.into = at
	}
	return res
}

func referenceClient(t *testing.T, socket, token string) caller {
	t.Helper()
	c, err := enforceclient.New(enforceclient.Config{Socket: socket, Token: token, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c.Call
}

func TestTheReferenceClientPassesEveryCase(t *testing.T) {
	for _, c := range loadCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			for _, m := range runCase(t, referenceClient, c.ID) {
				t.Error(m)
			}
		})
	}
}

func TestTheCaseFilesAgreeWithTheirIndex(t *testing.T) {
	cases := loadCases(t)
	var listed []string
	for _, c := range cases {
		if c.Contract != "v1alpha1" || c.Rule == "" || c.NegativeControl.Defect == "" || c.NegativeControl.Breaks == "" {
			t.Errorf("%s: needs contract v1alpha1, a rule and a negative control: %+v", c.ID, c)
		}
		if !slices.Contains(defects, c.NegativeControl.Defect) {
			t.Errorf("%s: no mutant implements defect %q", c.ID, c.NegativeControl.Defect)
		}
		listed = append(listed, c.ID)
	}
	entries, err := os.ReadDir(filepath.Join(casesDir, "client"))
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		dirs = append(dirs, e.Name())
	}
	slices.Sort(listed)
	if !slices.Equal(listed, dirs) {
		t.Errorf("cases.json lists %v, client/ holds %v", listed, dirs)
	}
	for _, id := range []string{
		"block", "unspecified-outcome", "unknown-outcome", "execute-plain", "execute-rewritten",
		"unknown-obligation", "pending", "timeout-before-send", "timeout-after-send", "cancellation",
		"completion", "unauthenticated", "malformed-answer", "handle-spent", "tool-reports-nothing",
	} {
		if !slices.Contains(listed, id) {
			t.Errorf("no case %s", id)
		}
	}
}
