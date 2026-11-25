//go:build unix

package notify

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
	"github.com/guardana/control/internal/findinglog"
)

// afterFile reads r only once the file at path exists, so the line reaches
// the pipe after the program did what it does to its input.
type afterFile struct {
	path string
	r    io.Reader
}

func (a *afterFile) Read(p []byte) (int, error) {
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Stat(a.path); err == nil {
			return a.r.Read(p)
		}
		if time.Now().After(deadline) {
			return 0, errors.New("the program never closed its input")
		}
	}
}

// TestAProgramThatLeftItsLineUnreadIsNotMarked: a program that closed its
// standard input before the line was written and exited 0 never took the
// alert; the failed write is a failed delivery, and nothing is marked.
func TestAProgramThatLeftItsLineUnreadIsNotMarked(t *testing.T) {
	r := newRig(t)
	r.write(t, finding(idA, confirmed, alert))
	o := r.options(true)
	o.Args = []string{helperArg, "closed", r.record}
	input := programInput
	t.Cleanup(func() { programInput = input })
	programInput = func(line []byte) io.Reader {
		return &afterFile{path: filepath.Join(r.record, "closed"), r: bytes.NewReader(line)}
	}
	s := r.run(t, o)
	wantSummary(t, s, 0, 0, 1, 0)
	if len(s.Failures) == 1 && !errors.Is(s.Failures[0].Err, syscall.EPIPE) {
		t.Errorf("the failure = %v, want the write's EPIPE", s.Failures[0].Err)
	}
	if got := r.delivered(t); got != "" {
		t.Errorf("delivered list = %q, want nothing marked", got)
	}
}

// TestTheProgramGetsOnlyTheBaseEnvironment: a variable of the caller's
// environment outside the base list, a credential here, never reaches the
// program; the base list does, with the caller's values.
func TestTheProgramGetsOnlyTheBaseEnvironment(t *testing.T) {
	t.Setenv("NOTIFY_TEST_CREDENTIAL", "not-for-the-program")
	t.Setenv("LANG", "C")
	r := newRig(t)
	r.write(t, finding(idA, confirmed, alert))
	o := r.options(true)
	o.Args[1] = "env"
	wantSummary(t, r.run(t, o), 1, 0, 0, 0)
	raw, err := os.ReadFile(filepath.Join(r.record, "env"))
	mustDo(t, err)
	env := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if strings.Contains(string(raw), "not-for-the-program") {
		t.Errorf("the program's environment carries the credential:\n%s", raw)
	}
	for _, want := range []string{"LANG=C", "PATH=" + os.Getenv("PATH")} {
		if !strings.Contains("\n"+string(raw), "\n"+want+"\n") {
			t.Errorf("the program's environment lacks %s:\n%s", want, raw)
		}
	}
	if len(env) > len(baseEnv) {
		t.Errorf("the program got %d variables, more than the %d of the base list:\n%s", len(env), len(baseEnv), raw)
	}
}

// TestTheProgramGetsTheVariablesTheOptionsName: a variable Env names
// reaches the program with this process's value, once, and one it does
// not name stays out.
func TestTheProgramGetsTheVariablesTheOptionsName(t *testing.T) {
	t.Setenv("NOTIFY_TEST_TOKEN", "for-the-program")
	t.Setenv("NOTIFY_TEST_OTHER", "not-for-the-program")
	r := newRig(t)
	r.write(t, finding(idA, confirmed, alert))
	o := r.options(true)
	o.Args[1] = "env"
	o.Env = []string{"NOTIFY_TEST_TOKEN", "PATH", "NOTIFY_TEST_TOKEN"}
	wantSummary(t, r.run(t, o), 1, 0, 0, 0)
	raw, err := os.ReadFile(filepath.Join(r.record, "env"))
	mustDo(t, err)
	var token, path int
	for _, v := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		switch {
		case v == "NOTIFY_TEST_TOKEN=for-the-program":
			token++
		case strings.HasPrefix(v, "PATH="):
			path++
		}
	}
	if token != 1 || path != 1 {
		t.Errorf("the program's environment holds the named variable %d times and PATH %d, want once each:\n%s", token, path, raw)
	}
	if strings.Contains(string(raw), "not-for-the-program") {
		t.Errorf("the program's environment carries a variable no option names:\n%s", raw)
	}
}

// TestAnEnvNameNotSetOrMalformedIsRefused: a name this process does not
// set, or one no variable can have, refuses the run before any program
// runs, and the refusal never carries a value.
func TestAnEnvNameNotSetOrMalformedIsRefused(t *testing.T) {
	t.Setenv("NOTIFY_TEST_TOKEN", "secret-value")
	for name, env := range map[string][]string{
		"not set":         {"NOTIFY_TEST_UNSET"},
		"empty":           {""},
		"with an equals":  {"NOTIFY_TEST_TOKEN=secret-value"},
		"with a NUL byte": {"NOTIFY_TEST_TOKEN\x00"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.write(t, finding(idA, confirmed, alert))
			o := r.options(true)
			o.Env = env
			s, err := Run(t.Context(), o)
			wantIs(t, "a refused --env", err, ErrOptions)
			wantSummary(t, s, 0, 0, 0, 0)
			if err != nil && strings.Contains(err.Error(), "secret-value") {
				t.Errorf("the refusal carries a value: %v", err)
			}
			if got := r.received(t); got != "" {
				t.Errorf("a refused run delivered %q", got)
			}
		})
	}
}

// TestAnInterruptStopsARunWithNothingToDeliver: a run whose context is done
// returns its error even when every alert of the log was delivered and the
// rest are informs, so the caller says it was interrupted.
func TestAnInterruptStopsARunWithNothingToDeliver(t *testing.T) {
	for name, findings := range map[string][]*findingv1alpha1.FindingRecord{
		"an inform alone":     {finding(idB, confirmed, inform)},
		"a delivered alert":   {finding(idA, confirmed, alert), finding(idB, confirmed, inform)},
		"no finding in a log": nil,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			if findings != nil {
				r.write(t, findings...)
			}
			r.run(t, r.options(true))
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			_, err := Run(ctx, r.options(false))
			wantIs(t, "an interrupted run", err, context.Canceled)
		})
	}
}

// TestAnInterruptStopsARunOverAnEmptyLog: a log of no line has no record to
// stop at, so the run asks its context before reading it.
func TestAnInterruptStopsARunOverAnEmptyLog(t *testing.T) {
	r := newRig(t)
	mustDo(t, os.Truncate(filepath.Join(r.findings, findinglog.FileName), 0))
	wantSummary(t, r.run(t, r.options(true)), 0, 0, 0, 0)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := Run(ctx, r.options(false))
	wantIs(t, "an interrupted run over an empty log", err, context.Canceled)
}

// TestAnInterruptDuringARunStopsItAtTheNextRecord: an interrupt that comes
// once the log is read, as its lines open over an alert already delivered
// or after a delivery's mark, stops the run at the next record, though what
// is left needs no delivery.
func TestAnInterruptDuringARunStopsItAtTheNextRecord(t *testing.T) {
	for name, c := range map[string]struct {
		delivered bool
		ops       func(cancel func()) fileOps
	}{
		"as the log opens": {true, func(cancel func()) fileOps {
			return fileOps{write: osOps.write, sync: osOps.sync, openLog: func(path string) (*os.File, error) {
				cancel()
				return osOps.openLog(path)
			}}
		}},
		"after a delivery's mark": {false, func(cancel func()) fileOps {
			return fileOps{write: func(f *os.File, b []byte) (int, error) {
				n, err := f.Write(b)
				cancel()
				return n, err
			}, sync: osOps.sync, openLog: osOps.openLog}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.write(t, finding(idA, confirmed, alert), finding(idB, confirmed, inform))
			if c.delivered {
				wantSummary(t, r.run(t, r.options(true)), 1, 0, 0, 1)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			s, err := run(ctx, r.options(!c.delivered), c.ops(cancel))
			wantIs(t, "an interrupted run", err, context.Canceled)
			if s.Inform != 0 || s.AlreadyDelivered != 0 {
				t.Errorf("the run went on past the interrupt: %s", describe(s))
			}
		})
	}
}

// TestAWriteNoReportClosesIsCountedWhenNoWriterHoldsTheLog: a finding line
// after the last report is a write still open while a writer holds the log,
// and one never to be closed once none does; either way it is not
// delivered, and only the second is counted, in bytes.
func TestAWriteNoReportClosesIsCountedWhenNoWriterHoldsTheLog(t *testing.T) {
	r := newRig(t)
	r.write(t, finding(idA, confirmed, alert))
	wantSummary(t, r.run(t, r.options(true)), 1, 0, 0, 0)
	rec := &findingv1alpha1.Record{Record: &findingv1alpha1.Record_FindingRecord{FindingRecord: finding(idB, confirmed, alert)}}
	line, err := findinglog.Line(rec)
	mustDo(t, err)
	mustDo(t, appendFile(filepath.Join(r.findings, findinglog.FileName), append(line, '\n')))

	held, err := os.Open(filepath.Join(r.findings, findinglog.FileName))
	mustDo(t, err)
	mustDo(t, syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))
	s := r.run(t, r.options(false))
	wantSummary(t, s, 0, 1, 0, 0)
	if s.Unclosed != 0 {
		t.Errorf("a write a writer holds open was counted as %d bytes never closed", s.Unclosed)
	}
	mustDo(t, held.Close())

	s = r.run(t, r.options(false))
	wantSummary(t, s, 0, 1, 0, 0)
	if want := int64(len(line) + 1); s.Unclosed != want {
		t.Errorf("a write no writer holds counted %d bytes, want %d", s.Unclosed, want)
	}
	if got := r.delivered(t); got != keyA {
		t.Errorf("delivered list = %q, want A alone", got)
	}
}
