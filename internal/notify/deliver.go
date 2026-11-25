package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"time"
)

// waitDelay bounds how long a delivery waits, once the program has exited or
// been killed, for a process it left holding its output open.
const waitDelay = 2 * time.Second

// baseEnv is all of this process's environment a program receives, each
// variable only when set here.
var baseEnv = []string{"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER"}

// programInput is what the program reads its line from; a test delays it.
var programInput = func(line []byte) io.Reader { return bytes.NewReader(line) }

// lineIn is a program's standard input. exec drops EPIPE from its copy to
// a program that exited 0, which is how a program that closed its input
// before the whole line was written would pass for a delivery; lineIn keeps
// the write's error, through the WriterTo io.Copy prefers.
type lineIn struct {
	r   io.Reader
	err error
}

func (in *lineIn) Read(p []byte) (int, error) { return in.r.Read(p) }

func (in *lineIn) WriteTo(w io.Writer) (int64, error) {
	n, err := io.Copy(w, in.r)
	in.err = err
	return n, err
}

// programEnv is the program's whole environment: each variable of baseEnv
// and of names this process has. It is never nil, since a nil environment
// is exec's signal to pass this process's whole one.
func programEnv(names []string) []string {
	env := []string{}
	for _, name := range append(slices.Clone(baseEnv), names...) {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// deliver runs the program once with line on its standard input, and
// returns nil only when the whole line was written to it, it exited 0
// within the timeout, released its output within waitDelay and its process
// group was then killed.
func deliver(ctx context.Context, o Options, line []byte) error {
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	// The program and its arguments are the operator's own command line;
	// nothing read from the findings log reaches them, only the standard
	// input.
	//nolint:gosec // G204: the operator names the program and its arguments, and no shell runs them
	cmd := exec.CommandContext(ctx, o.Program, o.Args...)
	in := &lineIn{r: programInput(line)}
	cmd.Stdin, cmd.Env = in, programEnv(o.Env)
	cmd.Stdout, cmd.Stderr = o.Stdout, o.Stderr
	cmd.WaitDelay = waitDelay
	ownGroup(cmd)
	err := errors.Join(cmd.Run(), endGroup(cmd))
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w (%s): %w", ErrTimeout, o.Timeout, err)
	}
	// Read only once Run returned nil: Run then waited for the copy.
	if err == nil && in.err != nil {
		return fmt.Errorf("writing the line to the program: %w", in.err)
	}
	return err
}
