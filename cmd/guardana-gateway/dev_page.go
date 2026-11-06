package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/guardana/control/internal/brand"
)

// The page's bounds: how long it has to print its line, how long that line
// may be, and how long it has to stop once its standard input closed.
const (
	pageStartWait = 10 * time.Second
	maxPageLine   = 256
	pageStopWait  = 5 * time.Second
)

// devApprover is the approver id the page is started under. A dev plane holds
// under the signed authority, so the page files no answer; it shows the
// command that signs one.
const devApprover = "dev-page"

// pageLine is the one line the page prints on standard output.
var pageLine = regexp.MustCompile(`^page: http://127\.0\.0\.1:[0-9]{1,5}/#t=[A-Za-z0-9_-]{43}\n$`)

// devPage is the approver's page, run as the sibling binary over a pipe
// whose end stops it. line is the one line it printed, which dev relays to
// its own standard output and nowhere else.
type devPage struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	line  string
	// exited is closed once the page's process has exited, and waitErr,
	// how it exited, is written before that.
	exited  chan struct{}
	waitErr error
}

// startPage starts the page over the plane's approvals directory, its inbox
// and its pause file, in a process group of its own so a terminal's interrupt reaches dev
// alone, and reads its first line within its bounds.
func startPage(control sibling, st devState, stderr io.Writer) (*devPage, error) {
	cmd := exec.Command(control.path, "console", //nolint:gosec // G204: the sibling found beside this binary, run without a shell
		"--approvals", st.path(stateApprovals), "--pause", st.path(statePause),
		"--approver-id", devApprover, "--inbox", st.path(stateInbox), "--until-stdin-closes")
	cmd.Stderr = stderr
	ownProcessGroup(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	// A pipe of dev's own rather than the one exec makes, which Wait closes
	// under a reader that may not be done with it.
	stdout, pageOut, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = pageOut
	err = cmd.Start()
	if cerr := pageOut.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("starting %s console: %w", brand.CLI, err), stdout.Close())
	}
	pg := &devPage{cmd: cmd, stdin: stdin, exited: make(chan struct{})}
	lines := readFirstLine(stdout)
	go func() {
		pg.waitErr = cmd.Wait()
		close(pg.exited)
	}()
	select {
	case line := <-lines:
		if pageLine.MatchString(line) {
			pg.line = line[:len(line)-1]
			return pg, nil
		}
		if line == "" {
			return nil, errors.Join(fmt.Errorf("%s console closed its output before it printed its page line", brand.CLI), pg.halt())
		}
		// The line is not repeated: whatever the page printed may hold its
		// token.
		return nil, errors.Join(fmt.Errorf("%s console printed a first line that is not its page line", brand.CLI), pg.halt())
	case <-pg.exited:
		return nil, fmt.Errorf("%s console exited before it printed its page line", brand.CLI)
	case <-time.After(pageStartWait):
		return nil, errors.Join(fmt.Errorf("%s console printed no page line within %v", brand.CLI, pageStartWait), pg.halt())
	}
}

// readFirstLine reads r's first line, of at most maxPageLine bytes with its
// newline, and then discards the rest, so the page never blocks on a pipe
// nobody reads. A line too long or cut short arrives as it was read, and
// fails the pattern.
func readFirstLine(r io.ReadCloser) <-chan string {
	lines := make(chan string, 1)
	go func() {
		defer func() { _ = r.Close() }()
		br := bufio.NewReaderSize(r, maxPageLine)
		line, _ := br.ReadSlice('\n')
		lines <- string(line)
		_, _ = io.Copy(io.Discard, br)
	}()
	return lines
}

// halt closes the page's standard input, which stops it, and kills it past
// pageStopWait. A page that exited with a failure is reported, so dev never
// ends well over a console that did not.
func (pg *devPage) halt() error {
	err := pg.stdin.Close()
	select {
	case <-pg.exited:
		if pg.waitErr != nil {
			err = errors.Join(err, fmt.Errorf("%s console failed: %w", brand.CLI, pg.waitErr))
		}
		return err
	case <-time.After(pageStopWait):
	}
	if kerr := pg.cmd.Process.Kill(); kerr != nil && !errors.Is(kerr, os.ErrProcessDone) {
		err = errors.Join(err, kerr)
	}
	<-pg.exited
	return errors.Join(err, fmt.Errorf("%s console did not stop within %v of its input closing, and was killed", brand.CLI, pageStopWait))
}
