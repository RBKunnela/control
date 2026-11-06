package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/console"
)

// consoleName is the word that reaches the page, and consoleForm how the help
// spells what follows it.
const (
	consoleName = "console"
	consoleForm = "--approvals <dir> [--pause <f>] [--approver-id <id>] [--inbox <dir>]\n      [--until-stdin-closes]"
)

// consoleStopWait bounds how long a stopping page waits for requests in
// flight before it drops them.
const consoleStopWait = time.Second

type consoleFlags struct {
	dir, pauseFile, approverID, inbox string
	untilStdinCloses                  bool
}

func consoleFlagsOf(command string, out io.Writer) (*flag.FlagSet, *consoleFlags) {
	flags := commandFlags(command, out)
	var c consoleFlags
	flags.StringVar(&c.dir, "approvals", "", "the approvals directory the page lists and answers")
	flags.StringVar(&c.pauseFile, "pause", "", "the pause file the page shows and writes")
	flags.StringVar(&c.approverID, "approver-id", "", "who is answering, recorded on every answer as claimed and never authenticated")
	flags.StringVar(&c.inbox, "inbox", "", "the plane's approvals.inbox_dir, named in the command that signs a hold; without --approver-id the page only reads, as an operator's own account")
	flags.BoolVar(&c.untilStdinCloses, "until-stdin-closes", false, "stop when standard input reaches its end")
	return flags, &c
}

func consoleFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := consoleFlagsOf(command, out)
	return flags
}

func consoleCommand(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveConsole(ctx, args, os.Stdin, stdout, stderr)
}

// serveConsole serves the page until ctx ends, the server fails, or, with
// --until-stdin-closes, stdin reaches its end. Standard output carries one
// line, the page's address with its token in the fragment, and nothing else:
// whoever starts the page reads that line and nobody else sees the token.
func serveConsole(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags, c := consoleFlagsOf(consoleName, stderr)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	switch {
	case flags.NArg() != 0:
		return usageError(stderr, consoleName, "takes flags only")
	case c.dir == "":
		return usageError(stderr, consoleName, "--approvals names the approvals directory the page answers")
	case c.inbox != "" && c.approverID == "":
		return serveReader(ctx, c, stdin, stdout, stderr)
	case c.approverID == "":
		return usageError(stderr, consoleName, "--approver-id names who is answering; an approval nobody claims is not an answer; "+
			"--inbox alone lists for signed answers")
	}
	if err := console.CheckApproverID(c.approverID); err != nil {
		return usageError(stderr, consoleName, "--approver-id: "+err.Error())
	}
	store, err := approvals.OpenApprover(c.dir)
	if err != nil {
		return fail(stderr, consoleName, err)
	}
	status := servePage(ctx, c, console.Options{Approvals: store, ApproverID: c.approverID, Inbox: c.inbox}, stdin, stdout, stderr)
	if err := store.Close(); err != nil && status == exitOK {
		return fail(stderr, consoleName, err)
	}
	return status
}

// serveReader serves a page that only reads the approvals directory, as an
// operator under the signed authority: it answers nothing and shows the
// command that signs each hold.
func serveReader(ctx context.Context, c *consoleFlags, stdin io.Reader, stdout, stderr io.Writer) int {
	r, err := approvals.OpenReader(c.dir)
	if err != nil {
		return fail(stderr, consoleName, err)
	}
	status := servePage(ctx, c, console.Options{Reader: r, Inbox: c.inbox}, stdin, stdout, stderr)
	if err := r.Close(); err != nil && status == exitOK {
		return fail(stderr, consoleName, err)
	}
	return status
}

// servePage binds an IP literal on the loopback, never a name another
// resolver could answer, and serves the page on it.
func servePage(ctx context.Context, c *consoleFlags, o console.Options, stdin io.Reader, stdout, stderr io.Writer) int {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return fail(stderr, consoleName, err)
	}
	token := console.NewToken()
	o.Directory, o.PauseFile, o.Host, o.Token = c.dir, c.pauseFile, ln.Addr().String(), token
	handler, err := console.New(o)
	if err != nil {
		return fail(stderr, consoleName, errors.Join(err, ln.Close()))
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(stderr, brand.CLI+": "+consoleName+": ", 0),
	}
	if _, err := fmt.Fprintf(stdout, "page: http://%s/#t=%s\n", ln.Addr(), token); err != nil {
		return fail(stderr, consoleName, errors.Join(fmt.Errorf("writing to standard output: %w", err), ln.Close()))
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	var stdinDone <-chan struct{}
	if c.untilStdinCloses {
		stdinDone = watchStdin(stdin)
	}
	select {
	case err := <-served:
		return fail(stderr, consoleName, err)
	case <-ctx.Done():
	case <-stdinDone:
	}
	return stopPage(srv, served, stderr)
}

// watchStdin closes the returned channel when stdin ends. A read error ends
// it too: a pipe that cannot be read can no longer say its writer is alive.
func watchStdin(stdin io.Reader) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, stdin)
		close(done)
	}()
	return done
}

// stopPage lets requests in flight finish within consoleStopWait and drops
// the rest.
func stopPage(srv *http.Server, served <-chan error, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), consoleStopWait)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		if cerr := srv.Close(); cerr != nil {
			return fail(stderr, consoleName, errors.Join(err, cerr))
		}
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return fail(stderr, consoleName, err)
	}
	return exitOK
}
