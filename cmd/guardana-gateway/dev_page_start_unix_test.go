//go:build unix

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakePage is a sibling whose console is the shell script body.
func fakePage(t *testing.T, body string) sibling {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-control")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil { //nolint:gosec // G306: a script this test runs
		t.Fatal(err)
	}
	return sibling{path: path, timeout: time.Second}
}

// validToken is 43 characters of the base64url alphabet, as the page draws.
var validToken = strings.Repeat("Ab0-_", 8) + "xyz"

// TestStartPageHoldsThePageToItsLine: a page that prints its line is taken
// and stops once its input closes; one that prints another line, one that
// prints nothing and one that exits first are each refused, and a refusal
// never repeats what the page printed.
func TestStartPageHoldsThePageToItsLine(t *testing.T) {
	t.Parallel()
	good := "page: http://127.0.0.1:4242/#t=" + validToken
	for _, c := range []struct {
		name, body, says string
	}{
		{"its line", "echo '" + good + "'; cat >/dev/null", ""},
		{"a name for the host", "echo 'page: http://localhost:4242/#t=" + validToken + "'; cat >/dev/null", "not its page line"},
		{"a short token", "echo 'page: http://127.0.0.1:4242/#t=" + validToken[1:] + "'; cat >/dev/null", "not its page line"},
		{"more on the line", "echo '" + good + " more'; cat >/dev/null", "not its page line"},
		{"no newline", "printf '%s' '" + good + "'; cat >/dev/null", "printed no page line"},
		{"nothing", "cat >/dev/null", "printed no page line"},
		{"an exit", "exit 0", "before it printed its page line"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var stderr syncBuffer
			started := time.Now()
			pg, err := startPage(fakePage(t, c.body), devState{dir: t.TempDir()}, &stderr)
			switch {
			case c.says == "" && err != nil:
				t.Fatalf("its own line refused: %v", err)
			case c.says == "":
				if pg.line != good {
					t.Errorf("the line kept is %q", pg.line)
				}
				if err := pg.halt(); err != nil {
					t.Errorf("a page that stops on its input's end: %v", err)
				}
			case err == nil || !strings.Contains(err.Error(), c.says):
				t.Fatalf("startPage = %v, want %q", err, c.says)
			case strings.Contains(err.Error(), validToken[:20]):
				t.Errorf("the refusal repeats what the page printed: %v", err)
			}
			if limit := pageStartWait + pageStopWait + 2*time.Second; time.Since(started) > limit {
				t.Errorf("took %v, past %v", time.Since(started), limit)
			}
		})
	}
}

// TestHaltReportsAPageThatFailed: a page that took its line and then exits
// with a failure once its input closes makes halt fail, naming the console.
func TestHaltReportsAPageThatFailed(t *testing.T) {
	t.Parallel()
	var stderr syncBuffer
	pg, err := startPage(fakePage(t, "echo 'page: http://127.0.0.1:4242/#t="+validToken+"'; cat >/dev/null; exit 3"), devState{dir: t.TempDir()}, &stderr)
	if err != nil {
		t.Fatalf("its own line refused: %v", err)
	}
	if err := pg.halt(); err == nil || !strings.Contains(err.Error(), "console failed: exit status 3") {
		t.Errorf("halt over a page that exited 3 = %v, want its failure", err)
	}
}

// endless is a reader of one byte repeated forever, which holds no newline.
type endless struct{}

func (endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func (endless) Close() error { return nil }

// TestTheFirstLineIsBounded: a page that writes without a newline is cut at
// maxPageLine bytes rather than read for good.
func TestTheFirstLineIsBounded(t *testing.T) {
	t.Parallel()
	select {
	case line := <-readFirstLine(io.NopCloser(endless{})):
		if len(line) != maxPageLine || strings.Contains(line, "\n") {
			t.Fatalf("the first line is %d bytes, want %d with no newline", len(line), maxPageLine)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a line with no end did not stop")
	}
}
