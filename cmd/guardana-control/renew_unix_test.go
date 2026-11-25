//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	ondisk "github.com/guardana/control/internal/files"
)

// specialOuts are the --out paths only this platform makes: a named pipe.
func specialOuts(t *testing.T, dir string) map[string]string {
	t.Helper()
	return map[string]string{"a named pipe": mkfifo(t, filepath.Join(dir, "statement-pipe"))}
}

// TestARenewGivesUpOnAReaderLockOfOutWithinTheFloorsWait: any account that
// can read --out, a public file, may hold a shared flock of it. The renew
// waits for it only within the floor directory's wait, exits 1 saying a lock
// of --out is held and nothing was written there, and lets the floor
// directory's lock go, so the next renew under it is not refused.
func TestARenewGivesUpOnAReaderLockOfOutWithinTheFloorsWait(t *testing.T) {
	r := newRenewTree(t)
	renewed(t, r, r.bundle, 3)
	saved := floorLockWait
	floorLockWait = 300 * time.Millisecond
	t.Cleanup(func() { floorLockWait = saved })
	reader, err := os.Open(r.out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	if err := syscall.Flock(int(reader.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	at := func(serial int) renewPaths {
		p := r.paths()
		p.bundle = filepath.Join(r.dir, "b"+strconv.Itoa(serial)+".bundle")
		writeBundle(t, p.bundle, renewDocument(serial, "allow-reads"), r.bundleSigner)
		return p
	}
	type exit struct {
		code   int
		stderr string
	}
	done := make(chan exit, 1)
	go func() {
		var stderr bytes.Buffer
		code := renew(at(4), time.Now().Add(time.Second), &bytes.Buffer{}, &stderr)
		done <- exit{code, stderr.String()}
	}()
	var got exit
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("renew is still running after 5s while a reader holds a lock of --out")
	}
	if got.code != exitFail || !strings.Contains(got.stderr, string(ondisk.ErrLockHeld)) || !strings.Contains(got.stderr, r.out) {
		t.Errorf("renew: exit %d, stderr %q; want exit 1 naming --out and the lock held", got.code, got.stderr)
	}
	if _, st := freshStatement(t, r.out); st.Serial() != 3 {
		t.Errorf("--out holds serial %d, want 3: the refused renew wrote it", st.Serial())
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := renew(at(5), time.Now().Add(time.Second), &bytes.Buffer{}, &stderr); code != exitOK {
		t.Errorf("the next renew: exit %d, stderr %q; want 0", code, stderr.String())
	}
}
