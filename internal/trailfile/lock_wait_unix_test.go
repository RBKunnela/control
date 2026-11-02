//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package trailfile

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestAWriterWaitsOutAReadersProbe: Open beside a reader's shared lock held
// for a moment opens once it lets go; one held past the bound is refused as
// held by another writer.
func TestAWriterWaitsOutAReadersProbe(t *testing.T) {
	path := trailPath(t)
	_ = openWriter(t, path).Close()
	for _, c := range []struct {
		hold time.Duration
		want error
	}{{50 * time.Millisecond, nil}, {500 * time.Millisecond, ErrLocked}} {
		f, err := os.Open(path) //nolint:gosec // G304: the test's own temp file
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			time.Sleep(c.hold)
			_ = f.Close()
			close(done)
		}()
		w, err := Open(path)
		if !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("Open beside a shared lock held %v: %v, want %v", c.hold, err, c.want)
		}
		if w != nil {
			_ = w.Close()
		}
		<-done
	}
}
