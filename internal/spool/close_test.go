package spool

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// closeFailingFile is the file seam with a Close that fails once fail is set;
// the descriptor is still closed.
type closeFailingFile struct {
	*os.File
	fail *atomic.Bool
}

func (f *closeFailingFile) Close() error {
	err := f.File.Close()
	if f.fail.Load() {
		return errors.Join(err, errBoomClose)
	}
	return err
}

var errBoomClose = errors.New("close refused")

// TestCloseReportsASegmentThatFailedToClose: a segment acknowledged whole is
// retired at once, so its failed close leaves nothing open for Close to
// close; Close still answers the failure, and the spool is not reported
// closed cleanly.
func TestCloseReportsASegmentThatFailedToClose(t *testing.T) {
	var fail atomic.Bool
	s, err := Open(Options{
		Dir: t.TempDir(), MaxBytes: 1 << 20, SegmentBytes: 1 << 16,
		Fsync: FsyncInterval, Interval: time.Hour,
		openFile: func(root *os.Root, name string, flag int) (segmentFile, error) {
			f, err := root.OpenFile(name, flag, 0o600)
			if err != nil {
				return nil, err
			}
			return &closeFailingFile{File: f, fail: &fail}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(context.Background(), sample(0)); err != nil {
		t.Fatal(err)
	}
	r, err := s.Reader(Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck // read only
	_, at, err := r.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := r.Ack(at); !errors.Is(err, errBoomClose) {
		t.Fatalf("Ack retiring the segment = %v, want the close failure", err)
	}
	if err := s.Close(); !errors.Is(err, errBoomClose) {
		t.Errorf("Close after a segment failed to close = %v, want that failure", err)
	}
}
