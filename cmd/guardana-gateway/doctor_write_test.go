package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

var errDeviceFull = errors.New("no space left on device")

// fullDevice takes room bytes and refuses the rest, as a full device does.
type fullDevice struct {
	room    int
	written bytes.Buffer
}

func (f *fullDevice) Write(p []byte) (int, error) {
	left := f.room - f.written.Len()
	if len(p) <= left {
		return f.written.Write(p)
	}
	f.written.Write(p[:left])
	return left, errDeviceFull
}

// TestDoctorFailsAReportItCouldNotWrite: a configuration every check passes,
// printed to a stdout that fills at the first line, in the middle of the
// settings and before the last check; each run fails and says why on stderr.
// The same tree with room for the whole report passes, so it is the write
// that fails each of them.
func TestDoctorFailsAReportItCouldNotWrite(t *testing.T) {
	tr := newTree(t)
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	whole := &fullDevice{room: 1 << 20}
	var stderr bytes.Buffer
	if status := doctor(context.Background(), tr.config, whole, &stderr); status != exitOK {
		t.Fatalf("doctor did not pass with room for its report:\n%s\n%s", whole.written.String(), stderr.String())
	}
	size := whole.written.Len()
	for _, room := range []int{0, size / 2, size - 1} {
		out := &fullDevice{room: room}
		stderr.Reset()
		if status := doctor(context.Background(), tr.config, out, &stderr); status == exitOK {
			t.Errorf("room for %d of %d bytes: doctor passed a report it could not write", room, size)
		}
		if !strings.Contains(stderr.String(), errDeviceFull.Error()) {
			t.Errorf("room for %d of %d bytes: stderr does not say the report was not written: %q", room, size, stderr.String())
		}
	}
}

// shortDevice takes all but the last byte of each write and reports no error,
// as a writer that breaks io.Writer's contract does.
type shortDevice struct{}

func (shortDevice) Write(p []byte) (int, error) { return max(len(p)-1, 0), nil }

// onceRefused refuses the first write and takes every later one.
type onceRefused struct {
	refused bool
	taken   int
}

func (o *onceRefused) Write(p []byte) (int, error) {
	if !o.refused {
		o.refused = true
		return 0, errDeviceFull
	}
	o.taken += len(p)
	return len(p), nil
}

// TestDoctorFailsAReportWrittenShortOrRefusedOnce: a write that takes less
// than it was given without an error fails the report, and so does one
// refused write followed by writes that would succeed: the report already
// lacks a line, so nothing more is written and doctor fails.
func TestDoctorFailsAReportWrittenShortOrRefusedOnce(t *testing.T) {
	tr := newTree(t)
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	var stderr bytes.Buffer
	if status := doctor(context.Background(), tr.config, shortDevice{}, &stderr); status == exitOK {
		t.Error("doctor passed a report every write of which came back short")
	}
	if !strings.Contains(stderr.String(), io.ErrShortWrite.Error()) {
		t.Errorf("stderr does not name the short write: %q", stderr.String())
	}
	stderr.Reset()
	once := &onceRefused{}
	if status := doctor(context.Background(), tr.config, once, &stderr); status == exitOK {
		t.Error("doctor passed a report whose first line was refused")
	}
	if once.taken != 0 {
		t.Errorf("doctor wrote %d byte(s) after a refused write", once.taken)
	}
	if !strings.Contains(stderr.String(), errDeviceFull.Error()) {
		t.Errorf("stderr does not say the report was not written: %q", stderr.String())
	}
}
