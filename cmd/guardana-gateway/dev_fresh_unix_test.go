//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/files"
)

// TestADevRenewalGivesUpOnAReaderLockOfTheStatement: a reader holding a
// shared flock of the statement file holds a renewal off only until its
// context ends; a running plane's renewal fails, and says so on the log, once
// it waited a whole period, and halting the plane does not wait on the reader.
func TestADevRenewalGivesUpOnAReaderLockOfTheStatement(t *testing.T) {
	b := &controlv1.PolicyBundle{Ref: &controlv1.PolicyBundleRef{BundleId: "dev-policy", Digest: "sha256:" + strings.Repeat("a", 64)}}
	path := filepath.Join(t.TempDir(), "policy.statement")
	s, err := newDevSigner(b, 1, time.Minute, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.renew(t.Context(), time.Now()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path) //nolint:gosec // G304: a path in this test's own directory
	if err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path) //nolint:gosec // G304: a path in this test's own directory
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	if err := syscall.Flock(int(reader.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if err := returnsSoon(t, func() error { return s.renew(ctx, time.Now().Add(time.Second)) }); !errors.Is(err, files.ErrLockHeld) {
		t.Errorf("a renewal under a reader's lock = %v, want files.ErrLockHeld", err)
	}
	var log syncBuffer
	s.every = 50 * time.Millisecond
	s.start(t.Context(), &log)
	line := waitFor(t, &log, "renewing the freshness statement")
	_ = returnsSoon(t, func() error { s.halt(); return nil })
	if !strings.Contains(line, string(files.ErrLockHeld)) || !strings.Contains(line, context.DeadlineExceeded.Error()) {
		t.Errorf("the renewal logged %q before halt, want the lock held past its period", line)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) { //nolint:gosec // G304: a path in this test's own directory
		t.Errorf("the statement changed under a reader's lock: %v", err)
	}
}

// returnsSoon runs f and fails the test when it has not returned within five
// seconds.
func returnsSoon(t *testing.T, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("still running after 5s while a reader holds a lock of the statement")
		return nil
	}
}
