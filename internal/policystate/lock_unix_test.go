//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package policystate_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policystate"
)

func TestRaiseWaitsForTheDirectoryLockUntilItsContextEnds(t *testing.T) {
	dir, s := raised(t)
	before := readFile(t, filepath.Join(dir, fileA))
	held, err := os.Open(dir) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if f, err := s.Raise(ctx, statement(t, idA, 6, d6, "11:30:00"), noon(t)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Raise while another file holds the lock: %s, %v; want the context's deadline", describe(f), err)
	}
	if after := readFile(t, filepath.Join(dir, fileA)); after != before {
		t.Fatalf("Raise wrote without the lock: %s", after)
	}
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if f, err := s.Raise(t.Context(), statement(t, idA, 6, d6, "11:30:00"), noon(t)); err != nil || f.Serial() != 6 {
		t.Errorf("Raise once the lock is free: %s, %v", describe(f), err)
	}
}

func TestResetWaitsForTheDirectoryLockUntilItsContextEnds(t *testing.T) {
	dir, _ := raised(t)
	held, err := os.Open(dir) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err := policystate.Reset(ctx, dir, policystate.KindPlane, floorAt3(t, "09:00:00"), "withdrawn"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Reset while another file holds the lock: %v; want the context's deadline", err)
	}
}

func TestAReadWaitsForAnyOtherHolderOfTheLock(t *testing.T) {
	dir, s := raised(t)
	held, err := os.Open(dir) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if f, err := s.Floor(ctx, idA); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Floor while a raise holds the lock: %s, %v; want the context's deadline", describe(f), err)
	}
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if f, err := s.Floor(ctx, idA); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Floor while another holds the lock shared: %s, %v; want the context's deadline", describe(f), err)
	}
	ctx, cancel = context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if f, err := s.Raise(ctx, statement(t, idA, 6, d6, "11:30:00"), noon(t)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Raise while a read holds the lock: %s, %v; want the context's deadline", describe(f), err)
	}
}

// holdLock takes dir's lock exclusive through a file of the test's own and
// returns what releases it.
func holdLock(t *testing.T, dir string) func() {
	t.Helper()
	held, err := os.Open(dir) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	return func() { _ = held.Close() }
}

// raiseWaiting starts a raise to serial 6 that waits on the lock the test
// holds, and returns where its answer arrives.
func raiseWaiting(t *testing.T, s *policystate.Store) <-chan error {
	t.Helper()
	st, now := statement(t, idA, 6, d6, "11:30:00"), noon(t)
	done := make(chan error, 1)
	go func() {
		_, err := s.Raise(context.Background(), st, now)
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	return done
}

func answer(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the raise never answered")
		return nil
	}
}

func TestRaiseReadsTheFloorOnlyOnceItHoldsTheLock(t *testing.T) {
	dir, s := raised(t)
	release := holdLock(t, dir)
	done := raiseWaiting(t, s)
	serial7 := `{"schema_version":"1.0","bundle_id":"bundle-a","serial":7,"digest":"` + d7 +
		`","issued_at":"2026-09-11T11:45:00Z","latest_issued_at":"2026-09-11T11:45:00Z","reset_reason":null,"reset_from":null}` + "\n"
	writeFile(t, filepath.Join(dir, fileA), serial7)
	release()
	if err := answer(t, done); !errors.Is(err, policy.ErrBelowFloor) {
		t.Errorf("a raise to 6 that waited while the floor rose to 7: %v, want ErrBelowFloor", err)
	}
	if got := readFile(t, filepath.Join(dir, fileA)); got != serial7 {
		t.Errorf("the floor file holds %s, want serial 7", got)
	}
}

func TestARaiseWaitingForTheLockRefusesADirectorySwappedMeanwhile(t *testing.T) {
	dir, s := raised(t)
	before := readFile(t, filepath.Join(dir, fileA))
	release := holdLock(t, dir)
	done := raiseWaiting(t, s)
	if err := os.Rename(dir, dir+".old"); err != nil {
		t.Fatal(err)
	}
	if err := policystate.Init(t.Context(), dir, policystate.KindPlane, idA); err != nil {
		t.Fatal(err)
	}
	release()
	if err := answer(t, done); !errors.Is(err, policystate.ErrDirectoryChanged) {
		t.Errorf("a raise that waited while the directory was swapped: %v, want ErrDirectoryChanged", err)
	}
	if got := readFile(t, filepath.Join(dir+".old", fileA)); got != before {
		t.Errorf("the raise wrote into the directory moved away: %s", got)
	}
	awaitWriters(t, dir+".old", 0)
}

// awaitWriters waits until n writers of this process wait for or hold the
// lock of dir.
func awaitWriters(t *testing.T, dir string, n int) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		got, err := policystate.WritersWaiting(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d writers wait for the lock, want %d", got, n)
		}
	}
}

// TestAReadThatStartsWhileARaiseWaitsReadsTheRaisedFloor: reads of this
// process that start while a raise waits for the lock go after the raise, so
// each reads the raised floor, whichever of them tries the lock first once it
// is free.
func TestAReadThatStartsWhileARaiseWaitsReadsTheRaisedFloor(t *testing.T) {
	dir, s := raised(t)
	readers := make([]*policystate.Store, 8)
	for i := range readers {
		readers[i] = open(t, dir)
	}
	release := holdLock(t, dir)
	done := raiseWaiting(t, s)
	awaitWriters(t, dir, 1)
	read := make(chan string, len(readers))
	for _, r := range readers {
		go func() {
			rec, err := r.Record(context.Background(), idA)
			if err != nil {
				read <- err.Error()
				return
			}
			read <- describe(rec.Floor)
		}()
	}
	time.Sleep(50 * time.Millisecond)
	release()
	if err := answer(t, done); err != nil {
		t.Fatalf("the raise: %v", err)
	}
	for range readers {
		select {
		case got := <-read:
			if !strings.Contains(got, " serial 6 ") {
				t.Errorf("a read started while the raise waited read %s, want serial 6", got)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a read never answered")
		}
	}
}

// TestAReadWaitingBehindARaiseEndsWithItsContext: a read that waits for a
// raise of this process to take and release the lock still ends when its own
// context does, while the raise goes on waiting.
func TestAReadWaitingBehindARaiseEndsWithItsContext(t *testing.T) {
	dir, s := raised(t)
	reader := open(t, dir)
	release := holdLock(t, dir)
	done := raiseWaiting(t, s)
	awaitWriters(t, dir, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	read := make(chan error, 1)
	go func() {
		_, err := reader.Record(ctx, idA)
		read <- err
	}()
	select {
	case err := <-read:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("a read behind a waiting raise: %v, want its deadline", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("a read behind a waiting raise outlived its context")
	}
	release()
	if err := answer(t, done); err != nil {
		t.Errorf("the raise: %v", err)
	}
}

// TestARaiseThatGivesUpLeavesReadsFree: a raise whose context ends while
// another process holds the lock stops counting as a writer, so a read once
// the lock is free runs at once instead of waiting out its context.
func TestARaiseThatGivesUpLeavesReadsFree(t *testing.T) {
	dir, s := raised(t)
	release := holdLock(t, dir)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err := s.Raise(ctx, statement(t, idA, 6, d6, "11:30:00"), noon(t)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a raise behind a held lock: %v, want its deadline", err)
	}
	release()
	awaitWriters(t, dir, 0)
	read, cancelRead := context.WithTimeout(t.Context(), time.Second)
	defer cancelRead()
	if rec, err := s.Record(read, idA); err != nil || rec.Floor.Serial() != 5 {
		t.Errorf("a read after the raise gave up: %s, %v; want serial 5", describe(rec.Floor), err)
	}
}

func TestARaiseCompletesWhileReadsRunWithoutPause(t *testing.T) {
	dir, s := raised(t)
	stop := make(chan struct{})
	readErrs := make([]error, 8)
	var wg sync.WaitGroup
	for i := range readErrs {
		r := open(t, dir)
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := r.Record(context.Background(), idA); err != nil && readErrs[i] == nil {
					readErrs[i] = err
				}
			}
		})
	}
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	f, err := s.Raise(ctx, statement(t, idA, 6, d6, "11:30:00"), noon(t))
	close(stop)
	wg.Wait()
	if err != nil || f.Serial() != 6 {
		t.Errorf("Raise among eight readers: %s, %v", describe(f), err)
	}
	for i, err := range readErrs {
		if err != nil {
			t.Errorf("reader %d: %v", i, err)
		}
	}
}

// helperDir is set only in a process this file starts to raise beside the
// test that started it.
const helperDir = "FLOORSTORE_HELPER_DIR"

// helperDone is what the other process prints once it raised through every
// serial, so a run that matched no test is not read as one that raised.
const helperDone = "the other process raised through every serial"

// raisesEach is how many serials each raiser walks through.
const raisesEach = 30

// walk is the statements every raiser raises with, serials 1 to raisesEach in
// order, each the same in every raiser.
func walk(t testing.TB) []policy.Statement {
	t.Helper()
	sts := make([]policy.Statement, 0, raisesEach)
	for serial := int64(1); serial <= raisesEach; serial++ {
		issued := time.Date(2026, time.September, 11, 10, 0, int(serial), 0, time.UTC).Format("15:04:05")
		sts = append(sts, statement(t, idA, serial, fmt.Sprintf("sha256:%064x", serial), issued))
	}
	return sts
}

// raiseAll raises with each statement in turn, and refuses any answer below
// the statement it raised with or below an answer it had before.
func raiseAll(s *policystate.Store, sts []policy.Statement, now time.Time) error {
	var highest int64
	for _, st := range sts {
		f, err := s.Raise(context.Background(), st, now)
		switch {
		case err == nil && f.Serial() < max(st.Serial(), highest):
			return fmt.Errorf("raise to %d returned serial %d after %d", st.Serial(), f.Serial(), highest)
		case err == nil:
			highest = f.Serial()
		case !errors.Is(err, policy.ErrBelowFloor):
			return fmt.Errorf("raise to %d: %w", st.Serial(), err)
		}
	}
	return nil
}

func TestTwoProcessesAndTwoHandlesRaisingOneFloorNeverLowerIt(t *testing.T) {
	dir := initDir(t, policystate.KindPlane)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperRaisesFromAnotherProcess$", "-test.count=1") //nolint:gosec // G204: this test's own binary
	cmd.Env = append(os.Environ(), helperDir+"="+dir)
	var other []byte
	var otherErr error
	var wg sync.WaitGroup
	wg.Go(func() { other, otherErr = cmd.CombinedOutput() })
	sts, now := walk(t), noon(t)
	errs := make([]error, 2)
	for i := range errs {
		s := open(t, dir)
		wg.Go(func() { errs[i] = raiseAll(s, sts, now) })
	}
	observer := open(t, dir)
	var seen int64
	for range 200 {
		f, err := observer.Floor(t.Context(), idA)
		if err != nil {
			t.Fatalf("Floor while raising: %v", err)
		}
		if f.Serial() < seen {
			t.Fatalf("the floor fell from %d to %d", seen, f.Serial())
		}
		seen = f.Serial()
	}
	wg.Wait()
	if otherErr != nil || !strings.Contains(string(other), helperDone) {
		t.Errorf("the other process: %v\n%s", otherErr, other)
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("handle %d: %v", i, err)
		}
	}
	if f, err := observer.Floor(t.Context(), idA); err != nil || f.Serial() != raisesEach || f.LatestIssuedAt().Format("15:04:05") != "10:00:30" {
		t.Errorf("Floor after every raise: %s, %v; want serial 30 renewed at 10:00:30", describe(f), err)
	}
}

func TestHelperRaisesFromAnotherProcess(t *testing.T) {
	dir := os.Getenv(helperDir)
	if dir == "" {
		t.Skip("run only as the other process of TestTwoProcessesAndTwoHandlesRaisingOneFloorNeverLowerIt")
	}
	if err := raiseAll(open(t, dir), walk(t), noon(t)); err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintln(os.Stderr, helperDone)
}
