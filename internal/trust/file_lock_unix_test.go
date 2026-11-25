//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package trust_test

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/guardana/control/internal/policystate"
	"github.com/guardana/control/internal/trust"
)

// movingClock is a clock a test moves while a lookup runs; once armed, it
// announces each reading.
type movingClock struct {
	mu   sync.Mutex
	now  time.Time
	read chan struct{}
}

func (c *movingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.read != nil {
		select {
		case c.read <- struct{}{}:
		default:
		}
	}
	return c.now
}

func (c *movingClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func (c *movingClock) arm() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.read = make(chan struct{}, 1)
	return c.read
}

// holdLock takes the exclusive lock of the floor directory at dir, as
// another process raising it would, and returns what releases it.
func holdLock(t *testing.T, dir string) func() {
	t.Helper()
	held, err := os.Open(dir) //nolint:gosec // G304: the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := syscall.Flock(int(held.Fd()), syscall.LOCK_UN); err != nil {
			t.Error(err)
		}
		if err := held.Close(); err != nil {
			t.Error(err)
		}
	}
}

// TestALookupHeldOnTheFloorPastTheExpiryNamesNoKey begins a lookup of a
// newer roster a second before its expiry, holds the floor's lock until a
// second after it, and then lets the lookup go on.
func TestALookupHeldOnTheFloorPastTheExpiryNamesNoKey(t *testing.T) {
	dir := t.TempDir()
	path, floor := filepath.Join(dir, "roster.json"), filepath.Join(dir, "floor")
	if err := policystate.InitAuthority(t.Context(), floor, "roster-a"); err != nil {
		t.Fatal(err)
	}
	writeRoster(t, path, signed(t, doc(1, "alice")))
	clock := &movingClock{now: clockAt(t, "2026-10-30T12:00:00Z")}
	roster, err := trust.Open(t.Context(), trust.Config{Root: public("root"), RosterID: "roster-a", Path: path, FloorDir: floor, Clock: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	next := doc(2, "alice")
	next["expiresAt"] = "2026-10-30T12:00:01Z"
	writeRoster(t, path, signed(t, next))
	read := clock.arm()
	release := holdLock(t, floor)
	answered := make(chan trust.Answer, 1)
	go func() { answered <- roster.Lookup(t.Context(), idOf("alice")) }()
	select {
	case <-read:
	case <-time.After(10 * time.Second):
		release()
		t.Fatal("the lookup never read the clock")
	}
	clock.set(clockAt(t, "2026-10-30T12:00:02Z"))
	release()
	var a trust.Answer
	select {
	case a = <-answered:
	case <-time.After(10 * time.Second):
		t.Fatal("the lookup did not return once the lock was released")
	}
	wantNoKey(t, "a lookup that took the roster after its expiry", a, trust.StateUnavailable, trust.CauseExpired)
}
