package policy_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/guardana/control/internal/policy"
)

// memStore is a FloorStore in memory, for tests only: Raise holds one lock
// while it reads, judges with Floor.Raise and writes, as a store on disk does
// under its file lock. writeErr, when set, fails every write after the floor
// judged the statement; afterWrite, when set, is returned after a write that
// was made; readErr fails every read. raises counts the writes made.
type memStore struct {
	mu         sync.Mutex
	floors     map[string]policy.Floor
	writeErr   error
	afterWrite error
	readErr    error
	raises     int
}

var (
	errWriteFailed = errors.New("memStore: the write failed")
	errSyncFailed  = errors.New("memStore: the floor was written, and the sync after it failed")
	errReadFailed  = errors.New("memStore: the read failed")
)

func newMemStore(floors ...policy.Floor) *memStore {
	s := &memStore{floors: map[string]policy.Floor{}}
	for _, f := range floors {
		s.floors[f.BundleID()] = f
	}
	return s
}

func (s *memStore) Floor(_ context.Context, bundleID string) (policy.Floor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return policy.Floor{}, s.readErr
	}
	f, ok := s.floors[bundleID]
	if !ok {
		return policy.Floor{}, fmt.Errorf("memStore: no floor for %q", bundleID)
	}
	return f, nil
}

func (s *memStore) Raise(ctx context.Context, st policy.Statement, now time.Time) (policy.Floor, error) {
	return s.RaiseAt(ctx, st, policy.At(now))
}

func (s *memStore) RaiseAt(_ context.Context, st policy.Statement, at policy.Reading) (policy.Floor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.floors[st.BundleID()]
	if !ok {
		return policy.Floor{}, fmt.Errorf("memStore: no floor for %q", st.BundleID())
	}
	now, err := at()
	if err != nil {
		return policy.Floor{}, err
	}
	next, err := stored.Raise(st, now)
	if err != nil {
		return policy.Floor{}, err
	}
	if s.writeErr != nil {
		return policy.Floor{}, s.writeErr
	}
	if !next.Equal(stored) {
		s.floors[st.BundleID()] = next
		s.raises++
	}
	if s.afterWrite != nil {
		return policy.Floor{}, s.afterWrite
	}
	return next, nil
}

func (s *memStore) stored(bundleID string) policy.Floor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.floors[bundleID]
}

func (s *memStore) writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.raises
}

// liarStore says it raised the floor and returns the floor it was built with,
// whatever statement it was handed.
type liarStore struct{ floor policy.Floor }

func (s liarStore) Floor(context.Context, string) (policy.Floor, error) { return s.floor, nil }

func (s liarStore) RaiseAt(context.Context, policy.Statement, policy.Reading) (policy.Floor, error) {
	return s.floor, nil
}
