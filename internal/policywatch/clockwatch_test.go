package policywatch_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policywatch"
)

type stuckStore struct {
	inFlight atomic.Int64
	release  chan struct{}
}

func (s *stuckStore) Floor(context.Context, string) (policy.Floor, error) {
	s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	<-s.release
	return policy.Floor{}, nil
}

func (s *stuckStore) Raise(context.Context, policy.Statement, time.Time) (policy.Floor, error) {
	s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	<-s.release
	return policy.Floor{}, nil
}

// TestBoundedHoldsOneCallToAStoreThatStoppedAnswering: fifty reads given up
// on a store that never answers leave one store call running, not fifty.
func TestBoundedHoldsOneCallToAStoreThatStoppedAnswering(t *testing.T) {
	s := &stuckStore{release: make(chan struct{})}
	t.Cleanup(func() { close(s.release) })
	b := policywatch.Bounded(s)
	for range 50 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		_, err := b.Floor(ctx, "bundle")
		cancel()
		if err == nil {
			t.Fatal("a store that never answers answered")
		}
	}
	time.Sleep(20 * time.Millisecond)
	if n := s.inFlight.Load(); n != 1 {
		t.Fatalf("%d store calls running after fifty given-up reads, want 1", n)
	}
}
