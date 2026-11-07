//go:build unix

package runs_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// TestTheBoundCountsResolvesUnderWay: with 63 closes held and state/ still
// read-only, a resolve of a closed run admitted but not yet answered counts
// against the bound, since it may hold one more; a resolve meanwhile is
// refused, and so is one after the first ends, holding 64.
func TestTheBoundCountsResolvesUnderWay(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser writes a directory whatever its mode")
	}
	const bound = 64
	dir, a := newSigned(t)
	_, yToken := openSignedRoot(t, a, "alice")
	_, tokens := openClosed(t, a, bound)
	var blocking atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	p := signedPlane(t, dir, judgeFunc(func(ctx context.Context, r runs.SignedRecord) (runs.SignedBy, error) {
		if blocking.CompareAndSwap(true, false) {
			close(entered)
			<-release
		}
		return alicesJudge.Judge(ctx, r)
	}))
	at := opened.Add(2 * time.Minute)
	if _, err := p.Resolve(t.Context(), yToken, alice, at); err != nil {
		t.Fatalf("Resolve of y: %v", err)
	}
	state := filepath.Join(dir, "state")
	if err := os.Chmod(state, 0o500); err != nil { //nolint:gosec // G302: read and search only, so no close can be carried
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(state, 0o700) }) //nolint:gosec // G302: as the layout made it
	resolveClosed(t, p, tokens[:bound-1], at)
	blocking.Store(true)
	answered := make(chan error, 1)
	go func() {
		_, err := p.Resolve(context.Background(), tokens[bound-1], alice, at)
		answered <- err
	}()
	<-entered
	_, err := p.Resolve(t.Context(), yToken, alice, at)
	close(release)
	if !errors.Is(err, runs.ErrUncarried) {
		t.Fatalf("Resolve of y with %d closes held and one resolve under way = %v, want ErrUncarried", bound-1, err)
	}
	if err := <-answered; causeOf(t, err) != runs.CauseClosed {
		t.Fatalf("the resolve under way = %v, want closed", err)
	}
	if _, err := p.Resolve(t.Context(), yToken, alice, at); !errors.Is(err, runs.ErrUncarried) {
		t.Fatalf("Resolve of y with %d closes held = %v, want ErrUncarried", bound, err)
	}
}

// TestARetryThatFailsIsCounted: every write of a held close state/ refuses,
// the survey's and Close's included, counts as carry_failed.
func TestARetryThatFailsIsCounted(t *testing.T) {
	dir, p, _, _, _, _ := heldClose(t)
	if err := os.Chmod(filepath.Join(dir, "state"), 0o500); err != nil { //nolint:gosec // G302: read and search only, so no close can be carried
		t.Fatal(err)
	}
	if _, err := p.CarryCloses(t.Context(), 100, opened.Add(3*time.Minute)); err == nil {
		t.Fatal("CarryCloses with a held close state/ refuses: err = nil")
	}
	if got := p.SignedCounts()["carry_failed"]; got != 2 {
		t.Fatalf("carry_failed after the survey's retry = %d, want 2", got)
	}
}
