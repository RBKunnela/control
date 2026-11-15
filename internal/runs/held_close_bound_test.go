//go:build unix

package runs_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// TestHeldClosesAreBounded: a plane holds at most 64 closes it could not
// carry. With 63 held it still resolves an open run; with 64 it refuses every
// signed resolve, an open run's included, until state/ takes the held closes,
// and then resolves again with every close written.
func TestHeldClosesAreBounded(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the superuser writes a directory whatever its mode")
	}
	const bound = 64
	dir, a := newSigned(t)
	_, yToken := openSignedRoot(t, a, "alice")
	closed, tokens := openClosed(t, a, bound)
	p := signedPlane(t, dir, alicesJudge)
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
	if _, err := p.Resolve(t.Context(), yToken, alice, at); err != nil {
		t.Fatalf("Resolve of y with %d closes held = %v, want it resolved", bound-1, err)
	}
	resolveClosed(t, p, tokens[bound-1:], at)
	_, err := p.Resolve(t.Context(), yToken, alice, at)
	if err == nil {
		t.Fatalf("Resolve of y with %d closes held resolved, want refused", bound)
	}
	if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, runs.ErrUncarried) {
		t.Fatalf("Resolve of y with %d closes held = %v, want unreadable, ErrUncarried", bound, err)
	}
	writable(t, dir)
	if _, err := p.Resolve(t.Context(), yToken, alice, at); err != nil {
		t.Fatalf("Resolve of y once state/ takes the closes: %v", err)
	}
	for _, id := range closed {
		if !closeCarried(t, dir, id) {
			t.Fatalf("the close of %s is not in state/", id)
		}
	}
}

// openClosed opens n runs and closes each, and returns their ids and tokens.
func openClosed(t *testing.T, a *runs.Admin, n int) (ids, tokens []string) {
	t.Helper()
	for range n {
		rec, token := openSignedRoot(t, a, "alice")
		if _, _, err := a.CloseSigned(t.Context(), rec.ID, opened.Add(time.Minute), testSigner("alice"), alicesJudge); err != nil {
			t.Fatal(err)
		}
		ids, tokens = append(ids, rec.ID), append(tokens, token)
	}
	return ids, tokens
}

func resolveClosed(t *testing.T, p *runs.Plane, tokens []string, at time.Time) {
	t.Helper()
	for i, token := range tokens {
		if _, err := p.Resolve(t.Context(), token, alice, at); causeOf(t, err) != runs.CauseClosed {
			t.Fatalf("Resolve of closed run %d = %v, want closed", i, err)
		}
	}
}
