package recovery_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/recovery"
)

// copyPlane copies the plane's whole tree, modes kept, to a new root and
// loads the copy's configuration.
func copyPlane(t *testing.T, p *plane) *plane {
	t.Helper()
	to := filepath.Join(t.TempDir(), "plane")
	err := filepath.WalkDir(p.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(p.root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Mkdir(filepath.Join(to, rel), info.Mode().Perm())
		}
		raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own directory
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), raw, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &plane{root: to}
	c.load(t)
	return c
}

// TestRestoreKilledAtEveryStepConverges stops a restore before each of its
// writes, runs it again, and requires the tree an unbroken restore leaves,
// over lost state and over state that survived, under each authority and
// with a stop list.
func TestRestoreKilledAtEveryStepConverges(t *testing.T) {
	template := newPlane(t, directoryBlock)
	template.raiseFloor(t, 1, d1, t0)
	rec := template.openRun(t, confidential)
	template.addPause(t, "p1")
	stops, _, _ := stopsPlane(t)
	signed, _, signedRec := signedStops(t)
	scenarios := map[string]struct {
		template *plane
		after    func(t *testing.T, p *plane)
		// passes is a prefix of a step each restore has to pass.
		passes []string
	}{
		"lost": {template, func(t *testing.T, p *plane) {
			removeAll(t, p, "floors", "runs", "pause/pause.json")
		}, []string{"floor/plane: build", "runs: state", "runs: record", "pause: merge"}},
		"survived": {template, func(t *testing.T, p *plane) {
			p.raiseFloor(t, 2, d2, t0.Add(time.Hour))
			p.setState(t, rec.ID, secretTaint)
			p.addPause(t, "p2")
		}, []string{"floor/plane: write", "runs: record"}},
		"a stop list lost": {stops, func(t *testing.T, p *plane) {
			removeAll(t, p, "stops")
		}, []string{"stops: make", "stops: carry"}},
		"signed, lost": {signed, func(t *testing.T, p *plane) {
			removeAll(t, p, "floors", "trust/floors", "pausefloor", "stopsfloor", "runs/state/"+signedRec.ID+".state.json")
		}, []string{"floor/plane: build", "floor/authority: build", "floor/pause: build", "floor/stops: build", "runs: carry", "runs: state"}},
	}
	for name, sc := range scenarios {
		t.Run(name, func(t *testing.T) {
			prepare := func(t *testing.T) (*plane, string) {
				p := copyPlane(t, sc.template)
				dir := filepath.Join(t.TempDir(), "backup")
				if _, err := recovery.Backup(t.Context(), p.cfg, dir, t0); err != nil {
					t.Fatal(err)
				}
				sc.after(t, p)
				return p, dir
			}
			var steps []string
			restore := recovery.SetKillPoint(func(step string) error { steps = append(steps, step); return nil })
			want, dir := prepare(t)
			_, err := recovery.Restore(t.Context(), want.cfg, dir, restoreAt)
			restore()
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range sc.passes {
				if !slices.ContainsFunc(steps, func(s string) bool { return strings.HasPrefix(s, want) }) {
					t.Fatalf("steps %q pass no %q; the seam is not reached there", steps, want)
				}
			}
			wantTree := settled(t, want.root)
			for i, step := range steps {
				p, dir := prepare(t)
				n := 0
				killed := errors.New("killed")
				restore := recovery.SetKillPoint(func(string) error {
					if n == i {
						return killed
					}
					n++
					return nil
				})
				_, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt)
				restore()
				if !errors.Is(err, killed) {
					t.Fatalf("killed at %q: err = %v", step, err)
				}
				if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
					t.Fatalf("the rerun after %q: %v", step, err)
				}
				if got := settled(t, p.root); fmt.Sprint(got) != fmt.Sprint(wantTree) {
					t.Fatalf("killed at %q, the rerun left another tree:\n%v\nwant\n%v", step, got, wantTree)
				}
			}
		})
	}
}

func removeAll(t *testing.T, p *plane, rel ...string) {
	t.Helper()
	for _, r := range rel {
		if err := os.RemoveAll(p.path(r)); err != nil {
			t.Fatal(err)
		}
	}
}

// settled is tree of root with a carried stop list's header, which holds
// the list id the carry drew, cut away.
func settled(t *testing.T, root string) map[string]string {
	t.Helper()
	out := tree(t, root)
	if list, ok := out["stops/stops.jsonl"]; ok {
		_, rest, _ := strings.Cut(list, "\n")
		out["stops/stops.jsonl"] = rest
	}
	return out
}
