//go:build unix

package runs_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardana/control/internal/runs"
)

// overwriteInPlace edits the JSON object in dir/name through its existing
// inode, as an account with write access to the file and none to the
// directory can.
func overwriteInPlace(t *testing.T, dir, name string, edit func(map[string]json.RawMessage)) {
	t.Helper()
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0) //nolint:gosec // G304: a file under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(out)
	if err = errors.Join(err, f.Close()); err != nil {
		t.Fatal(err)
	}
}

// trustCases are the modes a file is judged at: three a group or the world
// may write, and the owner's alone, at which the same rewrite is the owner's
// own word and is read.
var trustCases = []struct {
	mode    fs.FileMode
	trusted bool
}{{0o666, false}, {0o620, false}, {0o602, false}, {0o600, true}}

// TestARecordOthersMayWriteDoesNotResolve: a run record a group or the world
// may write could carry any expiry, so it resolves as unreadable.
func TestARecordOthersMayWriteDoesNotResolve(t *testing.T) {
	for _, c := range trustCases {
		t.Run(c.mode.String(), func(t *testing.T) {
			dir, a, p := setup(t)
			rec, token := openRoot(t, a)
			name := rec.ID + ".run.json"
			if err := os.Chmod(filepath.Join(dir, name), c.mode); err != nil {
				t.Fatal(err)
			}
			overwriteInPlace(t, dir, name, func(m map[string]json.RawMessage) {
				m["expires_at"] = json.RawMessage(`"2026-03-01T15:00:00Z"`)
			})
			late := opened.Add(2 * time.Hour)
			got, err := p.Resolve(t.Context(), token, alice, late)
			if c.trusted {
				if err != nil || got.ID != rec.ID {
					t.Errorf("Resolve over the owner's own record = %+v, %v; want it resolved", got, err)
				}
				return
			}
			if causeOf(t, err) != runs.CauseUnreadable || !errors.Is(err, runs.ErrForeignFile) {
				t.Errorf("Resolve over a record at %04o = %+v, %v; want unreadable, ErrForeignFile", c.mode, got, err)
			}
		})
	}
}

// TestAStateFileOthersMayWriteIsNotRead: a state file a group or the world
// may write could wash an untrusted root clean, so reading it is an error.
func TestAStateFileOthersMayWriteIsNotRead(t *testing.T) {
	for _, c := range trustCases {
		t.Run(c.mode.String(), func(t *testing.T) {
			dir, a, p := setup(t)
			rec, _ := openRoot(t, a)
			if err := p.Raise(t.Context(), rec.Root, func(s runs.State) runs.State {
				s.Untrusted = true
				return s
			}); err != nil {
				t.Fatal(err)
			}
			name := rec.Root + ".state.json"
			if err := os.Chmod(filepath.Join(dir, name), c.mode); err != nil {
				t.Fatal(err)
			}
			overwriteInPlace(t, dir, name, func(m map[string]json.RawMessage) { m["untrusted"] = json.RawMessage("false") })
			got, err := p.State(t.Context(), rec.Root)
			if c.trusted {
				if err != nil || got.Untrusted {
					t.Errorf("State over the owner's own file = %+v, %v; want it read as written", got, err)
				}
				return
			}
			if !errors.Is(err, runs.ErrForeignFile) || got.Untrusted {
				t.Errorf("State over a file at %04o = %+v, %v; want ErrForeignFile", c.mode, got, err)
			}
		})
	}
}

// TestALockFileOthersMayWriteRaisesNothing: a raise opens the root's lock
// file for writing, and one a group or the world may write is not the
// directory's.
func TestALockFileOthersMayWriteRaisesNothing(t *testing.T) {
	dir, a, p := setup(t)
	rec, _ := openRoot(t, a)
	if err := os.Chmod(filepath.Join(dir, rec.Root+".lock"), 0o666); err != nil { //nolint:gosec // G302: the mode under test
		t.Fatal(err)
	}
	err := p.Raise(t.Context(), rec.Root, func(s runs.State) runs.State {
		s.Untrusted = true
		return s
	})
	if !errors.Is(err, runs.ErrForeignFile) {
		t.Errorf("Raise through a lock file at 0666 = %v, want ErrForeignFile", err)
	}
	if got, err := p.State(t.Context(), rec.Root); err != nil || got.Untrusted {
		t.Errorf("the state after a refused raise = %+v, %v; want it untouched", got, err)
	}
}

// TestAFileAnotherUserOwnsIsNotRead: the directory stays the operator's, so
// only the file's own owner refuses the record and the state file. Both read
// again once this user owns them.
func TestAFileAnotherUserOwnsIsNotRead(t *testing.T) {
	_, a, p := setup(t)
	rec, token := openRoot(t, a)
	for _, uid := range []int{os.Geteuid() + 1, -1} {
		restore := runs.SetEffectiveUID(func() int { return uid })
		_, resolveErr := p.Resolve(t.Context(), token, alice, opened)
		_, stateErr := p.State(t.Context(), rec.Root)
		restore()
		if causeOf(t, resolveErr) != runs.CauseUnreadable || !errors.Is(resolveErr, runs.ErrForeignFile) {
			t.Errorf("Resolve of a record uid %d does not own = %v; want unreadable, ErrForeignFile", uid, resolveErr)
		}
		if !errors.Is(stateErr, runs.ErrForeignFile) {
			t.Errorf("State of a file uid %d does not own = %v; want ErrForeignFile", uid, stateErr)
		}
	}
	if _, err := p.Resolve(t.Context(), token, alice, opened); err != nil {
		t.Errorf("Resolve as the owner = %v", err)
	}
	if _, err := p.State(t.Context(), rec.Root); err != nil {
		t.Errorf("State as the owner = %v", err)
	}
}
