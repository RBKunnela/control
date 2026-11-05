//go:build unix

package pause

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// decoyDir makes a directory beside the pause file's that the group and
// others may write, holding a pause file of body the account running the test
// owns: a read or a write that ends up in it did not go through the
// directory it judged.
func decoyDir(t *testing.T, path, body string) string {
	t.Helper()
	decoy := filepath.Join(filepath.Dir(filepath.Dir(path)), "decoy")
	if err := os.Mkdir(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(decoy, filepath.Base(path)), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(decoy, 0o777); err != nil { //nolint:gosec // G302: a directory the checks refuse, on purpose
		t.Fatal(err)
	}
	return decoy
}

// swapAt swaps the pause file's directory for decoy, once, when opening the
// directory reaches step, and reports whether it did.
func swapAt(t *testing.T, step, path, decoy string) *bool {
	t.Helper()
	dir := filepath.Dir(path)
	swapped := new(bool)
	dirSteps = func(at string) {
		if at != step || *swapped {
			return
		}
		*swapped = true
		if err := os.Rename(dir, dir+".judged"); err != nil {
			t.Error(err)
		}
		if err := os.Rename(decoy, dir); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { dirSteps = nil })
	return swapped
}

const clearBody = `{"schema_version":"2","entries":[]}`

const globalBody = `{"schema_version":"2","entries":[{"id":"g","scope":{"kind":"global"},"created_at":"2026-09-24T10:00:00Z","reason":""}]}`

// TestAReadGoesThroughTheDirectoryItJudged: a directory swapped in under the
// path once the judged one is open is never read, and one swapped in between
// the two opens of the judged directory is refused; with no swap the file
// pauses.
func TestAReadGoesThroughTheDirectoryItJudged(t *testing.T) {
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		step  string
		state State
		cause Cause
	}{
		{"", Paused, ""},
		{stepRooted, Paused, ""},
		{stepOpened, Unknown, CauseUnreadable},
	} {
		t.Run("swapped at "+c.step, func(t *testing.T) {
			path := ownPauseFile(t)
			swapped := swapAt(t, c.step, path, decoyDir(t, path, clearBody))
			s := Read(path, now, time.Second)
			if c.step != "" && !*swapped {
				t.Fatal("the read never reached the step, so this case examined nothing")
			}
			if s.State() != c.state || s.Cause() != c.cause {
				t.Errorf("Read = %s, %q (%s); want %s, %q", s.State(), s.Cause(), s.Detail(), c.state, c.cause)
			}
		})
	}
}

// TestADirectoryLinkIsUnknown: a link at the directory's own name is refused
// even when it names a directory every check passes, which read directly
// pauses.
func TestADirectoryLinkIsUnknown(t *testing.T) {
	now := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	path := ownPauseFile(t)
	if s := Read(path, now, time.Second); s.State() != Paused {
		t.Fatalf("the directory read directly: %s, %q: %s", s.State(), s.Cause(), s.Detail())
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(filepath.Dir(path), link); err != nil {
		t.Fatal(err)
	}
	through := filepath.Join(link, filepath.Base(path))
	if s := Read(through, now, time.Second); s.State() != Unknown || s.Cause() != CauseLink {
		t.Errorf("Read through a directory link = %s, %q (%s); want unknown, %q", s.State(), s.Cause(), s.Detail(), CauseLink)
	}
	if _, err := List(through); !errors.Is(err, ErrDirLink) {
		t.Errorf("List through a directory link = %v, want ErrDirLink", err)
	}
	if err := Remove(context.Background(), through, "g"); !errors.Is(err, ErrDirLink) {
		t.Errorf("Remove through a directory link = %v, want ErrDirLink", err)
	}
}

// TestAWriteGoesIntoTheDirectoryItJudged: a directory swapped in under the
// path once the judged one is open is neither read nor written, and one
// swapped in between the two opens refuses the write, which then writes
// nowhere.
func TestAWriteGoesIntoTheDirectoryItJudged(t *testing.T) {
	for _, c := range []struct {
		step            string
		refused         bool
		judged, swapped string
	}{
		{stepRooted, false, clearBody, globalBody},
		{stepOpened, true, globalBody, globalBody},
	} {
		t.Run("swapped at "+c.step, func(t *testing.T) {
			path := ownPauseFile(t)
			swapped := swapAt(t, c.step, path, decoyDir(t, path, globalBody))
			err := Remove(context.Background(), path, "g")
			if !*swapped {
				t.Fatal("the write never reached the step, so this case examined nothing")
			}
			if c.refused != (err != nil) || c.refused && !errors.Is(err, ErrDirChanged) {
				t.Errorf("Remove = %v; refused %v, want %v", err, err != nil, c.refused)
			}
			for where, want := range map[string]string{
				filepath.Dir(path) + ".judged": c.judged,
				filepath.Dir(path):             c.swapped,
			} {
				doc, err := os.ReadFile(filepath.Join(where, filepath.Base(path))) //nolint:gosec // G304: the test's own temporary directory
				if err != nil {
					t.Fatal(err)
				}
				if got := string(doc); !sameDocument(t, got, want) {
					t.Errorf("%s holds %s, want %s", filepath.Base(where), got, want)
				}
			}
		})
	}
}

// sameDocument reports whether two pause documents hold the same entries.
func sameDocument(t *testing.T, a, b string) bool {
	t.Helper()
	da, err := Parse([]byte(a))
	if err != nil {
		t.Fatalf("Parse(%s): %v", a, err)
	}
	db, err := Parse([]byte(b))
	if err != nil {
		t.Fatalf("Parse(%s): %v", b, err)
	}
	if len(da.Entries) != len(db.Entries) {
		return false
	}
	for i := range da.Entries {
		if da.Entries[i].ID != db.Entries[i].ID {
			return false
		}
	}
	return true
}
