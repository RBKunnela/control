//go:build unix

package gatewayconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestALinkDoesNotJoinTheStopsDirectoryToALockedOne: a stops directory that
// is a link into the spool, and a spool that is a link into the stops
// directory, each sit inside the other under a path that does not say so,
// and each is refused.
func TestALinkDoesNotJoinTheStopsDirectoryToALockedOne(t *testing.T) {
	t.Run("the stops directory links into the spool", func(t *testing.T) {
		path := write(t, withRoute)
		dir := filepath.Dir(path)
		mkdir(t, filepath.Join(dir, "spool", "inner"))
		link(t, filepath.Join(dir, "spool", "inner"), filepath.Join(dir, "stopslink"))
		setEnv(t, "reaction.stops", "stopslink")
		refusedNaming(t, path, "evidence.dir")
	})
	t.Run("paths through a link and .. that put the stops directory around the spool", func(t *testing.T) {
		path := write(t, withRoute)
		dir := filepath.Dir(path)
		up := string(filepath.Separator) + ".."
		mkdir(t, filepath.Join(dir, "area", "child"))
		mkdir(t, filepath.Join(dir, "area", "spool", "inner"))
		mkdir(t, filepath.Join(dir, "x"))
		mkdir(t, filepath.Join(dir, "y"))
		link(t, filepath.Join(dir, "area", "child"), filepath.Join(dir, "x", "deep"))
		link(t, filepath.Join(dir, "area", "spool", "inner"), filepath.Join(dir, "y", "deep"))
		setEnv(t, "reaction.stops", filepath.Join(dir, "x", "deep")+up)
		setEnv(t, "evidence.dir", filepath.Join(dir, "y", "deep")+up)
		refusedNaming(t, path, "evidence.dir")
	})
	t.Run("a path naming .. that does not exist yet", func(t *testing.T) {
		path := write(t, withRoute)
		dir := filepath.Dir(path)
		setEnv(t, "reaction.stops", filepath.Join(dir, "none")+string(filepath.Separator)+".."+string(filepath.Separator)+"later")
		if _, err := Load(path, os.Environ()); err == nil || !strings.Contains(err.Error(), "reaction.stops") {
			t.Errorf("a stops directory that does not exist and names .. = %v, want a refusal naming reaction.stops", err)
		}
	})
	t.Run("the spool links into the stops directory", func(t *testing.T) {
		path := write(t, withRoute)
		dir := filepath.Dir(path)
		mkdir(t, filepath.Join(dir, "stops", "inner"))
		link(t, filepath.Join(dir, "stops", "inner"), filepath.Join(dir, "spoollink"))
		setEnv(t, "evidence.dir", "spoollink")
		refusedNaming(t, path, "evidence.dir")
	})
}

func mkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

func link(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

func refusedNaming(t *testing.T, path, key string) {
	t.Helper()
	_, err := Load(path, os.Environ())
	if err == nil {
		t.Fatalf("a stops directory joined to %s by a link was accepted", key)
	}
	if !strings.Contains(err.Error(), "reaction.stops") || !strings.Contains(err.Error(), key) {
		t.Errorf("the refusal names neither reaction.stops nor %s: %v", key, err)
	}
}

// TestALinkDoesNotJoinTheRunsOrTheJournalDirectoryToTheSpool: the runs
// directory and the hold journal's are kept out of the spool by identity, as
// the stops directory is, so a link into the spool is refused for each.
func TestALinkDoesNotJoinTheRunsOrTheJournalDirectoryToTheSpool(t *testing.T) {
	for _, key := range []string{"runs.dir", "approvals.hold_journal_dir"} {
		t.Run(key, func(t *testing.T) {
			path := write(t, withRoute)
			dir := filepath.Dir(path)
			mkdir(t, filepath.Join(dir, "spool", "inner"))
			link(t, filepath.Join(dir, "spool", "inner"), filepath.Join(dir, "linked"))
			if key == "approvals.hold_journal_dir" {
				setEnv(t, "approvals.authority", "directory")
				setEnv(t, "approvals.dir", "approvals")
			}
			setEnv(t, key, "linked")
			_, err := Load(path, os.Environ())
			if err == nil || !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "evidence.dir") {
				t.Errorf("%s linked into the spool = %v, want a refusal naming %s and evidence.dir", key, err, key)
			}
		})
	}
}
