package gatewayconfig

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestWithinComparesOneWay: a path is within the directory it is, or sits
// under, and a directory that holds the other one is not within it.
func TestWithinComparesOneWay(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, ".floors.restoring")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".", filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path string
		want bool
	}{
		{staging, true},
		{filepath.Join(staging, "journal"), true},
		{filepath.Join(dir, "alias", ".floors.restoring"), true},
		{filepath.Join(dir, "alias", ".floors.restoring", "journal"), true},
		{dir, false},
		{filepath.Join(dir, "floors"), false},
		{filepath.Join(dir, ".floors.restoring2"), false},
	} {
		got, err := Within(c.path, staging)
		if err != nil || got != c.want {
			t.Errorf("Within(%q, staging) = %v, %v, want %v", strings.TrimPrefix(c.path, dir), got, err, c.want)
		}
	}
}

// TestWithinRefusesANameInAnotherCase: a name in another case is the same
// directory on a file system that folds case, so Within reports it within on
// every file system rather than answer by the one it runs on.
func TestWithinRefusesANameInAnotherCase(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, ".floors.restoring")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, other := range []string{filepath.Join(dir, ".FLOORS.restoring"), filepath.Join(dir, ".FLOORS.restoring", "journal")} {
		if got, err := Within(other, staging); err != nil || !got {
			t.Errorf("Within(%q, staging) = %v, %v, want true", strings.TrimPrefix(other, dir), got, err)
		}
	}
}

// TestNamedPathsListsEveryFileKeySet: each key naming a file or a directory
// that is set is listed with its path resolved, an upstream's command by its
// index, and the configuration file last; a key left empty and a key that
// names no path are not.
func TestNamedPathsListsEveryFileKeySet(t *testing.T) {
	c := &Config{dir: "/etc/plane", path: "/etc/plane/plane.yaml", TenantID: "tenant-a"}
	c.Approvals.HoldJournalDir = "holds"
	c.Evidence.Dir = "/var/spool/plane"
	c.Upstreams = []UpstreamConfig{{Name: "a", Endpoint: "http://up"}, {Name: "b", Command: "bin/up"}}
	want := []NamedPath{
		{Key: "approvals.hold_journal_dir", Path: "/etc/plane/holds"},
		{Key: "evidence.dir", Path: "/var/spool/plane"},
		{Key: "upstreams.1.command", Path: "/etc/plane/bin/up"},
		{Key: "config", Path: "/etc/plane/plane.yaml"},
	}
	if got := c.NamedPaths(); !slices.Equal(got, want) {
		t.Fatalf("NamedPaths = %v, want %v", got, want)
	}
}

// TestWithinRefusesNamesNothingTellsApartYet: where neither name exists, one
// in another case, or one through a link above it, is within the other, since
// the file system may make them one directory once either is made.
func TestWithinRefusesNamesNothingTellsApartYet(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(".", filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(dir, ".routefloor.restoring")
	for _, c := range []struct {
		path string
		want bool
	}{
		{filepath.Join(dir, ".ROUTEFLOOR.restoring"), true},
		{filepath.Join(dir, ".RouteFloor.restoring", "journal"), true},
		{filepath.Join(dir, "alias", ".routefloor.restoring"), true},
		{filepath.Join(dir, "alias", "alias", ".ROUTEFLOOR.restoring", "x"), true},
		{filepath.Join(dir, ".routefloor"), false},
		{filepath.Join(dir, "alias", "floors"), false},
	} {
		got, err := Within(c.path, staging)
		if err != nil || got != c.want {
			t.Errorf("Within(%q, staging) = %v, %v, want %v", strings.TrimPrefix(c.path, dir), got, err, c.want)
		}
	}
}
