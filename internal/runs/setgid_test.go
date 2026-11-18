package runs

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// setgidDir is a new directory of mode 0700 under t's temporary directory
// carrying the setgid bit, or skips where this account cannot set it.
func setgidDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700|fs.ModeSetgid); err != nil {
		t.Skipf("the setgid bit cannot be set here: %v", err)
	}
	if info, err := os.Lstat(dir); err != nil || info.Mode()&fs.ModeSetgid == 0 {
		t.Skipf("the setgid bit does not hold on this platform: %v, %v", info, err)
	}
	return dir
}

func modeOf(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode() & (fs.ModePerm | fs.ModeSetgid | fs.ModeSetuid | fs.ModeSticky)
}

// TestChmodMadeKeepsTheSetgidBitItWasMadeWith: a directory made with the
// setgid bit, as one made under a setgid directory is, keeps it beside the
// mode it is given, and one made without it does not gain it.
func TestChmodMadeKeepsTheSetgidBitItWasMadeWith(t *testing.T) {
	parent := filepath.Dir(setgidDir(t, "probe"))
	top, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = top.Close() }()
	if err := chmodMade(top, "probe", 0o750); err != nil {
		t.Fatalf("chmodMade over a setgid directory: %v", err)
	}
	if got := modeOf(t, filepath.Join(parent, "probe")); got != 0o750|fs.ModeSetgid {
		t.Errorf("a directory made setgid is %v, want %v", got, 0o750|fs.ModeSetgid)
	}
	if err := top.Mkdir("plain", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := chmodMade(top, "plain", 0o750); err != nil {
		t.Fatalf("chmodMade over a plain directory: %v", err)
	}
	if got := modeOf(t, filepath.Join(parent, "plain")); got != 0o750 {
		t.Errorf("a directory made without the setgid bit is %v, want %v", got, fs.FileMode(0o750))
	}
}

// TestASetgidRunsDirectoryGivesRecordsItsBit: where a new directory takes a
// setgid parent's bit, records/ of a signed layout made in a setgid runs
// directory keeps it, so the records take records/'s group.
func TestASetgidRunsDirectoryGivesRecordsItsBit(t *testing.T) {
	dir := setgidDir(t, "runs")
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.Mkdir(probe, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(probe, 0o700|fs.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(probe, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if modeOf(t, filepath.Join(probe, "child"))&fs.ModeSetgid == 0 {
		t.Skip("a new directory does not take its parent's setgid bit on this platform")
	}
	a, err := InitSignedAdmin(context.Background(), dir)
	if err != nil {
		t.Fatalf("InitSignedAdmin: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if got := modeOf(t, filepath.Join(dir, RecordsDir)); got != 0o750|fs.ModeSetgid {
		t.Errorf("records/ is %v, want %v", got, 0o750|fs.ModeSetgid)
	}
}
