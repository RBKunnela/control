package recovery_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/holdjournal"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/recovery"
	"github.com/guardana/control/internal/runs"
	"github.com/guardana/control/internal/spool"
)

var (
	confidential = runs.State{Untrusted: false, MaxRead: controlv1.Sensitivity_SENSITIVITY_CONFIDENTIAL}
	secretTaint  = runs.State{Untrusted: true, MaxRead: controlv1.Sensitivity_SENSITIVITY_SECRET}
	restoreAt    = t0.Add(3 * time.Hour)
)

// backedUp is a directory plane at serial 1 with one open run and one pause,
// and a backup of it.
func backedUp(t *testing.T) (*plane, string, runs.Record) {
	t.Helper()
	p := newPlane(t, directoryBlock)
	p.raiseFloor(t, 1, d1, t0)
	rec := p.openRun(t, confidential)
	p.addPause(t, "p1")
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(t.Context(), p.cfg, dir, t0); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	return p, dir, rec
}

// TestRestoreAfterTheStateIsLost is the acceptance path: after the backup
// the plane renews to serial 2, raises the run's taint and closes nothing;
// then every floor, run and pause is lost and restored. Nothing resumes,
// the run is closed, the old bundle's statement confirms nothing, and the
// journal and the approvals store are as they were.
func TestRestoreAfterTheStateIsLost(t *testing.T) {
	p, dir, rec := backedUp(t)
	p.raiseFloor(t, 2, d2, t0.Add(time.Hour))
	p.setState(t, rec.ID, secretTaint)
	if err := os.WriteFile(p.path("approvals/held.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	untouched := tree(t, p.root, "floors", "runs", "pause")
	for _, d := range []string{"floors", "runs", "pause/pause.json"} {
		if err := os.RemoveAll(p.path(d)); err != nil {
			t.Fatal(err)
		}
	}

	report, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(report.Done) != 3 {
		t.Fatalf("Done = %q, want the floor, the runs and the pause", report.Done)
	}
	requireStamped(t, p)
	got, s := p.run(t, rec.ID)
	if !got.ClosedAt.Equal(restoreAt) {
		t.Fatalf("the run closed at %v, want %v", got.ClosedAt, restoreAt)
	}
	if s != confidential {
		t.Fatalf("state = %+v, want the backup's", s)
	}
	if ids := p.pauses(t); fmt.Sprint(ids) != "[p1]" {
		t.Fatalf("pauses = %v", ids)
	}
	after := tree(t, p.root, "floors", "runs", "pause")
	for name, body := range untouched {
		if after[name] != body {
			t.Fatalf("%s changed", name)
		}
	}
}

// requireStamped holds p's floor to the backup's serial stamped at the
// restore: the old bundle's statement is below it, one issued after it is
// taken.
func requireStamped(t *testing.T, p *plane) {
	t.Helper()
	want := "fixture serial 1 " + d1 + " issued 2026-03-01T15:00:00Z latest 2026-03-01T15:00:00Z"
	if got := p.floor(t); describe(got) != want {
		t.Fatalf("floor = %s, want %s", describe(got), want)
	}
	if err := p.floor(t).Takes(statement(t, 1, d1, t0), restoreAt.Add(time.Minute)); !errors.Is(err, policy.ErrBelowFloor) {
		t.Fatalf("the old bundle's statement: err = %v, want ErrBelowFloor", err)
	}
	if err := p.floor(t).Takes(statement(t, 1, d1, restoreAt.Add(time.Second)), restoreAt.Add(time.Minute)); err != nil {
		t.Fatalf("a statement issued after the restore: %v", err)
	}
}

// TestRestoreOverSurvivingStateNeverLowersIt: where the state survived, the
// higher floor, the higher taint and every pause stay.
func TestRestoreOverSurvivingStateNeverLowersIt(t *testing.T) {
	p, dir, rec := backedUp(t)
	p.raiseFloor(t, 2, d2, t0.Add(time.Hour))
	p.setState(t, rec.ID, secretTaint)
	p.addPause(t, "p2")
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
		t.Fatal(err)
	}
	if f := p.floor(t); f.Serial() != 2 || f.Digest() != d2 {
		t.Fatalf("floor = %s, want serial 2", describe(f))
	}
	if _, s := p.run(t, rec.ID); s != (runs.State{Untrusted: true, MaxRead: controlv1.Sensitivity_SENSITIVITY_SECRET}) {
		t.Fatalf("state = %+v", s)
	}
	if ids := p.pauses(t); fmt.Sprint(ids) != "[p1 p2]" {
		t.Fatalf("pauses = %v", ids)
	}
}

func TestBackupHoldsNothingThatResumes(t *testing.T) {
	_, dir, _ := backedUp(t)
	raw, err := os.ReadFile(filepath.Join(dir, recovery.ManifestName)) //nolint:gosec // G304: the test's own backup
	if err != nil {
		t.Fatal(err)
	}
	m, err := recovery.ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) == 0 {
		t.Fatal("the backup holds nothing")
	}
	for _, e := range m.Entries {
		for _, never := range []string{"/holds/", "/approvals/", "/spool/"} {
			if strings.Contains(e.Source, never) {
				t.Fatalf("the backup holds %s", e.Source)
			}
		}
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("the backup's mode = %v, %v", info.Mode().Perm(), err)
	}
}

// TestRestoreRefusesBeforeWriting: each refusal leaves the floor file as it
// was.
func TestRestoreRefusesBeforeWriting(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(t *testing.T, p *plane, dir string)
		want  error
	}{
		{"another project", func(_ *testing.T, p *plane, _ string) { p.cfg.ProjectID = "billing" }, recovery.ErrOtherPlane},
		{"another tenant", func(_ *testing.T, p *plane, _ string) { p.cfg.TenantID = "other" }, recovery.ErrOtherPlane},
		{"another authority", func(_ *testing.T, p *plane, _ string) { p.cfg.Approvals.Authority = "signed" }, recovery.ErrOtherPlane},
		{"the memory authority", func(_ *testing.T, p *plane, _ string) { p.cfg.Approvals.Authority = "memory" }, recovery.ErrMemory},
		{"a source moved", func(_ *testing.T, p *plane, _ string) { p.cfg.Policy.StateDir = "floors2" }, recovery.ErrSource},
		{"a class no longer configured", func(_ *testing.T, p *plane, _ string) { p.cfg.Pause.File = "" }, recovery.ErrSource},
		{"a tampered file", func(t *testing.T, _ *plane, dir string) {
			appendTo(t, filepath.Join(dir, "pause", "pause.json"), " ")
		}, recovery.ErrTampered},
		{"an unlisted file", func(t *testing.T, _ *plane, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "floor", "plane", "extra"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, recovery.ErrUnlisted},
		{"a link in the backup", func(t *testing.T, _ *plane, dir string) {
			if err := os.Symlink("/etc/hosts", filepath.Join(dir, "link")); err != nil {
				t.Fatal(err)
			}
		}, recovery.ErrUnlisted},
		{"a major the build does not read", func(t *testing.T, _ *plane, dir string) {
			edit(t, filepath.Join(dir, recovery.ManifestName), `"schema_version": "0.1"`, `"schema_version": "1.0"`)
		}, recovery.ErrVersion},
		{"a missing manifest", func(t *testing.T, _ *plane, dir string) {
			if err := os.Remove(filepath.Join(dir, recovery.ManifestName)); err != nil {
				t.Fatal(err)
			}
		}, os.ErrNotExist},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, dir, _ := backedUp(t)
			p.raiseFloor(t, 2, d2, t0.Add(time.Hour))
			before := tree(t, p.root)
			c.spoil(t, p, dir)
			if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if after := tree(t, p.root); fmt.Sprint(after) != fmt.Sprint(before) {
				t.Fatal("a refused restore changed the plane's tree")
			}
		})
	}
}

// openPlane opens what a serving plane holds open, the spool or the hold
// journal, and returns what closes it.
func openPlane(t *testing.T, p *plane, which string) (func() error, error) {
	t.Helper()
	if which == "spool" {
		s, err := spool.Open(spool.Options{Dir: p.path("spool"), MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
		if err != nil {
			return nil, err
		}
		return s.Close, nil
	}
	j, err := holdjournal.Open(p.path("holds"))
	if err != nil {
		return nil, err
	}
	return j.Close, nil
}

// TestRestoreRefusesWhileAPlaneHoldsALock: a plane holding the spool or the
// journal keeps a restore and a backup out, and nothing is written.
func TestRestoreRefusesWhileAPlaneHoldsALock(t *testing.T) {
	for _, held := range []string{"spool", "holds"} {
		t.Run(held, func(t *testing.T) {
			p, dir, _ := backedUp(t)
			release, err := openPlane(t, p, held)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = release() }()
			before := tree(t, p.root)
			if _, err = recovery.Restore(t.Context(), p.cfg, dir, restoreAt); !errors.Is(err, recovery.ErrPlaneRunning) {
				t.Fatalf("err = %v, want ErrPlaneRunning", err)
			}
			if after := tree(t, p.root); fmt.Sprint(after) != fmt.Sprint(before) {
				t.Fatal("a refused restore changed the plane's tree")
			}
			if _, err := recovery.Backup(t.Context(), p.cfg, filepath.Join(t.TempDir(), "b"), t0); !errors.Is(err, recovery.ErrPlaneRunning) {
				t.Fatalf("a backup beside a plane: err = %v, want ErrPlaneRunning", err)
			}
		})
	}
}

// TestRestoreKeepsAPlaneOutUntilItEnds: at every write a restore makes, a
// plane opening its spool or its journal is refused by the lock those
// packages take themselves; once the restore returns, both open.
func TestRestoreKeepsAPlaneOutUntilItEnds(t *testing.T) {
	p, dir, _ := backedUp(t)
	steps := 0
	defer recovery.SetKillPoint(func(step string) error {
		steps++
		for _, which := range []string{"spool", "holds"} {
			release, err := openPlane(t, p, which)
			if err == nil {
				_ = release()
				return fmt.Errorf("%s opened during %q", which, step)
			}
			if !errors.Is(err, spool.ErrLocked) && !errors.Is(err, holdjournal.ErrLocked) {
				return fmt.Errorf("%s during %q: %w, want its lock's refusal", which, step, err)
			}
		}
		return nil
	})()
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if steps == 0 {
		t.Fatal("the restore passed no write; nothing was examined")
	}
	for _, which := range []string{"spool", "holds"} {
		release, err := openPlane(t, p, which)
		if err != nil {
			t.Fatalf("%s after the restore: %v", which, err)
		}
		if err := release(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBackupRefuses(t *testing.T) {
	p := newPlane(t, directoryBlock)
	p.raiseFloor(t, 1, d1, t0)
	dir := filepath.Join(t.TempDir(), "backup")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Backup(t.Context(), p.cfg, dir, t0); !errors.Is(err, recovery.ErrExists) {
		t.Fatalf("an existing directory: err = %v, want ErrExists", err)
	}
	p.cfg.Approvals.Authority = "memory"
	if _, err := recovery.Backup(t.Context(), p.cfg, filepath.Join(t.TempDir(), "b"), t0); !errors.Is(err, recovery.ErrMemory) {
		t.Fatalf("memory: err = %v, want ErrMemory", err)
	}
	p.cfg.Approvals.Authority = "directory"
	if err := os.Symlink(p.path("floors"), p.path("runs")); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Backup(t.Context(), p.cfg, filepath.Join(t.TempDir(), "c"), t0); !errors.Is(err, recovery.ErrNotRegular) {
		t.Fatalf("a link where runs.dir is: err = %v, want ErrNotRegular", err)
	}
}

func appendTo(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0) //nolint:gosec // G304: the test's own backup
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func edit(t *testing.T, path, from, to string) {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own backup
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), from) {
		t.Fatalf("%s does not hold %s", path, from)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), from, to, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func describe(f policy.Floor) string {
	return fmt.Sprintf("%s serial %d %s issued %s latest %s", f.BundleID(), f.Serial(), f.Digest(),
		policy.FormatIssuedAt(f.IssuedAt()), policy.FormatIssuedAt(f.LatestIssuedAt()))
}

// TestRestoreTakesOnlyTheBytesItVerified: a backup file swapped after the
// manifest's check, at the first write, is not what the restore takes; the
// copy it reads is owner-only and gone once it returns.
func TestRestoreTakesOnlyTheBytesItVerified(t *testing.T) {
	scratch := t.TempDir()
	t.Setenv("TMPDIR", scratch)
	p, dir, _ := backedUp(t)
	q := newPlane(t, directoryBlock)
	q.addPause(t, "unverified")
	swap, err := os.ReadFile(q.path("pause/pause.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p.path("pause/pause.json")); err != nil {
		t.Fatal(err)
	}
	swapped := false
	defer recovery.SetKillPoint(func(string) error {
		if swapped {
			return nil
		}
		swapped = true
		if err := oneOwnerOnlyDir(scratch); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, "pause", "pause.json"), swap, 0o600)
	})()
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !swapped {
		t.Fatal("the restore passed no write; nothing was swapped")
	}
	if ids := p.pauses(t); fmt.Sprint(ids) != "[p1]" {
		t.Fatalf("pauses = %v, want the backup's [p1] as verified", ids)
	}
	if left, err := os.ReadDir(scratch); err != nil || len(left) != 0 {
		t.Fatalf("the verified copy was left: %v, %v", left, err)
	}
}

// oneOwnerOnlyDir refuses a dir that holds anything but one directory of
// mode 0700.
func oneOwnerOnlyDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != 1 {
		return fmt.Errorf("%s holds %d entries, want the one verified copy", dir, len(entries))
	}
	info, err := entries[0].Info()
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("the verified copy is %v, want an owner-only directory", info.Mode())
	}
	return nil
}
