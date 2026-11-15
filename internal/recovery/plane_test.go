package recovery_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/guardana/control/internal/recovery"
)

// signedManifestWith is a manifest of the signed authority of one entry,
// plane naming its plane_id member whole, or nothing.
func signedManifestWith(version, plane string) string {
	return strings.Replace(strings.Replace(manifestWith(version, goodEntry), `"authority":"directory"`, `"authority":"signed"`, 1),
		`"tenant"`, plane+`"tenant"`, 1)
}

// TestParseManifestHoldsThePlaneToTheAuthority: past 0.1 a signed manifest
// names its plane, an identifier, and no other names one; a 0.1 manifest
// names none under either authority.
func TestParseManifestHoldsThePlaneToTheAuthority(t *testing.T) {
	directoryWith := func(version, plane string) string {
		return strings.Replace(manifestWith(version, goodEntry), `"tenant"`, plane+`"tenant"`, 1)
	}
	for _, c := range []struct {
		name, raw, plane string
	}{
		{"0.2 under signed naming its plane", signedManifestWith("0.2", `"plane_id":"plane-a",`), "plane-a"},
		{"0.2 under signed naming a plane with slashes and dots", signedManifestWith("0.2", `"plane_id":"../planes/a",`), "../planes/a"},
		{"0.3 under signed naming its plane", signedManifestWith("0.3", `"plane_id":"plane-a",`), "plane-a"},
		{"0.1 under signed", signedManifestWith("0.1", ""), ""},
		{"0.1 under directory", directoryWith("0.1", ""), ""},
		{"0.2 under directory", directoryWith("0.2", ""), ""},
	} {
		m, err := recovery.ParseManifest([]byte(c.raw))
		if err != nil || m.PlaneID != c.plane {
			t.Errorf("%s = %q, %v; want plane %q", c.name, m.PlaneID, err, c.plane)
		}
	}
	for _, c := range []struct{ name, raw string }{
		{"0.2 under signed naming no plane", signedManifestWith("0.2", "")},
		{"0.3 under signed naming no plane", signedManifestWith("0.3", "")},
		{"0.2 under signed naming an empty plane", signedManifestWith("0.2", `"plane_id":"",`)},
		{"0.2 under signed naming a plane as a number", signedManifestWith("0.2", `"plane_id":7,`)},
		{"0.2 under signed naming a plane of white space", signedManifestWith("0.2", `"plane_id":" plane-a",`)},
		{"0.1 under signed naming a plane", signedManifestWith("0.1", `"plane_id":"plane-a",`)},
		{"0.2 under directory naming a plane", directoryWith("0.2", `"plane_id":"plane-a",`)},
		{"0.2 naming its plane twice", signedManifestWith("0.2", `"plane_id":"plane-a","plane_id":"plane-a",`)},
	} {
		if _, err := recovery.ParseManifest([]byte(c.raw)); !errors.Is(err, recovery.ErrManifest) {
			t.Errorf("%s = %v, want ErrManifest", c.name, err)
		}
	}
	m, err := recovery.ParseManifest([]byte(signedManifestWith("0.2", `"plane_id":"plane-a",`)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := recovery.MarshalManifest(m)
	if err != nil || !strings.Contains(string(raw), `"plane_id": "plane-a"`) || !strings.Contains(string(raw), `"schema_version": "0.2"`) {
		t.Errorf("MarshalManifest of a signed manifest = %s, %v", raw, err)
	}
	m.PlaneID = ""
	if _, err := recovery.MarshalManifest(m); !errors.Is(err, recovery.ErrManifest) {
		t.Errorf("MarshalManifest of a signed manifest naming no plane = %v, want a refusal", err)
	}
}

// editManifest rewrites dir's backup.json, failing unless edit changed it.
func editManifest(t *testing.T, dir string, edit func(string) string) {
	t.Helper()
	path := filepath.Join(dir, recovery.ManifestName)
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	edited := edit(string(raw))
	if edited == string(raw) {
		t.Fatalf("the edit left %s as it was:\n%s", path, raw)
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
}

var planeLine = regexp.MustCompile(`(?m)^plane_id: .*\n`)

// renamePlane rewrites p's configuration to name plane as its id.
func renamePlane(t *testing.T, p *plane, plane string) {
	t.Helper()
	raw, err := os.ReadFile(p.path("plane.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	renamed := planeLine.ReplaceAllString(string(raw), "plane_id: "+plane+"\n")
	if renamed == string(raw) && !strings.Contains(renamed, "plane_id: "+plane+"\n") {
		t.Fatalf("the configuration names no plane_id to rename:\n%s", raw)
	}
	if err := os.WriteFile(p.path("plane.yaml"), []byte(renamed), 0o600); err != nil {
		t.Fatal(err)
	}
	p.load(t)
}

const (
	namedPlane = "  \"plane_id\": \"plane-a\",\n"
	version02  = `"schema_version": "0.2"`
	version01  = `"schema_version": "0.1"`
)

// TestASignedBackupNamesItsPlaneAndRestoresOnlyIntoIt: the manifest of a
// signed backup names the plane's id; a plane of another id, with the same
// tenant, project and paths, refuses it; the plane it names restores it and
// says nothing of a plane not checked.
func TestASignedBackupNamesItsPlaneAndRestoresOnlyIntoIt(t *testing.T) {
	p, dir, _ := signedPlane(t)
	raw, err := os.ReadFile(filepath.Join(dir, recovery.ManifestName)) //nolint:gosec // G304: the test's own backup
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), namedPlane) || !strings.Contains(string(raw), version02) {
		t.Fatalf("the signed manifest does not name version 0.2 and its plane:\n%s", raw)
	}
	renamePlane(t, p, "plane-b")
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); !errors.Is(err, recovery.ErrOtherPlane) {
		t.Errorf("plane-b restoring plane-a's backup = %v, want ErrOtherPlane", err)
	}
	renamePlane(t, p, "plane-a")
	report, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt)
	if err != nil || report.PlaneNotChecked {
		t.Errorf("the control, plane-a restoring its own backup = %+v, %v", report, err)
	}
}

// TestASignedManifestNamingNoPlaneIsRefusedPast01: a 0.2 manifest under
// signed whose plane_id is gone or empty is refused, never read as a 0.1
// manifest; a 0.1 manifest restores, and the report says its plane was not
// checked.
func TestASignedManifestNamingNoPlaneIsRefusedPast01(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(string) string
	}{
		{"no plane_id", func(s string) string { return strings.Replace(s, namedPlane, "", 1) }},
		{"an empty plane_id", func(s string) string { return strings.Replace(s, namedPlane, "  \"plane_id\": \"\",\n", 1) }},
	} {
		p, dir, _ := signedPlane(t)
		editManifest(t, dir, c.edit)
		if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); !errors.Is(err, recovery.ErrManifest) {
			t.Errorf("a 0.2 manifest under signed with %s = %v, want ErrManifest", c.name, err)
		}
	}
	p, dir, _ := signedPlane(t)
	editManifest(t, dir, func(s string) string {
		return strings.Replace(strings.Replace(s, namedPlane, "", 1), version02, version01, 1)
	})
	renamePlane(t, p, "plane-b")
	report, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt)
	if err != nil || !report.PlaneNotChecked {
		t.Fatalf("a 0.1 manifest under signed = %+v, %v; want a restore whose plane was not checked", report, err)
	}
	requireSignedFloors(t, p)
}

// TestADirectoryBackupNamesNoPlane: outside signed the manifest names no
// plane at 0.2, and a 0.1 manifest restores as before, with nothing said of
// a plane.
func TestADirectoryBackupNamesNoPlane(t *testing.T) {
	_, dir, _ := backedUp(t)
	raw, err := os.ReadFile(filepath.Join(dir, recovery.ManifestName)) //nolint:gosec // G304: the test's own backup
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "plane_id") || !strings.Contains(string(raw), version02) {
		t.Fatalf("the directory manifest:\n%s", raw)
	}
	for _, version := range []string{version02, version01} {
		p, dir, _ := backedUp(t)
		if version != version02 {
			editManifest(t, dir, func(s string) string { return strings.Replace(s, version02, version, 1) })
		}
		if report, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil || report.PlaneNotChecked {
			t.Errorf("a directory restore of %s = %+v, %v", version, report, err)
		}
	}
}

// TestASignedBackupNeedsThePlanesID: a signed configuration that names no
// plane, which Load refuses, is refused by Backup too, before it makes the
// directory.
func TestASignedBackupNeedsThePlanesID(t *testing.T) {
	p := newPlane(t, signedBlock)
	p.cfg.PlaneID = ""
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(t.Context(), p.cfg, dir, t0); !errors.Is(err, recovery.ErrOtherPlane) {
		t.Errorf("Backup with no plane id = %v, want ErrOtherPlane", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused Backup made %s: %v", dir, err)
	}
}
