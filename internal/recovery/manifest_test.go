package recovery_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/guardana/control/internal/recovery"
)

const sum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// manifestWith is a manifest of one entry, its members as given.
func manifestWith(version, entry string) string {
	return `{"schema_version":"` + version + `","kind":"state-backup","authority":"directory","tenant":"acme","project":"orders",` +
		`"taken_at":"2026-03-01T12:00:00Z","entries":[` + entry + `]}`
}

func entryWith(class, key, source, path string, bytes int) string {
	return fmt.Sprintf(`{"class":%q,"key":%q,"source":%q,"path":%q,"sha256":%q,"bytes":%d}`, class, key, source, path, sum, bytes)
}

var goodEntry = entryWith("floor/plane", "policy.state_dir", "/srv/floors/floors.meta", "floor/plane/floors.meta", 10)

func TestParseManifestReadsWhatItWrites(t *testing.T) {
	m, err := recovery.ParseManifest([]byte(manifestWith("0.7", goodEntry)))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(m.Entries) != 1 || m.Entries[0].Source != "/srv/floors/floors.meta" || m.Entries[0].Bytes != 10 || m.Tenant != "acme" {
		t.Fatalf("manifest = %+v", m)
	}
	raw, err := recovery.MarshalManifest(m)
	if err != nil || !strings.Contains(string(raw), `"schema_version": "0.1"`) {
		t.Fatalf("MarshalManifest = %s, %v", raw, err)
	}
}

func TestParseManifestRefuses(t *testing.T) {
	cases := map[string]string{
		"another major":            manifestWith("1.0", goodEntry),
		"an unknown member":        strings.Replace(manifestWith("0.1", goodEntry), `"kind"`, `"extra":1,"kind"`, 1),
		"a member twice":           strings.Replace(manifestWith("0.1", goodEntry), `"kind":"state-backup"`, `"kind":"state-backup","kind":"state-backup"`, 1),
		"another kind":             strings.Replace(manifestWith("0.1", goodEntry), "state-backup", "other", 1),
		"the memory authority":     strings.Replace(manifestWith("0.1", goodEntry), `"directory"`, `"memory"`, 1),
		"a time not in UTC":        strings.Replace(manifestWith("0.1", goodEntry), "12:00:00Z", "12:00:00+01:00", 1),
		"an unknown class":         manifestWith("0.1", entryWith("ledger", "policy.state_dir", "/srv/a", "ledger/a", 1)),
		"another class's key":      manifestWith("0.1", entryWith("floor/plane", "runs.dir", "/srv/a", "floor/plane/a", 1)),
		"a relative source":        manifestWith("0.1", entryWith("floor/plane", "policy.state_dir", "srv/a", "floor/plane/a", 1)),
		"an unclean source":        manifestWith("0.1", entryWith("floor/plane", "policy.state_dir", "/srv/../a", "floor/plane/a", 1)),
		"a path outside its class": manifestWith("0.1", entryWith("floor/plane", "policy.state_dir", "/srv/a", "runs/a", 1)),
		"a path climbing out":      manifestWith("0.1", entryWith("floor/plane", "policy.state_dir", "/srv/a", "floor/plane/../../a", 1)),
		"the class itself":         manifestWith("0.1", entryWith("floor/plane", "policy.state_dir", "/srv/a", "floor/plane/", 1)),
		"a size past the bound":    manifestWith("0.1", entryWith("floor/plane", "policy.state_dir", "/srv/a", "floor/plane/a", recovery.MaxFileBytes+1)),
		"a negative size":          manifestWith("0.1", entryWith("floor/plane", "policy.state_dir", "/srv/a", "floor/plane/a", -1)),
		"a fractional size":        strings.Replace(manifestWith("0.1", goodEntry), `"bytes":10`, `"bytes":10.5`, 1),
		"an upper-case sha256":     strings.Replace(manifestWith("0.1", goodEntry), sum, strings.ToUpper(sum), 1),
		"a path named twice":       manifestWith("0.1", goodEntry+","+goodEntry),
		"an empty tenant":          strings.Replace(manifestWith("0.1", goodEntry), `"acme"`, `""`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := recovery.ParseManifest([]byte(raw))
			if !errors.Is(err, recovery.ErrManifest) && !errors.Is(err, recovery.ErrVersion) {
				t.Fatalf("err = %v, want a refusal", err)
			}
		})
	}
}

// TestParseManifestAtTheBounds: a size of exactly MaxFileBytes is read, and
// MaxEntries entries are read while one more is refused.
func TestParseManifestAtTheBounds(t *testing.T) {
	if _, err := recovery.ParseManifest([]byte(manifestWith("0.1", entryWith("floor/plane", "policy.state_dir", "/srv/a", "floor/plane/a", recovery.MaxFileBytes)))); err != nil {
		t.Fatalf("a size at the bound: %v", err)
	}
	many := func(n int) string {
		items := make([]string, n)
		for i := range items {
			items[i] = entryWith("runs", "runs.dir", fmt.Sprintf("/r/%d", i), fmt.Sprintf("runs/%d", i), 0)
		}
		return manifestWith("0.1", strings.Join(items, ","))
	}
	if _, err := recovery.ParseManifest([]byte(many(recovery.MaxEntries))); err != nil {
		t.Fatalf("MaxEntries entries: %v", err)
	}
	if _, err := recovery.ParseManifest([]byte(many(recovery.MaxEntries + 1))); !errors.Is(err, recovery.ErrManifest) {
		t.Fatalf("one entry more: err = %v", err)
	}
}
