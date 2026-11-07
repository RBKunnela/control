package recovery

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/policy/strictjson"
	"github.com/guardana/control/pkg/contract"
)

// The manifest's name in a backup, the version this build writes, which a
// reader takes at any minor of major 0, and its kind.
const (
	ManifestName    = "backup.json"
	ManifestVersion = "0.1"
	manifestMajor   = "0"
	ManifestKind    = "state-backup"
)

// The bounds of a backup. A manifest past any of them is refused whole.
const (
	MaxManifestBytes = 4 << 20
	MaxEntries       = 8192
	MaxFileBytes     = 8 << 20
	MaxPathBytes     = 4096
)

// Manifest is what backup.json says: whose state a backup holds, under which
// authority, when it was taken, and each file it holds.
type Manifest struct {
	Authority, Tenant, Project string
	TakenAt                    time.Time
	Entries                    []Entry
}

// Entry is one file a backup holds: its class, the configuration key naming
// where it came from, its absolute source, its slash-separated path in the
// backup, its hex SHA-256 and its size.
type Entry struct {
	Class, Key, Source, Path, SHA256 string
	Bytes                            int64
}

var (
	manifestMembers = []string{"schema_version", "kind", "authority", "tenant", "project", "taken_at", "entries"}
	entryMembers    = []string{"class", "key", "source", "path", "sha256", "bytes"}
)

type wireManifest struct {
	SchemaVersion string      `json:"schema_version"`
	Kind          string      `json:"kind"`
	Authority     string      `json:"authority"`
	Tenant        string      `json:"tenant"`
	Project       string      `json:"project"`
	TakenAt       string      `json:"taken_at"`
	Entries       []wireEntry `json:"entries"`
}

type wireEntry struct {
	Class  string `json:"class"`
	Key    string `json:"key"`
	Source string `json:"source"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// MarshalManifest renders m as backup.json holds it, and refuses one
// ParseManifest would not read back as m.
func MarshalManifest(m Manifest) ([]byte, error) {
	w := wireManifest{SchemaVersion: ManifestVersion, Kind: ManifestKind, Authority: m.Authority, Tenant: m.Tenant,
		Project: m.Project, TakenAt: m.TakenAt.UTC().Format(time.RFC3339), Entries: make([]wireEntry, 0, len(m.Entries))}
	for _, e := range m.Entries {
		w.Entries = append(w.Entries, wireEntry(e))
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(w); err != nil {
		return nil, err
	}
	if _, err := ParseManifest(b.Bytes()); err != nil {
		return nil, fmt.Errorf("the manifest would not read back: %w", err)
	}
	return b.Bytes(), nil
}

// ParseManifest reads backup.json strictly: one JSON object of at most
// MaxManifestBytes with every member and no other, schema_version of major
// 0, kind "state-backup", authority directory or signed, a tenant and a
// project each an identifier, taken_at in RFC 3339 UTC, and at most
// MaxEntries entries. An entry names a class this build backs up and that
// class's key, an absolute clean source, a path under the class that is
// clean, relative and named once, a hex SHA-256 and a size of at most
// MaxFileBytes. Any other input is ErrManifest, or ErrVersion for another
// major.
func ParseManifest(raw []byte) (Manifest, error) {
	if len(raw) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("%w: %d bytes, the bound is %d", ErrManifest, len(raw), MaxManifestBytes)
	}
	o, err := object(raw, manifestMembers)
	if err != nil {
		return Manifest{}, err
	}
	s, err := stringMembers(o, "schema_version", "kind", "authority", "tenant", "project", "taken_at")
	if err != nil {
		return Manifest{}, err
	}
	taken, err := header(s)
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{Authority: s["authority"], Tenant: s["tenant"], Project: s["project"], TakenAt: taken}
	if m.Entries, err = entries(o["entries"]); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// header checks the manifest's string members and returns when the backup
// was taken.
func header(s map[string]string) (time.Time, error) {
	switch {
	case !strictjson.IsVersion(s["schema_version"], manifestMajor):
		return time.Time{}, fmt.Errorf("%w: %q", ErrVersion, clip(s["schema_version"]))
	case s["kind"] != ManifestKind:
		return time.Time{}, fmt.Errorf("%w: kind", ErrManifest)
	case s["authority"] != gatewayconfig.AuthorityDirectory && s["authority"] != gatewayconfig.AuthoritySigned:
		return time.Time{}, fmt.Errorf("%w: authority", ErrManifest)
	case contract.CheckID(s["tenant"]) != nil || contract.CheckID(s["project"]) != nil:
		return time.Time{}, fmt.Errorf("%w: the tenant or the project", ErrManifest)
	}
	taken, err := time.Parse(time.RFC3339, s["taken_at"])
	if err != nil || !strings.HasSuffix(s["taken_at"], "Z") || taken.Nanosecond() != 0 {
		return time.Time{}, fmt.Errorf("%w: taken_at", ErrManifest)
	}
	return taken, nil
}

func entries(raw json.RawMessage) ([]Entry, error) {
	var items []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil {
		return nil, fmt.Errorf("%w: entries is not a list", ErrManifest)
	}
	if len(items) > MaxEntries {
		return nil, fmt.Errorf("%w: %d entries, the bound is %d", ErrManifest, len(items), MaxEntries)
	}
	out := make([]Entry, 0, len(items))
	seen := make(map[string]bool, len(items))
	for i, item := range items {
		e, err := entry(item)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		if seen[e.Path] {
			return nil, fmt.Errorf("%w: entry %d: a path named twice", ErrManifest, i)
		}
		seen[e.Path] = true
		out = append(out, e)
	}
	return out, nil
}

func entry(raw json.RawMessage) (Entry, error) {
	o, err := object(raw, entryMembers)
	if err != nil {
		return Entry{}, err
	}
	s, err := stringMembers(o, "class", "key", "source", "path", "sha256")
	if err != nil {
		return Entry{}, err
	}
	e := Entry{Class: s["class"], Key: s["key"], Source: s["source"], Path: s["path"], SHA256: s["sha256"]}
	if err := json.Unmarshal(o["bytes"], &e.Bytes); err != nil || !isInteger(o["bytes"]) || e.Bytes < 0 || e.Bytes > MaxFileBytes {
		return Entry{}, fmt.Errorf("%w: bytes", ErrManifest)
	}
	if err := checkEntry(e); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// checkEntry checks an entry's class, key, source, path and digest.
func checkEntry(e Entry) error {
	c, ok := classNamed(e.Class)
	switch {
	case !ok:
		return fmt.Errorf("%w: class %q", ErrManifest, clip(e.Class))
	case e.Key != c.key:
		return fmt.Errorf("%w: class %s is %s's, not %q", ErrManifest, c.name, c.key, clip(e.Key))
	case len(e.Source) > MaxPathBytes || !filepath.IsAbs(e.Source) || filepath.Clean(e.Source) != e.Source:
		return fmt.Errorf("%w: source is not an absolute clean path", ErrManifest)
	case !underClass(e.Path, c.name):
		return fmt.Errorf("%w: path is not a clean path under %s/", ErrManifest, c.name)
	case len(e.SHA256) != 64 || strings.ToLower(e.SHA256) != e.SHA256:
		return fmt.Errorf("%w: sha256", ErrManifest)
	}
	if _, err := hex.DecodeString(e.SHA256); err != nil {
		return fmt.Errorf("%w: sha256", ErrManifest)
	}
	return nil
}

// underClass reports whether p is a clean, relative, slash-separated path
// under the directory named after class.
func underClass(p, class string) bool {
	rel, ok := strings.CutPrefix(p, class+"/")
	return ok && rel != "" && len(p) <= MaxPathBytes && path.Clean(p) == p && !strings.Contains(p, "\\") &&
		!strings.HasPrefix(rel, "../") && rel != ".." && !strings.ContainsRune(p, 0)
}

func object(raw []byte, members []string) (strictjson.Object, error) {
	o, err := strictjson.ReadObject(raw)
	if err == nil {
		err = o.Only(members...)
	}
	if err == nil {
		err = o.Require(members...)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrManifest, err)
	}
	return o, nil
}

func stringMembers(o strictjson.Object, names ...string) (map[string]string, error) {
	out := make(map[string]string, len(names))
	for _, n := range names {
		v, ok := strictjson.String(o[n])
		if !ok {
			return nil, fmt.Errorf("%w: %s is not a string", ErrManifest, n)
		}
		out[n] = v
	}
	return out, nil
}

// isInteger reports whether raw spells a JSON number with no fraction and no
// exponent.
func isInteger(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	for i, b := range raw {
		if (b < '0' || b > '9') && (i != 0 || b != '-') {
			return false
		}
	}
	return true
}

func clip(s string) string {
	const limit = 80
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
