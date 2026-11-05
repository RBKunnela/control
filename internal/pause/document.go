package pause

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/guardana/control/pkg/contract"
)

// SchemaVersion is the version of the pause file this build writes. It reads
// subsetVersion too, a version that names no run, agent or principal.
const (
	SchemaVersion = "2"
	subsetVersion = "1"
)

// The bounds of one document. A file past any of them is refused whole.
// MaxEntries entries with every field at its bound and escaped at twice its
// length, as Marshal renders them, fit in MaxFileBytes, so a file the writer
// keeps meets the entry bound before the byte bound.
const (
	MaxFileBytes   = 160 << 10
	MaxEntries     = 64
	MaxIDBytes     = 64
	MaxNameBytes   = 256
	MaxReasonBytes = 512
)

// Entry is one pause. CreatedAt and Reason are for the operator and decide
// nothing.
type Entry struct {
	ID        string
	Scope     Scope
	CreatedAt time.Time
	Reason    string
}

// Document is the whole pause file.
type Document struct {
	Entries []Entry
}

// Parse reads a pause document strictly. It refuses, with ErrTooLarge, a
// document over MaxFileBytes; with ErrVersion, a schema version other than
// SchemaVersion and subsetVersion; and with ErrMalformed, anything else it
// cannot read exactly: text that is not UTF-8 or not one JSON object, an
// unknown, repeated or missing member, a value of the wrong type, out of its
// bound or its set, more than MaxEntries entries, two entries under one id,
// and a scope a subsetVersion file cannot name.
func Parse(raw []byte) (Document, error) {
	if len(raw) > MaxFileBytes {
		return Document{}, fmt.Errorf("%w: %d bytes, the bound is %d", ErrTooLarge, len(raw), MaxFileBytes)
	}
	if !utf8.Valid(raw) {
		return Document{}, malformed("the text is not UTF-8")
	}
	top, err := members(raw, true)
	if err != nil {
		return Document{}, malformed("%v", err)
	}
	version, err := member(top, "schema_version", str)
	if err != nil {
		return Document{}, malformed("%v", err)
	}
	if version != SchemaVersion && version != subsetVersion {
		return Document{}, fmt.Errorf("%w: %q, this build reads %q and %q", ErrVersion, bounded(version), subsetVersion, SchemaVersion)
	}
	if err := only(top, "schema_version", "entries"); err != nil {
		return Document{}, malformed("%v", err)
	}
	list, err := member(top, "entries", array)
	if err != nil {
		return Document{}, malformed("%v", err)
	}
	if len(list) > MaxEntries {
		return Document{}, malformed("%d entries, the bound is %d", len(list), MaxEntries)
	}
	doc, err := parseEntries(list, version)
	if err != nil {
		return Document{}, err
	}
	if err := doc.Check(); err != nil {
		return Document{}, err
	}
	return doc, nil
}

// parseEntries reads the entries of a file of version, refusing a scope a
// subsetVersion file cannot name.
func parseEntries(list []json.RawMessage, version string) (Document, error) {
	doc := Document{Entries: make([]Entry, 0, len(list))}
	for i, raw := range list {
		e, err := parseEntry(raw)
		if err != nil {
			return Document{}, malformed("entries.%d: %v", i, err)
		}
		if version == subsetVersion && !inSubset(e.Scope) {
			return Document{}, malformed("entries.%d: a version %s file names no run, agent or principal", i, subsetVersion)
		}
		doc.Entries = append(doc.Entries, e)
	}
	return doc, nil
}

func parseEntry(raw json.RawMessage) (Entry, error) {
	m, err := members(raw, false)
	if err != nil {
		return Entry{}, err
	}
	if err := only(m, "id", "scope", "created_at", "reason"); err != nil {
		return Entry{}, err
	}
	var e Entry
	if e.ID, err = member(m, "id", str); err != nil {
		return Entry{}, err
	}
	if e.Reason, err = member(m, "reason", str); err != nil {
		return Entry{}, err
	}
	created, err := member(m, "created_at", str)
	if err != nil {
		return Entry{}, err
	}
	if e.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return Entry{}, fmt.Errorf("created_at: not an RFC 3339 time")
	}
	scope, err := member(m, "scope", object)
	if err != nil {
		return Entry{}, err
	}
	if e.Scope, err = parseScope(scope); err != nil {
		return Entry{}, fmt.Errorf("scope: %w", err)
	}
	return e, nil
}

// parseScope reads a scope's members. A member that is present is never
// empty: an empty one would read as absent and slip past Scope.Check.
func parseScope(m map[string]json.RawMessage) (Scope, error) {
	if err := only(m, "kind", "provider", "action", "name", "id"); err != nil {
		return Scope{}, err
	}
	kind, err := member(m, "kind", str)
	if err != nil {
		return Scope{}, err
	}
	s := Scope{Kind: ScopeKind(kind)}
	for _, f := range []struct {
		name string
		to   *string
	}{{"provider", &s.Provider}, {"action", &s.Action}, {"name", &s.Name}, {"id", &s.ID}} {
		if _, set := m[f.name]; !set {
			continue
		}
		if *f.to, err = member(m, f.name, str); err != nil {
			return Scope{}, err
		}
		if *f.to == "" {
			return Scope{}, fmt.Errorf("%s: empty; leave the member out instead", f.name)
		}
	}
	return s, nil
}

// inSubset reports whether s is a scope a version 1 file could name.
func inSubset(s Scope) bool {
	return s.ID == "" && (s.Kind == ScopeGlobal || s.Kind == ScopeProvider || s.Kind == ScopeAction)
}

// Check refuses a document Parse would refuse for its values: more than
// MaxEntries entries, an entry that breaks its own rules, and two entries
// under one id. The writer checks every document it writes with it.
func (d Document) Check() error {
	if len(d.Entries) > MaxEntries {
		return malformed("%d entries, the bound is %d", len(d.Entries), MaxEntries)
	}
	seen := make(map[string]bool, len(d.Entries))
	for i, e := range d.Entries {
		if err := e.Check(); err != nil {
			return malformed("entries.%d: %v", i, err)
		}
		if seen[e.ID] {
			return malformed("entries.%d: the id %q is taken by an earlier entry", i, e.ID)
		}
		seen[e.ID] = true
	}
	return nil
}

// Check refuses an entry with no id or one out of its bound or its
// character set, a zero creation time, a reason past MaxReasonBytes or
// holding a control or format character, and a scope Scope.Check refuses.
func (e Entry) Check() error {
	if err := checkName("id", e.ID, MaxIDBytes); err != nil {
		return err
	}
	if e.CreatedAt.IsZero() {
		return fmt.Errorf("created_at: the zero time")
	}
	if len(e.Reason) > MaxReasonBytes {
		return fmt.Errorf("reason: %d bytes, the bound is %d", len(e.Reason), MaxReasonBytes)
	}
	if !utf8.ValidString(e.Reason) {
		return fmt.Errorf("reason: not UTF-8")
	}
	for i, r := range e.Reason {
		if unicode.In(r, unicode.Cc, unicode.Cf) {
			return fmt.Errorf("reason: a control or format character U+%04X at byte %d", r, i)
		}
	}
	return e.Scope.Check()
}

// checkName refuses an empty value, one over limit bytes, and one the
// contract refuses as an identifier. The value is never repeated: it is the
// operator's, and the refusal may be printed where it should not be.
func checkName(member, value string, limit int) error {
	switch {
	case value == "":
		return fmt.Errorf("%s: empty", member)
	case len(value) > limit:
		return fmt.Errorf("%s: %d bytes, the bound is %d", member, len(value), limit)
	}
	if err := contract.CheckIdentifier(value); err != nil {
		return fmt.Errorf("%s: %w", member, err)
	}
	return nil
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// wire is the document as the file spells it.
type wire struct {
	SchemaVersion string      `json:"schema_version"`
	Entries       []wireEntry `json:"entries"`
}

type wireEntry struct {
	ID        string    `json:"id"`
	Scope     wireScope `json:"scope"`
	CreatedAt string    `json:"created_at"`
	Reason    string    `json:"reason"`
}

type wireScope struct {
	Kind     ScopeKind `json:"kind"`
	Provider string    `json:"provider,omitempty"`
	Action   string    `json:"action,omitempty"`
	Name     string    `json:"name,omitempty"`
	ID       string    `json:"id,omitempty"`
}

// Marshal renders d as the file holds it, or refuses a document Check
// refuses or whose rendering Parse would not read back as d.
func Marshal(d Document) ([]byte, error) {
	if err := d.Check(); err != nil {
		return nil, err
	}
	w := wire{SchemaVersion: SchemaVersion, Entries: make([]wireEntry, 0, len(d.Entries))}
	for _, e := range d.Entries {
		w.Entries = append(w.Entries, wireEntry{
			ID: e.ID, CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339Nano), Reason: e.Reason,
			Scope: wireScope{Kind: e.Scope.Kind, Provider: e.Scope.Provider, Action: e.Scope.Action, Name: e.Scope.Name, ID: e.Scope.ID},
		})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(w); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	back, err := Parse(out)
	if err != nil {
		return nil, err
	}
	if !slices.EqualFunc(back.Entries, d.Entries, sameEntry) {
		return nil, malformed("the rendering does not read back as the document")
	}
	return out, nil
}

func sameEntry(a, b Entry) bool {
	return a.ID == b.ID && a.Scope == b.Scope && a.Reason == b.Reason && a.CreatedAt.Equal(b.CreatedAt)
}
