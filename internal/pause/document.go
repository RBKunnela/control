package pause

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/pkg/contract"
)

// SchemaVersion is the one version of the pause file this build reads and
// writes.
const SchemaVersion = "1"

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

// ScopeKind is what a pause entry covers.
type ScopeKind string

// The three scopes. Principal, agent and tenant are refused until a listener
// authenticates: on a listener that authenticates nobody each is the whole
// plane or nothing, and an entry that silently pauses nothing is the unsafe
// failure of an emergency control.
const (
	ScopeGlobal   ScopeKind = "global"
	ScopeProvider ScopeKind = "provider"
	ScopeAction   ScopeKind = "action"
)

// The kinds of call an action scope names, as the envelope's action kind
// spells them.
const (
	ActionTool     = channel.KindTool
	ActionPrompt   = channel.KindPrompt
	ActionResource = channel.KindResource
)

// Scope is the calls one entry pauses. Provider is an upstream by its
// configured name; Action and Name are set only on an action scope, and Name
// only for a tool. A prompt and a resource are paused by their provider only:
// the plane routes either by its upstream alone, so its name or URI is the
// client's spelling and could be written another way to slip past an exact
// match.
type Scope struct {
	Kind     ScopeKind
	Provider string
	Action   string
	Name     string
}

// Matches reports whether s covers a call of the action kind, provider and
// name the envelope carries. A field the call does not carry matches, as an
// absent input restricts: a call nothing classifies carries no provider, so
// every entry pauses it. A kind outside the plane's vocabulary matches every
// action scope, as an absent one does, and a scope of a kind this build does
// not know matches every call.
func (s Scope) Matches(kind, provider, name string) bool {
	switch s.Kind {
	case ScopeGlobal:
		return true
	case ScopeProvider:
		return absentOr(provider, s.Provider)
	case ScopeAction:
		return (!channel.KnownKind(kind) || kind == s.Action) && absentOr(provider, s.Provider) &&
			(s.Name == "" || absentOr(name, s.Name))
	}
	return true
}

func absentOr(got, want string) bool { return got == "" || got == want }

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
// SchemaVersion; and with ErrMalformed, anything else it cannot read exactly:
// text that is not UTF-8 or not one JSON object, an unknown, repeated or
// missing member, a value of the wrong type, out of its bound or its set,
// more than MaxEntries entries, and two entries under one id.
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
	if version != SchemaVersion {
		return Document{}, fmt.Errorf("%w: %q, this build reads %q", ErrVersion, bounded(version), SchemaVersion)
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
	doc := Document{Entries: make([]Entry, 0, len(list))}
	for i, raw := range list {
		e, err := parseEntry(raw)
		if err != nil {
			return Document{}, malformed("entries.%d: %v", i, err)
		}
		doc.Entries = append(doc.Entries, e)
	}
	if err := doc.Check(); err != nil {
		return Document{}, err
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
	if err := only(m, "kind", "provider", "action", "name"); err != nil {
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
	}{{"provider", &s.Provider}, {"action", &s.Action}, {"name", &s.Name}} {
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

// Check refuses a scope of an unknown kind, a global scope that names
// anything, a provider scope without its provider or with an action or a
// name, an action scope without its kind of call or its provider, a tool
// scope without its name, and a prompt or resource scope with one.
func (s Scope) Check() error {
	switch s.Kind {
	case ScopeGlobal:
		if s.Provider != "" || s.Action != "" || s.Name != "" {
			return fmt.Errorf("scope: a global scope names nothing else")
		}
		return nil
	case ScopeProvider:
		if s.Action != "" || s.Name != "" {
			return fmt.Errorf("scope: a provider scope names its provider and nothing else")
		}
		return checkName("scope.provider", s.Provider, MaxNameBytes)
	case ScopeAction:
		return s.checkAction()
	}
	return fmt.Errorf("scope.kind: %q is not one of %s, %s, %s", s.Kind, ScopeGlobal, ScopeProvider, ScopeAction)
}

func (s Scope) checkAction() error {
	if err := checkName("scope.provider", s.Provider, MaxNameBytes); err != nil {
		return err
	}
	switch s.Action {
	case ActionTool:
		return checkName("scope.name", s.Name, MaxNameBytes)
	case ActionPrompt, ActionResource:
		if s.Name != "" {
			return fmt.Errorf("scope.name: a %s is paused by its provider only, since the plane routes it by its upstream alone and its name is the client's to spell", s.Action)
		}
		return nil
	}
	return fmt.Errorf("scope.action: %q is not one of %s, %s, %s", s.Action, ActionTool, ActionPrompt, ActionResource)
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
			Scope: wireScope{Kind: e.Scope.Kind, Provider: e.Scope.Provider, Action: e.Scope.Action, Name: e.Scope.Name},
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
