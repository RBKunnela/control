package console

import (
	"time"

	"github.com/guardana/control/internal/keytext"
	"github.com/guardana/control/internal/pause"
)

// pauseReply is the pause file as `pause list` reads it. State is "clear",
// "paused" or "unreadable"; an unreadable file carries its refusal in Error.
// Status is what the page says of the file.
type pauseReply struct {
	File    string       `json:"file"`
	State   string       `json:"state"`
	Status  string       `json:"status"`
	Error   string       `json:"error,omitempty"`
	Entries []entryReply `json:"entries"`
}

// entryReply is one pause. ID is what a lift sends back; Covers and Fields
// are what the page shows of it.
type entryReply struct {
	ID      string       `json:"id"`
	Scope   scopeReply   `json:"scope"`
	Covers  string       `json:"covers"`
	Created string       `json:"created"`
	Reason  string       `json:"reason"`
	Fields  []fieldReply `json:"fields"`
}

// scopeReply is a scope as the pause file spells it, and as /api/pause takes
// it.
type scopeReply struct {
	Kind     string `json:"kind"`
	Provider string `json:"provider"`
	Action   string `json:"action"`
	Name     string `json:"name"`
	ID       string `json:"id"`
}

// pauseState reads the file with every check a plane's read makes, so a file
// refused here is one a plane reading it blocks every call under.
func pauseState(file string) *pauseReply {
	out := &pauseReply{File: keytext.Printable(file), Entries: []entryReply{}}
	doc, err := pause.List(file)
	if err != nil {
		out.State, out.Error = "unreadable", keytext.Printable(err.Error())+"; a plane reading this file blocks every call"
		out.Status = "Unreadable: a plane reading this file blocks every call."
		return out
	}
	out.State, out.Status = "clear", "Clear: this file pauses nothing."
	if len(doc.Entries) > 0 {
		out.State, out.Status = "paused", "Paused:"
	}
	for _, e := range doc.Entries {
		scope := scopeReply{
			Kind:     keytext.Printable(string(e.Scope.Kind)),
			Provider: keytext.Printable(e.Scope.Provider),
			Action:   keytext.Printable(e.Scope.Action),
			Name:     keytext.Printable(e.Scope.Name),
			ID:       keytext.Printable(e.Scope.ID),
		}
		created := e.CreatedAt.UTC().Format(time.RFC3339)
		reason := keytext.Printable(e.Reason)
		out.Entries = append(out.Entries, entryReply{
			ID:      e.ID,
			Scope:   scope,
			Covers:  scopeText(scope),
			Created: created,
			Reason:  reason,
			Fields:  []fieldReply{{"id", keytext.Printable(e.ID)}, {"created", created}, {"reason", reason}},
		})
	}
	return out
}

// scopeText says which calls a scope covers.
func scopeText(s scopeReply) string {
	switch s.Kind {
	case string(pause.ScopeGlobal):
		return "every call"
	case string(pause.ScopeProvider):
		return "every call to " + s.Provider
	case string(pause.ScopeAction):
		if s.Name != "" {
			return "tool " + s.Name + " of " + s.Provider
		}
		return "every " + s.Action + " of " + s.Provider
	case string(pause.ScopeRun):
		return "run " + s.ID + ", or every run under it as their root"
	case string(pause.ScopeAgent), string(pause.ScopePrincipal):
		return "every call of " + s.Kind + " " + s.ID
	}
	return "scope " + s.Kind
}
