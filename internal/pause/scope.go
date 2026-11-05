package pause

import (
	"fmt"

	"github.com/guardana/control/internal/channel"
	"github.com/guardana/control/internal/runs"
)

// ScopeKind is what a pause entry covers.
type ScopeKind string

// The six scopes. A run, an agent and a principal are matched only against
// the identity the plane vouches for, never against anything the client
// sent. Tenant is refused: on a plane serving one tenant it is the whole
// plane or nothing, and an entry that silently pauses nothing is the unsafe
// failure of an emergency control.
const (
	ScopeGlobal    ScopeKind = "global"
	ScopeProvider  ScopeKind = "provider"
	ScopeAction    ScopeKind = "action"
	ScopeRun       ScopeKind = "run"
	ScopeAgent     ScopeKind = "agent"
	ScopePrincipal ScopeKind = "principal"
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
// match. ID is set only on a run, agent or principal scope, and names that
// run or root, agent or principal.
type Scope struct {
	Kind     ScopeKind
	Provider string
	Action   string
	Name     string
	ID       string
}

// Vouched is the identity the plane vouches for a call: the opened run the
// listener resolved from its token and that run's root, and the principal
// and agent the listener's configuration names. An empty field is one the
// plane vouches nothing for.
type Vouched struct {
	Run, Root, Principal, Agent string
}

// Matches reports whether s covers a call of the action kind, provider and
// name the envelope carries, made under who. A field the call does not carry
// matches, as an absent input restricts: a call nothing classifies carries no
// provider, so every entry pauses it, and a call under no opened run is
// paused by every run entry. A run entry matches the run it names and every
// run whose root it names. A kind outside the plane's vocabulary matches
// every action scope, as an absent one does, and a scope of a kind this build
// does not know matches every call.
func (s Scope) Matches(kind, provider, name string, who Vouched) bool {
	switch s.Kind {
	case ScopeGlobal:
		return true
	case ScopeProvider:
		return absentOr(provider, s.Provider)
	case ScopeAction:
		return (!channel.KnownKind(kind) || kind == s.Action) && absentOr(provider, s.Provider) &&
			(s.Name == "" || absentOr(name, s.Name))
	case ScopeRun:
		return absentOr(who.Run, s.ID) || who.Root == s.ID
	case ScopeAgent:
		return absentOr(who.Agent, s.ID)
	case ScopePrincipal:
		return absentOr(who.Principal, s.ID)
	}
	return true
}

func absentOr(got, want string) bool { return got == "" || got == want }

// Check refuses a scope of an unknown kind, a global scope that names
// anything, a provider scope without its provider or with an action, a name
// or an id, an action scope without its kind of call or its provider or with
// an id, a tool scope without its name, a prompt or resource scope with one,
// a run, agent or principal scope without its id or with anything else, and
// a run scope whose id is not in the form a run is named by.
func (s Scope) Check() error {
	switch s.Kind {
	case ScopeGlobal:
		if anySet(s.Provider, s.Action, s.Name, s.ID) {
			return fmt.Errorf("scope: a global scope names nothing else")
		}
		return nil
	case ScopeProvider:
		if anySet(s.Action, s.Name, s.ID) {
			return fmt.Errorf("scope: a provider scope names its provider and nothing else")
		}
		return checkName("scope.provider", s.Provider, MaxNameBytes)
	case ScopeAction:
		if s.ID != "" {
			return fmt.Errorf("scope: an action scope names no id")
		}
		return s.checkAction()
	case ScopeRun, ScopeAgent, ScopePrincipal:
		if anySet(s.Provider, s.Action, s.Name) {
			return fmt.Errorf("scope: a %s scope names its id and nothing else", s.Kind)
		}
		if err := checkName("scope.id", s.ID, MaxNameBytes); err != nil {
			return err
		}
		if s.Kind == ScopeRun && runs.CheckRunID(s.ID) != nil {
			return fmt.Errorf("scope.id: a run is named by run- and 32 lower-case hex digits")
		}
		return nil
	}
	return fmt.Errorf("scope.kind: %q is not one of %s, %s, %s, %s, %s, %s", s.Kind,
		ScopeGlobal, ScopeProvider, ScopeAction, ScopeRun, ScopeAgent, ScopePrincipal)
}

func anySet(values ...string) bool {
	for _, v := range values {
		if v != "" {
			return true
		}
	}
	return false
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
