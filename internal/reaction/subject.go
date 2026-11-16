package reaction

import (
	"fmt"
	"time"
)

// Subject is what a call is matched against a stop list by: the tenant,
// agent and principal the plane serves, and the opened run the plane
// vouched for the call, or none.
type Subject struct{ Tenant, Run, Agent, Principal string }

// StopMatch is the kinds of active stop that name a call. The zero value is
// none.
type StopMatch uint8

// The kinds of stop a call can match, one bit each, since one call can match
// both.
const (
	// StopRun is a stop of the call's opened run.
	StopRun StopMatch = 1 << iota
	// StopWider is a stop of the agent or the principal the call acts for.
	StopWider
)

// Has reports whether m holds every kind in k.
func (m StopMatch) Has(k StopMatch) bool { return k != 0 && m&k == k }

// CauseSubject is the state of a call that leaves out the field an active
// stop names it by: no tenant, or no agent or principal under a stop of one.
// It is a call's cause, never a read's, so no reader counts it.
const CauseSubject Cause = "a call that names no subject for an active stop"

// Target is the scope and subject whose stops a stop line or a lift names.
type Target struct{ Scope, Subject string }

// Target is the scope and subject s stops: its run under a 1.0 or 2.0 line,
// which names no subject, and its scope and subject under a 3.0 line.
func (s Stop) Target() Target {
	if s.Subject == "" {
		return Target{ScopeRun, s.RunID}
	}
	return Target{s.Scope, s.Subject}
}

// ForSubject is what s says of a call of who at the call's clock now, given
// floor, the latest instant the call relied on, with At's age rule applied
// at now: Stopped with the kinds of the active entries that name the call,
// Clear when none does, and Unknown with its cause when the state is unknown
// or past its age, or when an active entry names the call by a field who
// leaves empty. A plane with no route is Disabled. The cause is empty unless
// the state is Unknown; an Unknown state still reports what matched.
func (s Snapshot) ForSubject(who Subject, now, floor time.Time) (State, Cause, StopMatch) {
	at := s.At(now)
	switch at.state {
	case Disabled:
		return Disabled, "", 0
	case Clear, Stopped:
		m, named := at.list.match(who, now, floor)
		switch {
		case !named:
			return Unknown, CauseSubject, m
		case m != 0:
			return Stopped, "", m
		}
		return Clear, "", 0
	}
	return Unknown, at.Cause(), 0
}

// matches is the kinds of the entries of a list read whole that name a call
// of who at the call's clock now, given floor, as ForSubject matches them,
// with no age rule; an Unknown snapshot matches none.
func (s Snapshot) matches(who Subject, now, floor time.Time) StopMatch {
	if s.state != Clear && s.state != Stopped {
		return 0
	}
	m, _ := s.list.match(who, now, floor)
	return m
}

// match is the kinds of l's entries active at now given floor that name a
// call of who, each within who's tenant: a run stop by the call's run, an
// agent stop by its agent and a principal stop by its principal. A call with
// no run matches no run stop. named is false when who has no tenant and an
// entry is active, or an active agent or principal stop of who's tenant
// meets a call whose field for it is empty: such a call is never Clear.
func (l List) match(who Subject, now, floor time.Time) (m StopMatch, named bool) {
	named = true
	for _, e := range l.entries {
		if !active(e, now, floor) {
			continue
		}
		if who.Tenant == "" {
			named = false
			continue
		}
		if e.TenantID != who.Tenant {
			continue
		}
		t := e.Target()
		var field string
		bit := StopWider
		switch t.Scope {
		case ScopeRun:
			field, bit = who.Run, StopRun
		case ScopeAgent:
			field = who.Agent
		case ScopePrincipal:
			field = who.Principal
		default:
			named = false
			continue
		}
		switch {
		case field == "" && bit == StopWider:
			named = false
		case field != "" && field == t.Subject:
			m |= bit
		}
	}
	return m, named
}

// SubjectOf is the subject a stop of scope names for the run r stands for:
// the run itself, or its agent or principal as the run's record holds them.
// An empty one, a scope the grammar does not name among them, is refused,
// since a stop of no one would stop nothing.
func SubjectOf(scope string, r RunFacts) (string, error) {
	var subject string
	switch scope {
	case ScopeRun:
		subject = r.RunID
	case ScopeAgent:
		subject = r.AgentID
	case ScopePrincipal:
		subject = r.PrincipalID
	}
	if subject == "" {
		return "", fmt.Errorf("%w: scope %q", ErrStopSubject, scope)
	}
	return subject, nil
}

// ExpiresAt is when a stop under r created at created ends: created plus the
// rule's lifetime for a stop of an agent or a principal, which no run's
// expiry bounds since it holds runs opened after it; for a stop of a run,
// that run's expiry rounded up to a whole second, as a line spells it, or
// created plus the lifetime when that comes first. A rule with no lifetime
// takes MaxLifetime.
func (r Rule) ExpiresAt(created, runExpires time.Time) time.Time {
	limit := r.Lifetime
	if limit == 0 {
		limit = MaxLifetime
	}
	end := created.Add(limit)
	if wider(r.Scope) {
		return end
	}
	if down := runExpires.Truncate(time.Second); down.Before(runExpires) {
		runExpires = down.Add(time.Second)
	}
	if end.Before(runExpires) {
		return end
	}
	return runExpires
}
