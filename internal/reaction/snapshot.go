package reaction

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	"github.com/guardana/control/internal/policy"
)

// State is one of the four states a plane can be in about stops. The zero
// value is Unknown: a state nobody read is not a clear one.
type State uint8

const (
	// Unknown is a stop state the plane cannot vouch for; it blocks every
	// call.
	Unknown State = iota
	// Disabled is a plane configured with no route.
	Disabled
	// Clear is a stop list read whole with no entry active at the read.
	Clear
	// Stopped is a stop list read whole with an entry active at the read.
	Stopped
)

// String names the state as a report prints it.
func (s State) String() string {
	switch s {
	case Disabled:
		return "disabled"
	case Clear:
		return "clear"
	case Stopped:
		return "stopped"
	}
	return "unknown"
}

// Cause is why a state is Unknown, as a report prints it.
type Cause string

// The causes of an unknown state this package names. A reader of the file
// names its own causes for a file it cannot read.
const (
	CauseNeverRead    Cause = "never read"
	CauseTooLarge     Cause = "too large"
	CauseMalformed    Cause = "malformed"
	CauseRoute        Cause = "another route"
	CauseHeader       Cause = "header changed"
	CauseShrunk       Cause = "shrunk"
	CauseRewritten    Cause = "rewritten"
	CauseNotPermitted Cause = "a stop the route does not permit"
	CauseDatedAhead   Cause = "a line dated ahead"
	CauseLift         Cause = "a lift that does not verify"
	CauseClock        Cause = "clock unusable"
	CauseStale        Cause = "stale"
	CauseAhead        Cause = "read ahead"
	// The causes only a list an operator signed can have.
	CauseVersion        Cause = "another format version"
	CauseUnsigned       Cause = "a header that does not verify"
	CauseOtherPlane     Cause = "another plane's"
	CauseUnanswered     Cause = "operator ports unavailable"
	CauseRouteUnvouched Cause = "a route no operator vouches for"
)

// Causes is every cause this package names, in the order declared. The slice
// is a copy.
func Causes() []Cause {
	return []Cause{
		CauseNeverRead, CauseTooLarge, CauseMalformed, CauseRoute, CauseHeader, CauseShrunk, CauseRewritten,
		CauseNotPermitted, CauseDatedAhead, CauseLift, CauseClock, CauseStale, CauseAhead,
		CauseVersion, CauseUnsigned, CauseOtherPlane, CauseUnanswered, CauseRouteUnvouched,
	}
}

// CauseOf names the cause of a Judge refusal, a voucher that could not answer
// before any refusal it wraps. A refusal it does not know is CauseMalformed.
func CauseOf(err error) Cause {
	for _, c := range []struct {
		err   Error
		cause Cause
	}{
		{ErrUnanswered, CauseUnanswered},
		{ErrListTooLarge, CauseTooLarge}, {ErrListLines, CauseTooLarge},
		{ErrListRoute, CauseRoute}, {ErrListHeader, CauseHeader},
		{ErrListShrunk, CauseShrunk}, {ErrListRewritten, CauseRewritten},
		{ErrStopRefused, CauseNotPermitted}, {ErrDatedAhead, CauseDatedAhead},
		{ErrLiftUnsigned, CauseLift}, {ErrLiftMismatch, CauseLift}, {ErrJudgeClock, CauseClock},
		{ErrSignedLiftUnvouched, CauseLift}, {ErrSignedLiftMismatch, CauseLift},
		{ErrListVersion, CauseVersion}, {ErrRouteUpgrade, CauseVersion}, {ErrListUpgrade, CauseVersion},
		{ErrLiftUpgrade, CauseVersion}, {ErrHeaderOther, CauseOtherPlane}, {ErrOtherPlane, CauseOtherPlane},
		{ErrOtherFile, CauseOtherPlane}, {ErrHeaderUnsigned, CauseUnsigned},
		{ErrNoVoucher, CauseUnsigned}, {ErrRouteUnvouched, CauseRouteUnvouched},
	} {
		if errors.Is(err, c.err) {
			return c.cause
		}
	}
	return CauseMalformed
}

// staleAfter is how many poll intervals a snapshot answers for, as a pause
// snapshot's.
const staleAfter = 3

// maxDetailBytes bounds what a snapshot's detail quotes of a refusal.
const maxDetailBytes = 256

// MaxListedEntries bounds the active entries a report lists.
const MaxListedEntries = 64

// Snapshot is the stop state as one read found it, and the list a plane
// accepted so far, which an unknown read keeps and the next read is judged
// from. It is immutable.
type Snapshot struct {
	state    State
	cause    Cause
	detail   string
	list     List
	accepted List
	readAt   time.Time
	maxAge   time.Duration
}

// DisabledSnapshot is the state of a plane with no route.
func DisabledSnapshot() Snapshot { return Snapshot{state: Disabled} }

// Next judges content, the stop list read at the plane's clock now, against
// route, from the list s accepted, with one poll interval of tolerance: only
// the lines after its prefix are judged anew. The snapshot it returns answers
// for staleAfter intervals. A refused list is Unknown with its cause, and
// keeps the list s accepted.
func (s Snapshot) Next(route Route, content []byte, now time.Time, interval time.Duration) Snapshot {
	return s.NextContext(context.Background(), route, content, now, interval)
}

// NextContext is Next whose questions to the voucher asked again are held to
// ctx, as JudgeFromContext holds them.
func (s Snapshot) NextContext(ctx context.Context, route Route, content []byte, now time.Time, interval time.Duration) Snapshot {
	l, err := JudgeFromContext(ctx, route, s.accepted, content, now, interval)
	if err != nil {
		return s.Unknown(CauseOf(err), err.Error(), now, interval)
	}
	state := Clear
	if len(activeAt(l.entries, now, time.Time{}, 1)) > 0 {
		state = Stopped
	}
	return Snapshot{state: state, list: l, accepted: l, readAt: now, maxAge: interval}
}

// Unknown is an Unknown snapshot read at now with cause, keeping the list s
// accepted. A reader that cannot read the file says so through it.
func (s Snapshot) Unknown(cause Cause, detail string, now time.Time, interval time.Duration) Snapshot {
	return Snapshot{state: Unknown, cause: cause, detail: bounded(detail), accepted: s.accepted, readAt: now, maxAge: interval}
}

// State is the snapshot's state.
func (s Snapshot) State() State { return s.state }

// Cause is why the state is Unknown, and empty for any other state.
func (s Snapshot) Cause() Cause {
	if s.state == Unknown && s.cause == "" {
		return CauseNeverRead
	}
	return s.cause
}

// Detail is what the judge refused, for a log line; empty unless Unknown,
// and cut to maxDetailBytes.
func (s Snapshot) Detail() string { return s.detail }

// ReadAt is the plane's clock when the list was read.
func (s Snapshot) ReadAt() time.Time { return s.readAt }

// Accepted is the prefix the next read is judged from.
func (s Snapshot) Accepted() Prefix { return s.accepted.prefix }

// AcceptedList is the list the plane accepted last, which an unknown read
// keeps: the list it holds, whatever the last read found.
func (s Snapshot) AcceptedList() List { return s.accepted }

// Header is the header of the list read; the zero Header unless the list was
// accepted.
func (s Snapshot) Header() Header { return s.list.header }

// Usage is how much of its bounds the list read uses; zero unless the list
// was accepted.
func (s Snapshot) Usage() Usage { return s.list.usage }

// Entries is a copy of the stops no lift ended, expired ones among them.
func (s Snapshot) Entries() []Entry { return s.list.Entries() }

// At is s as it stands at now: a read snapshot older than three poll
// intervals, or read after now, is Unknown with that cause.
func (s Snapshot) At(now time.Time) Snapshot {
	if s.state != Clear && s.state != Stopped {
		return s
	}
	switch age := now.Sub(s.readAt); {
	case age < 0:
		return s.Unknown(CauseAhead, fmt.Sprintf("read %v after the plane's clock", -age), s.readAt, s.maxAge)
	case age > answersFor(s.maxAge):
		return s.Unknown(CauseStale, fmt.Sprintf("read %v ago, past %d poll intervals", age, staleAfter), s.readAt, s.maxAge)
	}
	return s
}

// answersFor is staleAfter intervals, saturated rather than wrapped.
func answersFor(interval time.Duration) time.Duration {
	if interval > math.MaxInt64/staleAfter {
		return math.MaxInt64
	}
	return staleAfter * interval
}

// ActiveEntries is at most MaxListedEntries of the entries active at now
// given floor, in the order of their lines, and how many are active in all.
func (s Snapshot) ActiveEntries(now, floor time.Time) ([]Entry, int) {
	if s.state != Clear && s.state != Stopped {
		return nil, 0
	}
	all := activeAt(s.list.entries, now, floor, len(s.list.entries))
	return all[:min(len(all), MaxListedEntries)], len(all)
}

func activeAt(entries []Entry, now, floor time.Time, limit int) []Entry {
	var out []Entry
	for _, e := range entries {
		if len(out) == limit {
			break
		}
		if active(e, now, floor) {
			out = append(out, e)
		}
	}
	return out
}

// ActiveAt reports whether e still stops at now given floor, by the rule a
// plane decides a call under.
func (e Entry) ActiveAt(now, floor time.Time) bool { return active(e, now, floor) }

// active reports whether e still stops: it ends only at a clock the call can
// trust, one usable and not behind floor, at or past its expiry. An
// approval's lapse reads the same clock the other way, since there an
// untrusted clock must end what it would otherwise keep.
func active(e Entry, now, floor time.Time) bool {
	trusted := policy.UsableTime(now) && !now.Before(floor)
	return !trusted || now.Before(e.ExpiresAt)
}

// bounded cuts detail to maxDetailBytes, at a character boundary.
func bounded(detail string) string {
	if len(detail) <= maxDetailBytes {
		return detail
	}
	cut := maxDetailBytes
	for cut > 0 && !utf8.RuneStart(detail[cut]) {
		cut--
	}
	return detail[:cut] + "..."
}
