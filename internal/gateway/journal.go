package gateway

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/evidence"
)

// holdEntrySchemaVersion is the version of the entry shape a journal stores.
const holdEntrySchemaVersion = "1.0"

// defaultReconcileMax bounds one reconciliation where the configuration names
// no bound, so a journal nobody bounded still costs a start a fixed amount of
// work.
const defaultReconcileMax = 256

// HoldState is where a journal entry stands. Its zero value is no state this
// build knows, which is read the same way as an interrupted close: the plane
// cannot say, so it says nothing and writes nothing.
type HoldState int

const (
	// HoldUnknown is an entry in no state this build knows.
	HoldUnknown HoldState = iota
	// HoldHeld is the one state that proves something: the trail stands at
	// its request for approval and can still be closed.
	HoldHeld
	// HoldResuming is an entry whose plane was about to write the approval's
	// answer on the trail.
	HoldResuming
	// HoldClosing is an entry whose plane was about to close the trail.
	HoldClosing
)

// HoldEntry is what a plane records about a request it holds for an approval,
// so that a hold it loses to a restart can still be closed on its own trail.
//
// It carries no envelope and no decision: a lost hold is closed, never
// resumed, and storing what a retry would be compared against would widen
// what the plane keeps on disk for behaviour nobody asked for (ADR-0016).
type HoldEntry struct {
	// SchemaVersion is the version of this shape; a journal refuses a major
	// version it does not know rather than reading past it.
	SchemaVersion string
	// State is where the entry stands.
	State HoldState
	// IDs name the held trail.
	IDs evidence.IDs
	// LastEventID is where that trail stands: its APPROVAL_REQUESTED.
	LastEventID string
	// Binding is what the approval was held under, and all the plane needs to
	// ask a store about it.
	Binding approval.Binding
	// Approval is what the plane minted and the agent was told to retry with.
	Approval *controlv1.Approval
	// Expires is the expiry the plane minted, which an answer may not exceed.
	Expires time.Time
}

// HoldListing is one pass over a journal: the entries that read as held, and
// what the pass could not say about the rest.
type HoldListing struct {
	// Held is the entries in HoldHeld, at most the bound the pass was given.
	Held []HoldEntry
	// Interrupted counts entries in any other state: a close a plane did not
	// finish, whose trail nobody can speak for.
	Interrupted int
	// Unreadable counts entries the journal could not decode. They are
	// unmeasured, never skipped, and a pass that met one is not complete.
	Unreadable int
	// Complete is false when the bound stopped the pass before the journal
	// was read out, or an entry could not be decoded: either way the pass has
	// not seen every hold, and may not report itself done.
	Complete bool
}

// HoldJournal is the plane's own durable record of its own holds, written by
// no other process. It is optional: a pipeline built without one holds and
// resumes exactly as it would otherwise, and never closes a hold it loses,
// which Stats reports as HoldJournal being false.
//
// The write order is what makes an entry's word worth anything, and it is the
// pipeline's to keep: an entry is recorded after APPROVAL_REQUESTED is
// appended and before the agent is told pending, every append that would move
// a trail past APPROVAL_REQUESTED is preceded by a flip out of HoldHeld, and
// the entry is forgotten once that trail can take nothing more. So HoldHeld
// means the trail stands at its request for approval, and a journal that
// refuses a write stops the append rather than being written around.
type HoldJournal interface {
	// Record files entry, which is in HoldHeld. It refuses an entry missing
	// anything its trail's close needs, or in another state, with
	// ErrHoldEntry, and a request id it holds an entry for already with
	// ErrHoldRecorded. It returns only after the entry is durable. An error
	// wrapping ErrHoldMaybeRecorded means the entry may be filed, and the
	// caller treats it so; any other error means nothing was filed.
	Record(ctx context.Context, entry HoldEntry) error
	// Mark flips the entry of requestID out of HoldHeld into state, which is
	// HoldResuming or HoldClosing. It refuses an entry it does not hold with
	// ErrNoHoldEntry, and one that is not in HoldHeld, or a state that is
	// neither, with ErrHoldFlip. It returns only after the flip is durable.
	Mark(ctx context.Context, requestID string, state HoldState) error
	// Forget drops the entry of requestID, which its trail can take nothing
	// more after. The plane calls it for every execution it closes, including
	// calls it never held, so forgetting a request it holds no entry for is
	// no error and is worth making cheap.
	Forget(ctx context.Context, requestID string) error
	// List reads at most bound entries and reports what it found. A
	// non-positive bound reads nothing and reports Complete false, because a
	// pass that examined nothing has not found the journal empty, and so does
	// a pass that could not decode an entry.
	List(ctx context.Context, bound int) (HoldListing, error)
}

// recordOutcome is what journalRecord learned of the entry.
type recordOutcome int

const (
	// entryFiled is an entry the journal holds, or no journal at all: the
	// hold may stand.
	entryFiled recordOutcome = iota
	// entryNotFiled is a refusal that filed nothing.
	entryNotFiled
	// entryMaybeFiled is a refusal after which the entry may be filed, so the
	// trail is closed only after the entry has left held.
	entryMaybeFiled
)

// journalRecord files own as a held entry, and reports whether it is filed,
// not filed, or may be. A pipeline with no journal keeps no entry and says
// so.
func (p *Pipeline) journalRecord(ctx context.Context, own *heldRequest) recordOutcome {
	if p.cfg.Journal == nil {
		return entryFiled
	}
	entry := HoldEntry{
		SchemaVersion: holdEntrySchemaVersion,
		State:         HoldHeld,
		IDs:           own.ids,
		LastEventID:   own.lastEventID,
		Binding:       own.binding,
		Approval:      proto.CloneOf(own.approval),
		Expires:       own.expires,
	}
	err := p.cfg.Journal.Record(ctx, entry)
	if err == nil {
		return entryFiled
	}
	p.counts.add(func(s *Stats) *uint64 { return &s.JournalRefusals })
	if errors.Is(err, ErrHoldMaybeRecorded) {
		return entryMaybeFiled
	}
	return entryNotFiled
}

// journalMark flips the entry of requestID into state and reports whether the
// caller may now append past that trail's APPROVAL_REQUESTED. A journal that
// refuses the flip blocks the append: the entry still says the trail stands
// where it stood, and only that statement lets a later plane close it.
func (p *Pipeline) journalMark(ctx context.Context, requestID string, state HoldState) bool {
	if p.cfg.Journal == nil {
		return true
	}
	if err := p.cfg.Journal.Mark(ctx, requestID, state); err != nil {
		p.counts.add(func(s *Stats) *uint64 { return &s.JournalRefusals })
		return false
	}
	return true
}

// journalForget drops the entry of requestID once its trail can take nothing
// more. An entry that will not go stays in the state the flip left it, which
// a later reconciliation reports rather than acts on, so nothing appends to
// that trail twice.
func (p *Pipeline) journalForget(ctx context.Context, requestID string) {
	if p.cfg.Journal == nil {
		return
	}
	if err := p.cfg.Journal.Forget(ctx, requestID); err != nil {
		p.counts.add(func(s *Stats) *uint64 { return &s.JournalRefusals })
	}
}
