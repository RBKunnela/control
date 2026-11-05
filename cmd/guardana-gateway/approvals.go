package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/gatewayconfig"
	"github.com/guardana/control/internal/holdjournal"
)

// The durable stores keep no import of the gateway, so the two seams are
// satisfied here: one adapter per store, each translating that store's
// documented refusals into the vocabulary the pipeline names. A refusal
// nobody translated travels as itself, and the pipeline refuses the call it
// was making on any error at all (ADR-0016).

// approvalStore is the approvals directory as the pipeline's ApprovalStore.
// What it hands back is the record and the binding, and never an envelope, a
// decision or a position in a trail: the plane compares every answer with its
// own record of what it held, and takes the trail's position from there.
type approvalStore struct{ plane *approvals.Plane }

var _ gateway.ApprovalStore = (*approvalStore)(nil)

func (s *approvalStore) Hold(ctx context.Context, held gateway.Held, now time.Time) error {
	return storeError(s.plane.Hold(ctx, approvals.Hold{
		Approval: held.Approval,
		Binding:  held.Binding,
		Envelope: held.Envelope,
		Decision: held.Decision,
	}, now))
}

func (s *approvalStore) Find(ctx context.Context, binding approval.Binding, now time.Time) ([]gateway.Held, error) {
	records, err := s.plane.Find(ctx, binding, now)
	if err != nil {
		return nil, storeError(err)
	}
	out := make([]gateway.Held, 0, len(records))
	for _, r := range records {
		out = append(out, gateway.Held{Approval: r.Approval, Binding: r.Binding})
	}
	return out, nil
}

func (s *approvalStore) Release(ctx context.Context, binding approval.Binding, requestID, approvalID string) error {
	return storeError(s.plane.Release(ctx, binding, requestID, approvalID))
}

// storeErrors is the translation the store's package documents, one entry per
// refusal the pipeline names.
var storeErrors = map[approvals.Error]gateway.Error{
	approvals.ErrNoApproval:       gateway.ErrNoApproval,
	approvals.ErrZeroTime:         gateway.ErrZeroTime,
	approvals.ErrInvalidHold:      gateway.ErrInvalidHold,
	approvals.ErrAlreadyHeld:      gateway.ErrAlreadyHeld,
	approvals.ErrApprovalAnswered: gateway.ErrApprovalAnswered,
	approvals.ErrApprovalAnswer:   gateway.ErrApprovalAnswer,
}

// storeError names a store's refusal in the pipeline's vocabulary, keeping the
// store's own words beside it so an operator reads which directory, record or
// bound refused.
func storeError(err error) error {
	return translate(err, storeErrors)
}

// spentLedger is the ledger beside the plane's hold journal, as the
// pipeline's Ledger. The journal's package answers a refusal and nothing
// else; the resolution the pipeline reads beside it is built here from that
// refusal, so what this returns is what the package documents and no more.
type spentLedger struct{ ledger *holdjournal.Ledger }

var _ gateway.Ledger = (*spentLedger)(nil)

func (l *spentLedger) Spend(ctx context.Context, b approval.Binding, req, appr, proof string, now time.Time) (gateway.Resolution, error) {
	err := l.ledger.Spend(ctx, b, req, appr, proof, now)
	switch {
	case err == nil:
		return gateway.ResolutionConsumed, nil
	case errors.Is(err, holdjournal.ErrSpent):
		return gateway.ResolutionConsumed, ledgerError(err)
	case errors.Is(err, holdjournal.ErrSettled):
		return gateway.ResolutionNotResumed, ledgerError(err)
	}
	return gateway.ResolutionUnspecified, ledgerError(err)
}

func (l *spentLedger) Settle(ctx context.Context, b approval.Binding, req, appr string, now time.Time) (gateway.Resolution, error) {
	err := l.ledger.Settle(ctx, b, req, appr, now)
	switch {
	case err == nil:
		return gateway.ResolutionNotResumed, nil
	case errors.Is(err, holdjournal.ErrSpent):
		return gateway.ResolutionConsumed, ledgerError(err)
	}
	return gateway.ResolutionUnspecified, ledgerError(err)
}

func (l *spentLedger) Lookup(ctx context.Context, b approval.Binding, now time.Time) (map[string]gateway.Resolution, error) {
	marks, err := l.ledger.Lookup(ctx, b, now)
	if err != nil {
		return nil, ledgerError(err)
	}
	out := make(map[string]gateway.Resolution, len(marks))
	for req, m := range marks {
		out[req] = ledgerResolution(m)
	}
	return out, nil
}

// ledgerErrors is the translation the journal's package documents for its
// ledger.
var ledgerErrors = map[holdjournal.Error]gateway.Error{
	holdjournal.ErrSpent:       gateway.ErrApprovalConsumed,
	holdjournal.ErrSettled:     gateway.ErrNoApproval,
	holdjournal.ErrLedgerEntry: gateway.ErrLedgerEntry,
	holdjournal.ErrZeroTime:    gateway.ErrZeroTime,
}

func ledgerError(err error) error {
	return translate(err, ledgerErrors)
}

// ledgerResolution is a mark as the pipeline reads it. A mark this build
// cannot name proves nothing, which is the unspecified resolution.
func ledgerResolution(m holdjournal.Mark) gateway.Resolution {
	switch m {
	case holdjournal.MarkConsumed:
		return gateway.ResolutionConsumed
	case holdjournal.MarkNotResumed:
		return gateway.ResolutionNotResumed
	default:
		return gateway.ResolutionUnspecified
	}
}

// planeLedger is the ledger beside the plane's hold journal, or one in this
// process where no journal is configured: only the memory authority runs
// without one, and its holds do not outlive the process either.
func planeLedger(holds gateway.HoldJournal) gateway.Ledger {
	if h, ok := holds.(*holdJournal); ok && h.ledger != nil {
		return &spentLedger{ledger: h.ledger}
	}
	return &gateway.MemoryLedger{}
}

// holdJournal is the plane's own directory of its own holds, as the
// pipeline's HoldJournal.
type holdJournal struct {
	journal *holdjournal.Journal
	ledger  *holdjournal.Ledger
}

var _ gateway.HoldJournal = (*holdJournal)(nil)

func (j *holdJournal) Record(ctx context.Context, entry gateway.HoldEntry) error {
	return journalError(j.journal.Record(ctx, holdjournal.Entry{
		SchemaVersion: entry.SchemaVersion,
		State:         journalState(entry.State),
		IDs:           entry.IDs,
		LastEventID:   entry.LastEventID,
		Binding:       entry.Binding,
		Approval:      entry.Approval,
		Expires:       entry.Expires,
	}))
}

func (j *holdJournal) Mark(ctx context.Context, requestID string, state gateway.HoldState) error {
	return journalError(j.journal.Mark(ctx, requestID, journalState(state)))
}

func (j *holdJournal) Forget(ctx context.Context, requestID string) error {
	return journalError(j.journal.Forget(ctx, requestID))
}

func (j *holdJournal) List(ctx context.Context, bound int) (gateway.HoldListing, error) {
	listing, err := j.journal.List(ctx, bound)
	if err != nil {
		return gateway.HoldListing{}, journalError(err)
	}
	return holdListing(listing), nil
}

// journalErrors is the translation the journal's package documents. Every
// other refusal travels as itself: the directory, the lock, a bound and a file
// that will not decode are not the entry's fault, and an operator acts on each
// of them differently.
var journalErrors = map[holdjournal.Error]gateway.Error{
	holdjournal.ErrEntry:         gateway.ErrHoldEntry,
	holdjournal.ErrRequestName:   gateway.ErrHoldEntry,
	holdjournal.ErrSchemaVersion: gateway.ErrHoldEntry,
	holdjournal.ErrEntryTooLarge: gateway.ErrHoldEntry,
	holdjournal.ErrRecorded:      gateway.ErrHoldRecorded,
	holdjournal.ErrNoEntry:       gateway.ErrNoHoldEntry,
	holdjournal.ErrFlip:          gateway.ErrHoldFlip,
	holdjournal.ErrMaybeRecorded: gateway.ErrHoldMaybeRecorded,
}

func journalError(err error) error {
	return translate(err, journalErrors)
}

// translate names one package's refusal in the pipeline's vocabulary. The
// sentinels of a package are distinct constants, so at most one of them
// matches, and an error none of them matches is returned unchanged.
func translate[E interface {
	comparable
	error
}](err error, table map[E]gateway.Error) error {
	if err == nil {
		return nil
	}
	for from, to := range table {
		if errors.Is(err, from) {
			return fmt.Errorf("%w: %w", to, err)
		}
	}
	return err
}

// journalState is where an entry stands, as the journal spells it. A state
// this build cannot name becomes the journal's unknown state, which it
// refuses to record or to flip into.
func journalState(s gateway.HoldState) holdjournal.State {
	switch s {
	case gateway.HoldHeld:
		return holdjournal.StateHeld
	case gateway.HoldResuming:
		return holdjournal.StateResuming
	case gateway.HoldClosing:
		return holdjournal.StateClosing
	default:
		return holdjournal.StateUnknown
	}
}

// holdState is the same reading back. An entry in a state this build cannot
// name is one the plane cannot speak for, which is what the pipeline's
// unknown state means.
func holdState(s holdjournal.State) gateway.HoldState {
	switch s {
	case holdjournal.StateHeld:
		return gateway.HoldHeld
	case holdjournal.StateResuming:
		return gateway.HoldResuming
	case holdjournal.StateClosing:
		return gateway.HoldClosing
	default:
		return gateway.HoldUnknown
	}
}

// holdListing carries a pass over the journal across the seam, counts and all:
// what the pass could not say is as much of the report as what it read.
func holdListing(listing holdjournal.Listing) gateway.HoldListing {
	out := gateway.HoldListing{
		Interrupted: listing.Interrupted,
		Unreadable:  listing.Unreadable,
		Complete:    listing.Complete,
	}
	for _, e := range listing.Held {
		out.Held = append(out.Held, gateway.HoldEntry{
			SchemaVersion: e.SchemaVersion,
			State:         holdState(e.State),
			IDs:           e.IDs,
			LastEventID:   e.LastEventID,
			Binding:       e.Binding,
			Approval:      e.Approval,
			Expires:       e.Expires,
		})
	}
	return out
}

// openApprovals opens the store the configuration's authority keeps the held
// records in. The memory store keeps them in this process, so nothing outside
// it answers a hold; under directory and signed they are a directory an
// approver lists, and the plane holds its lock for as long as it serves.
func openApprovals(cfg *gatewayconfig.Config) (gateway.ApprovalStore, *approvals.Plane, error) {
	if cfg.Approvals.Authority == gatewayconfig.AuthorityMemory {
		return &gateway.MemoryApprovals{}, nil, nil
	}
	// The window is the plane's own TTL: a record standing further from its
	// request than this plane could ever mint is one it did not write, and a
	// forged record cannot outlast a window it did not choose.
	p, err := approvals.OpenPlane(cfg.Resolve(cfg.Approvals.Dir),
		approvals.WithMaxRecords(cfg.Approvals.MaxRecords),
		approvals.WithMaxRecordBytes(cfg.Approvals.MaxRecordBytes),
		approvals.WithMaxApprovalWindow(cfg.Approvals.TTL))
	if err != nil {
		return nil, nil, fmt.Errorf("approvals.dir: %w", err)
	}
	return &approvalStore{plane: p}, p, nil
}

// openJournal opens the plane's own journal of its own holds, where one is
// configured. A plane without one holds and resumes as it otherwise would and
// closes no hold it loses to a restart, which is the limit ADR-0016 declares
// and which `doctor`, `/healthz` and the start-up line all say out loud.
func openJournal(cfg *gatewayconfig.Config) (gateway.HoldJournal, *holdjournal.Journal, error) {
	if cfg.Approvals.HoldJournalDir == "" {
		return nil, nil, nil
	}
	j, err := holdjournal.Open(cfg.Resolve(cfg.Approvals.HoldJournalDir),
		holdjournal.WithMaxEntries(cfg.Approvals.MaxRecords),
		holdjournal.WithMaxEntryBytes(cfg.Approvals.MaxRecordBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("approvals.hold_journal_dir: %w", err)
	}
	ledger, err := openLedger(j, cfg.Approvals.TTL)
	if err != nil {
		return nil, nil, errors.Join(fmt.Errorf("approvals.hold_journal_dir: %w", err), j.Close())
	}
	return &holdJournal{journal: j, ledger: ledger}, j, nil
}

// openLedger opens the ledger beside the journal and forgets the marks older
// than one approval lifetime: an approval spent at a time t expires before t
// plus that lifetime, so no record such a mark speaks for is still live.
func openLedger(j *holdjournal.Journal, ttl time.Duration) (*holdjournal.Ledger, error) {
	ledger, err := j.Ledger()
	if err != nil {
		return nil, err
	}
	if _, err := ledger.Prune(context.Background(), time.Now().Add(-ttl)); err != nil {
		return nil, fmt.Errorf("the ledger's sweep: %w", err)
	}
	return ledger, nil
}
