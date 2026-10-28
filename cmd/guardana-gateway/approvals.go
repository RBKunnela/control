package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
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
		out = append(out, gateway.Held{
			Approval:   r.Approval,
			Binding:    r.Binding,
			Resolution: heldResolution(r.Resolution),
		})
	}
	return out, nil
}

func (s *approvalStore) Consume(ctx context.Context, binding approval.Binding, requestID, approvalID string, now time.Time) (*controlv1.Approval, error) {
	a, err := s.plane.Consume(ctx, binding, requestID, approvalID, now)
	return a, storeError(err)
}

func (s *approvalStore) Resolve(ctx context.Context, binding approval.Binding, requestID string, resolution gateway.Resolution, now time.Time) error {
	to, ok := storeResolution(resolution)
	if !ok {
		return fmt.Errorf("%w: %d", gateway.ErrResolution, resolution)
	}
	return storeError(s.plane.Resolve(ctx, binding, requestID, to, now))
}

// storeErrors is the translation the store's package documents, one entry per
// refusal the pipeline names.
var storeErrors = map[approvals.Error]gateway.Error{
	approvals.ErrNoApproval:       gateway.ErrNoApproval,
	approvals.ErrApprovalConsumed: gateway.ErrApprovalConsumed,
	approvals.ErrApprovalExpired:  gateway.ErrApprovalExpired,
	approvals.ErrApprovalRejected: gateway.ErrApprovalRejected,
	approvals.ErrMultiUse:         gateway.ErrMultiUse,
	approvals.ErrZeroTime:         gateway.ErrZeroTime,
	approvals.ErrInvalidHold:      gateway.ErrInvalidHold,
	approvals.ErrAlreadyHeld:      gateway.ErrAlreadyHeld,
	approvals.ErrApprovalAnswered: gateway.ErrApprovalAnswered,
	approvals.ErrApprovalAnswer:   gateway.ErrApprovalAnswer,
	approvals.ErrResolution:       gateway.ErrResolution,
}

// storeError names a store's refusal in the pipeline's vocabulary, keeping the
// store's own words beside it so an operator reads which directory, record or
// bound refused.
func storeError(err error) error {
	return translate(err, storeErrors)
}

// heldResolution reads what the store can prove about a record. A resolution
// this build cannot name is the store having no answer, so the plane holds the
// request anew rather than reading a record it cannot speak for as spent.
func heldResolution(r approvals.Resolution) gateway.Resolution {
	switch r {
	case approvals.ResolutionPending:
		return gateway.ResolutionPending
	case approvals.ResolutionConsumed:
		return gateway.ResolutionConsumed
	case approvals.ResolutionNotResumed:
		return gateway.ResolutionNotResumed
	default:
		return gateway.ResolutionUnspecified
	}
}

// storeResolution is the one resolution a store may be told to write. Only the
// consuming path marks a record spent, so nothing else is passed through.
func storeResolution(r gateway.Resolution) (approvals.Resolution, bool) {
	if r == gateway.ResolutionNotResumed {
		return approvals.ResolutionNotResumed, true
	}
	return approvals.ResolutionUnspecified, false
}

// holdJournal is the plane's own directory of its own holds, as the
// pipeline's HoldJournal.
type holdJournal struct{ journal *holdjournal.Journal }

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

// openApprovals opens the store the configuration names. The memory store
// keeps its records in this process, so nothing outside it answers a hold; the
// file store is a directory an approver writes, and the plane holds its lock
// for as long as it serves.
func openApprovals(cfg *gatewayconfig.Config) (gateway.ApprovalStore, *approvals.Plane, error) {
	if cfg.Approvals.Provider != gatewayconfig.ProviderFile {
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
	return &holdJournal{journal: j}, j, nil
}
