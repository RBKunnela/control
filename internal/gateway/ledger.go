package gateway

import (
	"context"
	"sync"
	"time"

	"github.com/guardana/control/internal/core/approval"
)

// Resolution is what became of a held request's approval, as far as the
// plane's own ledger can prove it.
//
// The zero value is the ledger saying it cannot tell, which is why this is not
// a bool: a bool's zero value reads as "not consumed", so a ledger that cannot
// answer would be indistinguishable from one answering that nothing used the
// approval, and the unsafe side would be reached by default rather than on
// purpose (ADR-0016).
type Resolution int

const (
	// ResolutionUnspecified is a ledger that cannot say what became of the
	// approval. It proves nothing, so the plane holds the call anew.
	ResolutionUnspecified Resolution = iota
	// ResolutionConsumed is an approval a plane spent on an execution of the
	// request it was held for. It is the only answer APPROVAL_ALREADY_USED
	// may rest on, and only Spend sets it.
	ResolutionConsumed
	// ResolutionNotResumed is an approval a plane gave up on, because the
	// request it was granted for is gone. Nothing spent it and nothing will.
	ResolutionNotResumed
)

// Ledger is the plane's own record of which approvals it spent and which it
// gave up on. It is the only place a spent mark lives: the approval store
// holds what the plane held and what approvers answered, and nothing an
// approver can write makes the plane read an approval as spent or given up.
//
// Every method refuses a zero now with ErrZeroTime, and an empty binding,
// request id or approval id with ErrLedgerEntry: nothing is ever read as "any
// approval will do". A ledger that cannot be read or written answers an error
// of its own, which the plane meets with INDETERMINATE and nothing spent.
type Ledger interface {
	// Spend is the compare-and-swap of invariant 6: it marks approval appr of
	// request req under b consumed at now, recording proof, the approver the
	// plane judged the answer to come from. It answers (ResolutionConsumed,
	// nil) when this call spent it, (ResolutionConsumed, ErrApprovalConsumed)
	// when an earlier call did, and (ResolutionNotResumed, ErrNoApproval) when
	// the plane had settled it. An empty proof is refused with ErrLedgerEntry.
	Spend(ctx context.Context, b approval.Binding, req, appr, proof string, now time.Time) (Resolution, error)
	// Settle marks approval appr of request req under b not resumed at now. It
	// answers (ResolutionNotResumed, nil) when that was done now or before,
	// and (ResolutionConsumed, ErrApprovalConsumed) when the approval was
	// spent, since a spent mark is proof of an execution and nothing writes
	// over it.
	Settle(ctx context.Context, b approval.Binding, req, appr string, now time.Time) (Resolution, error)
	// Lookup answers every resolution the ledger holds under b at now, keyed
	// by request id, and an empty map when there is none. Where one request
	// has marks under two approval ids, ResolutionConsumed wins.
	Lookup(ctx context.Context, b approval.Binding, now time.Time) (map[string]Resolution, error)
}

// MemoryLedger is a Ledger in process memory. The zero value is ready to use
// and holds nothing. What it holds is lost with the process, so a plane that
// restarts holds anew what it would otherwise have answered with
// APPROVAL_ALREADY_USED; it never runs a call twice, because a hold does not
// survive the restart either.
type MemoryLedger struct {
	mu      sync.Mutex
	entries map[ledgerKey]ledgerMark
}

var _ Ledger = (*MemoryLedger)(nil)

type ledgerKey struct {
	binding  approval.Binding
	request  string
	approval string
}

type ledgerMark struct {
	resolution Resolution
	proof      string
	written    time.Time
}

// Spend marks the approval consumed unless a mark is there already.
func (m *MemoryLedger) Spend(ctx context.Context, b approval.Binding, req, appr, proof string, now time.Time) (Resolution, error) {
	if err := checkLedgerCall(ctx, b, req, appr, now); err != nil {
		return ResolutionUnspecified, err
	}
	if proof == "" {
		return ResolutionUnspecified, ErrLedgerEntry
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := ledgerKey{binding: b, request: req, approval: appr}
	switch m.entries[key].resolution {
	case ResolutionConsumed:
		return ResolutionConsumed, ErrApprovalConsumed
	case ResolutionNotResumed:
		return ResolutionNotResumed, ErrNoApproval
	}
	if m.entries == nil {
		m.entries = make(map[ledgerKey]ledgerMark)
	}
	m.entries[key] = ledgerMark{resolution: ResolutionConsumed, proof: proof, written: now}
	return ResolutionConsumed, nil
}

// Settle marks the approval not resumed unless it was spent.
func (m *MemoryLedger) Settle(ctx context.Context, b approval.Binding, req, appr string, now time.Time) (Resolution, error) {
	if err := checkLedgerCall(ctx, b, req, appr, now); err != nil {
		return ResolutionUnspecified, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := ledgerKey{binding: b, request: req, approval: appr}
	switch m.entries[key].resolution {
	case ResolutionConsumed:
		return ResolutionConsumed, ErrApprovalConsumed
	case ResolutionNotResumed:
		return ResolutionNotResumed, nil
	}
	if m.entries == nil {
		m.entries = make(map[ledgerKey]ledgerMark)
	}
	m.entries[key] = ledgerMark{resolution: ResolutionNotResumed, written: now}
	return ResolutionNotResumed, nil
}

// Lookup answers the marks under b.
func (m *MemoryLedger) Lookup(ctx context.Context, b approval.Binding, now time.Time) (map[string]Resolution, error) {
	switch {
	case now.IsZero():
		return nil, ErrZeroTime
	case b == "":
		return nil, ErrLedgerEntry
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Resolution)
	for key, mark := range m.entries {
		if key.binding != b || out[key.request] == ResolutionConsumed {
			continue
		}
		out[key.request] = mark.resolution
	}
	return out, nil
}

// Prune forgets every mark written before before and reports how many. The
// plane passes its clock less the approval lifetime: an approval spent at a
// time t expires before t plus that lifetime, so no record a mark speaks for
// can still be live once the mark is pruned.
func (m *MemoryLedger) Prune(ctx context.Context, before time.Time) (int, error) {
	if before.IsZero() {
		return 0, ErrZeroTime
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pruned := 0
	for key, mark := range m.entries {
		if mark.written.Before(before) {
			delete(m.entries, key)
			pruned++
		}
	}
	return pruned, nil
}

// checkLedgerCall makes the refusals every ledger call shares.
func checkLedgerCall(ctx context.Context, b approval.Binding, req, appr string, now time.Time) error {
	switch {
	case now.IsZero():
		return ErrZeroTime
	case b == "" || req == "" || appr == "":
		return ErrLedgerEntry
	}
	return ctx.Err()
}
