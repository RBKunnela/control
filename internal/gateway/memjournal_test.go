package gateway

import (
	"context"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"
)

// MemoryHoldJournal is a HoldJournal in process memory, which is what the
// write order is driven against in a test. It keeps a plane's holds no longer
// than the plane itself, so it closes no hold a restart loses: only a journal
// that outlives the process does that.
type MemoryHoldJournal struct {
	mu      sync.Mutex
	entries map[string]HoldEntry
	order   []string
}

var _ HoldJournal = (*MemoryHoldJournal)(nil)

// Record files entry under its request id.
func (j *MemoryHoldJournal) Record(ctx context.Context, entry HoldEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !recordable(entry) {
		return ErrHoldEntry
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	id := entry.IDs.RequestID
	if _, taken := j.entries[id]; taken {
		return ErrHoldRecorded
	}
	if j.entries == nil {
		j.entries = make(map[string]HoldEntry)
	}
	j.entries[id] = cloneEntry(entry)
	j.order = append(j.order, id)
	return nil
}

// recordable reports whether entry holds what closing its trail needs.
func recordable(entry HoldEntry) bool {
	return entry.State == HoldHeld &&
		entry.SchemaVersion != "" &&
		entry.IDs.RequestID != "" &&
		entry.LastEventID != "" &&
		entry.Binding != "" &&
		entry.Approval.GetApprovalId() != "" &&
		entry.Approval.GetRequestId() != "" &&
		!entry.Expires.IsZero()
}

// Mark flips the entry of requestID out of HoldHeld.
func (j *MemoryHoldJournal) Mark(ctx context.Context, requestID string, state HoldState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if state != HoldResuming && state != HoldClosing {
		return ErrHoldFlip
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	entry, kept := j.entries[requestID]
	switch {
	case !kept:
		return ErrNoHoldEntry
	case entry.State != HoldHeld:
		return ErrHoldFlip
	}
	entry.State = state
	j.entries[requestID] = entry
	return nil
}

// Forget drops the entry of requestID.
func (j *MemoryHoldJournal) Forget(ctx context.Context, requestID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.entries, requestID)
	j.order = slices.DeleteFunc(j.order, func(id string) bool { return id == requestID })
	return nil
}

// List reads the entries in the order they were recorded, at most bound of
// them.
func (j *MemoryHoldJournal) List(ctx context.Context, bound int) (HoldListing, error) {
	if err := ctx.Err(); err != nil {
		return HoldListing{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	var out HoldListing
	read := 0
	for _, id := range j.order {
		if read >= bound {
			return out, nil
		}
		read++
		entry := j.entries[id]
		if entry.State == HoldHeld {
			out.Held = append(out.Held, cloneEntry(entry))
			continue
		}
		out.Interrupted++
	}
	out.Complete = true
	return out, nil
}

// Entries returns what the journal holds, by request id, so a test can read
// the state an entry stands in without reading it out of a listing.
func (j *MemoryHoldJournal) Entries() map[string]HoldEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make(map[string]HoldEntry, len(j.entries))
	for id, entry := range j.entries {
		out[id] = cloneEntry(entry)
	}
	return out
}

// cloneEntry deep-copies the approval, so neither side's later writes reach
// the other.
func cloneEntry(entry HoldEntry) HoldEntry {
	entry.Approval = proto.CloneOf(entry.Approval)
	return entry
}
