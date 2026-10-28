package holdjournal

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
)

// Record files entry, which is in StateHeld, and returns only once it is
// durable. It refuses an entry that is missing anything its trail's close
// needs, or in another state, and a request id it holds an entry for already.
// An error wrapping ErrMaybeRecorded means the entry may be filed; any other
// means it was not.
func (j *Journal) Record(ctx context.Context, entry Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.mayWrite(); err != nil {
		return err
	}
	if entry.State != StateHeld {
		return fmt.Errorf("%w: an entry is recorded in %s", ErrEntry, entry.State)
	}
	name, err := encodeName(entry.IDs.RequestID)
	if err != nil {
		return err
	}
	body, err := encodeEntry(entry, j.opts.maxEntryBytes)
	if err != nil {
		return err
	}
	if j.entries >= j.opts.maxEntries {
		return fmt.Errorf("%w: %d entries, limit %d", ErrTooManyEntries, j.entries, j.opts.maxEntries)
	}
	if err := j.create(name, body); err != nil {
		if errors.Is(err, errExists) {
			return fmt.Errorf("%w: %q", ErrRecorded, cause(entry.IDs.RequestID))
		}
		if errors.Is(err, ErrMaybeRecorded) {
			// The entry stands, so it counts against the bound until a
			// Forget removes it or the next open counts the directory.
			j.entries++
		}
		return err
	}
	j.entries++
	return nil
}

// Mark flips the entry of requestID out of StateHeld into state, which is
// StateResuming or StateClosing, and returns only once the flip is durable.
func (j *Journal) Mark(ctx context.Context, requestID string, state State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.mayWrite(); err != nil {
		return err
	}
	if state != StateResuming && state != StateClosing {
		return fmt.Errorf("%w: into %s", ErrFlip, state)
	}
	name, err := encodeName(requestID)
	if err != nil {
		return err
	}
	entry, err := j.readEntry(name, requestID)
	if err != nil {
		return err
	}
	if entry.State != StateHeld {
		return fmt.Errorf("%w: out of %s", ErrFlip, entry.State)
	}
	entry.State = state
	body, err := encodeEntry(entry, j.opts.maxEntryBytes)
	if err != nil {
		return err
	}
	// A crash before the rename leaves the entry held, and that is the right
	// answer rather than a lost flip: the flip precedes the append it guards,
	// so nothing was appended, the trail really does still stand at its
	// request for approval, and a later pass may still close it.
	return j.replace(name, body)
}

// Forget drops the entry of requestID, whose trail can take nothing more. The
// caller forgets every execution it closes, including calls it never held, so
// a request with no entry is no error and costs one unlink at most.
func (j *Journal) Forget(ctx context.Context, requestID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.mayWrite(); err != nil {
		return err
	}
	name, err := encodeName(requestID)
	if err != nil {
		// An id that cannot name a file here has no entry here either.
		return nil
	}
	removed, err := j.remove(name)
	if err != nil {
		return err
	}
	if removed && j.entries > 0 {
		j.entries--
	}
	return nil
}

// List reads at most bound entries and reports what it found. A non-positive
// bound reads nothing and reports Complete false, because a pass that examined
// nothing has not found the journal empty; so does a pass a bound stopped, and
// one that met an entry it could not decode.
func (j *Journal) List(ctx context.Context, bound int) (Listing, error) {
	if err := ctx.Err(); err != nil {
		return Listing{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.usable(); err != nil {
		return Listing{}, err
	}
	if bound <= 0 {
		return Listing{}, nil
	}
	names, err := j.entryNames()
	if err != nil {
		return Listing{}, err
	}
	limit := min(bound, j.opts.maxEntries)
	out := Listing{Complete: len(names) <= limit}
	if len(names) > limit {
		names = names[:limit]
	}
	for _, name := range names {
		j.readInto(&out, name)
	}
	if out.Unreadable > 0 {
		out.Complete = false
	}
	return out, nil
}

// readInto reads one entry into the listing. An entry that will not decode, or
// that disagrees with the name it is filed under, is counted and never held:
// the pass cannot speak for that trail, and says so through Unreadable.
func (j *Journal) readInto(out *Listing, name string) {
	id, ok := decodeName(name)
	if !ok {
		out.Unreadable++
		return
	}
	entry, err := j.readEntry(name, id)
	switch {
	case err != nil:
		out.Unreadable++
	case entry.State == StateHeld:
		out.Held = append(out.Held, entry)
	default:
		out.Interrupted++
	}
}

// entryNames lists the entry files, sorted, so two passes over one directory
// read them in one order. A file this package did not write refuses the whole
// pass: the journal owns its directory, and guessing what else is in it is how
// a forged name gets read as an entry.
func (j *Journal) entryNames() ([]string, error) {
	listed, err := j.readDir()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range listed {
		switch classifyEntry(e) {
		case kindEntry:
			names = append(names, e.Name())
		case kindMarker, kindTemp:
		case kindForeign:
			return nil, fmt.Errorf("%w: %q", ErrForeignFile, cause(e.Name()))
		}
	}
	slices.Sort(names)
	return names, nil
}

// readEntry reads the entry filed under name and holds it to the request id
// that name encodes. A file whose request id disagrees with its name is
// refused, never read as if the two agreed: the name is how an entry is found
// and the content is what a close would be written from.
func (j *Journal) readEntry(name, requestID string) (Entry, error) {
	raw, err := j.readBounded(name, headerBytes+j.opts.maxEntryBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Entry{}, fmt.Errorf("%w: %q", ErrNoEntry, cause(requestID))
	case err != nil:
		return Entry{}, err
	}
	entry, err := decodeEntry(raw, j.opts.maxEntryBytes)
	if err != nil {
		return Entry{}, fmt.Errorf("the entry of %q: %w", cause(requestID), err)
	}
	if entry.IDs.RequestID != requestID {
		return Entry{}, fmt.Errorf("%w: the file of %q holds request %q",
			ErrNameMismatch, cause(requestID), cause(entry.IDs.RequestID))
	}
	return entry, nil
}
