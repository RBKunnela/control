package runs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// maxAncestry is the most ancestors a child's first admission reads before
// it finds one the plane admitted or the root.
const maxAncestry = 32

// parentStands refuses, with ErrParentClosed, an open child the plane never
// admitted below an ancestor whose close state/ holds or the handle failed to
// carry. A child admitted before keeps running, and so does every descendant
// of a run admitted before: closing a parent closes none of its children. The
// plane's own <id>.seen tells them apart, never a signed time, which two
// operators' clocks would skew. It is nil off a signed layout and for a root.
func (p *Plane) parentStands(ctx context.Context, rec Record) error {
	if !p.signed || rec.Parent == "" {
		return nil
	}
	switch seen, err := p.marked(rec.ID + seenSuffix); {
	case err != nil:
		return fmt.Errorf("the first admission of %s: %w", rec.ID, err)
	case seen:
		return nil
	}
	return p.ancestorsStand(ctx, rec)
}

// ancestorsStand walks up from rec's parent until it finds an ancestor the
// plane admitted, or the root, refusing at the first ancestor whose close is
// carried. Between the two it reads each ancestor's record as Resolve reads
// one, so a run put back above a refused child cannot vouch for a grandchild.
func (p *Plane) ancestorsStand(ctx context.Context, rec Record) error {
	id := rec.Parent
	for range maxAncestry {
		switch closed, err := p.closeCarried(id); {
		case err != nil:
			return err
		case closed:
			p.counts.refused(ErrParentClosed)
			return fmt.Errorf("%w: %s was closed before this run was first admitted", ErrParentClosed, id)
		}
		if id == rec.Root {
			return nil
		}
		switch seen, err := p.marked(id + seenSuffix); {
		case err != nil:
			return fmt.Errorf("the first admission of %s: %w", id, err)
		case seen:
			return nil
		}
		next, err := p.ancestor(ctx, id, rec.Root)
		if err != nil {
			return err
		}
		id = next
	}
	return fmt.Errorf("%w: %s has more than %d ancestors the plane never admitted", ErrTreeBound, rec.ID, maxAncestry)
}

// closeCarried reports whether the close of run id is in state/ or held.
func (p *Plane) closeCarried(id string) (bool, error) {
	if p.uncarried.has(id) {
		return true, nil
	}
	closed, err := p.marked(id + closedSuffix)
	if err != nil {
		return false, fmt.Errorf("the close of %s: %w", id, err)
	}
	return closed, nil
}

// ancestor reads and judges the record of run id, an ancestor of a run of
// root that is not root, and returns its parent.
func (p *Plane) ancestor(ctx context.Context, id, root string) (string, error) {
	stored, err := p.d.readStored(id)
	if err != nil {
		p.counts.refused(err)
		return "", fmt.Errorf("the ancestor %s: %w", id, err)
	}
	if err := p.take(ctx, stored); err != nil {
		return "", fmt.Errorf("the ancestor %s: %w", id, err)
	}
	if rec := stored.Record; rec.Root != root || rec.Parent == "" {
		return "", fmt.Errorf("%w: %s is not under %s", ErrTreeBroken, id, root)
	}
	return stored.Record.Parent, nil
}

// marked reports whether state/ holds the empty marker name, refusing one
// that is not a regular file of the plane's alone.
func (p *Plane) marked(name string) (bool, error) {
	f, err := p.st.openRegular(name, os.O_RDONLY)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, f.Close()
}
