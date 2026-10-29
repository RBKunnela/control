package runs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
)

// Lookup reads the record of run id as Plane.Lookup does, under the
// directory's lock.
func (a *Admin) Lookup(ctx context.Context, id string) (_ Record, err error) {
	if err := checkRunID(id); err != nil {
		return Record{}, err
	}
	end, err := a.begin(ctx)
	if err != nil {
		return Record{}, err
	}
	defer func() { err = errors.Join(err, end()) }()
	return a.d.lookup(id)
}

// Tree reads run root and every run whose root it is: root first, then each
// run after its parent, with no secret's hash. Every record of the directory
// is read and only the tree's are kept, so the runs of other trees bound
// nothing; bound is the most runs the tree may hold, root included. Tree
// refuses a bound that is not positive with ErrBound, a run no record names
// with ErrNoRun, a run opened under another with ErrNotRoot, a tree past
// bound with ErrTreeBound, a member of another tenant than root's with
// ErrTreeTenant, one of another project with ErrTreeProject, a member whose
// parents do not reach root within the tree with ErrTreeBroken, and, as List
// does, a record that does not decode.
func (a *Admin) Tree(ctx context.Context, root string, bound int) ([]Record, error) {
	return a.family(ctx, root, bound, func(head, r Record) bool { return r.Root == head.ID }, func(head Record) error {
		if head.Root != head.ID {
			return fmt.Errorf("%w: %s is under %s", ErrNotRoot, head.ID, head.Root)
		}
		return nil
	})
}

// Children reads run id and the runs opened under it, not the runs under
// those: id first, then its children by run id, with no secret's hash. bound
// is the most runs read, id included. It refuses as Tree does, a child whose
// root is not id's with ErrTreeBroken, and takes a run of any place in a
// tree.
func (a *Admin) Children(ctx context.Context, id string, bound int) ([]Record, error) {
	return a.family(ctx, id, bound, func(head, r Record) bool { return r.Parent == head.ID }, nil)
}

// family reads head's record, judges it with check, and then every record
// keep takes beside it, in the order ordered gives.
func (a *Admin) family(ctx context.Context, id string, bound int, keep func(head, r Record) bool,
	check func(head Record) error) (_ []Record, err error) {
	if bound <= 0 {
		return nil, fmt.Errorf("%w: %d", ErrBound, bound)
	}
	if err := checkRunID(id); err != nil {
		return nil, err
	}
	end, err := a.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, end()) }()
	head, err := a.d.lookup(id)
	if err != nil {
		return nil, err
	}
	if check != nil {
		if err := check(head); err != nil {
			return nil, err
		}
	}
	members, err := a.d.members(head, bound, keep)
	if err != nil {
		return nil, err
	}
	return ordered(head, members)
}

// members reads every record but head's and keeps those keep takes, each of
// head's tenant, project and root, at most bound-1 of them.
func (d *dir) members(head Record, bound int, keep func(head, r Record) bool) ([]Record, error) {
	entries, err := d.readDir()
	if err != nil {
		return nil, err
	}
	ids, err := scan(entries)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, id := range ids {
		if id == head.ID {
			continue
		}
		r, err := d.readRecord(id)
		switch {
		case err != nil:
			return nil, err
		case !keep(head, r):
			continue
		case r.Who.TenantID != head.Who.TenantID:
			return nil, fmt.Errorf("%w: %s", ErrTreeTenant, r.ID)
		case r.Who.ProjectID != head.Who.ProjectID:
			return nil, fmt.Errorf("%w: %s", ErrTreeProject, r.ID)
		case r.Root != head.Root:
			return nil, fmt.Errorf("%w: %s names root %s", ErrTreeBroken, r.ID, r.Root)
		case len(out)+2 > bound:
			return nil, fmt.Errorf("%w: more than %d", ErrTreeBound, bound)
		}
		r.SecretSHA256 = ""
		out = append(out, r)
	}
	return out, nil
}

// ordered is head, then members level by level, each after its parent. A
// member it never reaches has parents that do not lead to head: a parent
// in no record kept, or a loop.
func ordered(head Record, members []Record) ([]Record, error) {
	under := make(map[string][]Record, len(members))
	for _, m := range members {
		under[m.Parent] = append(under[m.Parent], m)
	}
	out := make([]Record, 0, len(members)+1)
	out = append(out, head)
	for i := 0; i < len(out); i++ {
		out = append(out, under[out[i].ID]...)
	}
	if len(out) != len(members)+1 {
		return nil, fmt.Errorf("%w: %d of %d runs reach %s", ErrTreeBroken, len(out)-1, len(members), head.ID)
	}
	return out, nil
}

// lookup reads the record of id with its secret's hash left out, and
// refuses a run no record names with ErrNoRun.
func (d *dir) lookup(id string) (Record, error) {
	rec, err := d.readRecord(id)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Record{}, fmt.Errorf("%w: %s", ErrNoRun, id)
	case err != nil:
		return Record{}, err
	}
	rec.SecretSHA256 = ""
	return rec, nil
}
