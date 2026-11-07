package runs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/guardana/control/internal/files"
)

// PruneRequest is a prune the operator asks for.
type PruneRequest struct {
	// ExpiredBefore is the cutoff: a tree goes when every run in it expired
	// before it. It may not be after Now.
	ExpiredBefore time.Time
	// Archive is the directory the prune creates, for its owner alone, and
	// copies the records and the state of every tree it removes into. It
	// must not exist, and must not be inside the runs directory.
	Archive string
	// Now is the clock reading the cutoff is held to.
	Now time.Time
}

// Pruned is what a prune did.
type Pruned struct {
	// Trees are the roots of the trees archived and removed, by run id, and
	// Runs the records that went with them.
	Trees []string
	Runs  int
	// Refused is every tree the cutoff reached that the prune left whole.
	Refused []RefusedTree
}

// RefusedTree is a tree a prune left in place, and why.
type RefusedTree struct {
	Root string
	Err  error
}

// Prune removes the run trees whose every run expired before the cutoff,
// each only after its records and its state are copied into the archive and
// forced to disk, under the directory's lock. A tree with a run that did not
// expire before the cutoff, one whose root has no record or whose parents do
// not reach it, one whose state or lock file cannot be read, and one whose
// state lock a plane holds is refused and named, and the others go on. A
// record anywhere that does not decode refuses the whole prune before
// anything is written: it may belong to any tree.
//
// A run expires at its expiry; a closed run counts by its expiry too. Trees
// go one at a time, children first and the root's record before its state, so
// a prune stopped part way leaves every tree it did not finish either whole
// or as a root with fewer runs, and every file it removed in the archive.
//
// On a signed layout a prune reads and removes records/ alone: state/ is the
// plane's, so a pruned root's state, lock and carried closes stay there, and
// no plane serves a run with no record.
func (a *Admin) Prune(ctx context.Context, req PruneRequest) (Pruned, error) {
	return a.prune(ctx, req, nil)
}

// prune is Prune with archived called once a tree's copy is on disk and
// before anything of it is removed: an error from it stops the prune there.
func (a *Admin) prune(ctx context.Context, req PruneRequest, archived func() error) (_ Pruned, err error) {
	if err := req.check(); err != nil {
		return Pruned{}, err
	}
	end, err := a.begin(ctx)
	if err != nil {
		return Pruned{}, err
	}
	defer func() { err = errors.Join(err, end()) }()
	trees, err := a.d.trees()
	if err != nil {
		return Pruned{}, err
	}
	archive, err := a.d.newArchive(req.Archive)
	if err != nil {
		return Pruned{}, err
	}
	defer func() { err = errors.Join(err, archive.Close()) }()
	var out Pruned
	for _, root := range sortedRoots(trees) {
		members := trees[root]
		if !reached(root, members, req.ExpiredBefore) {
			continue
		}
		n, err := a.d.pruneTree(root, members, req.ExpiredBefore, archive, archived)
		var refused *treeRefusal
		switch {
		case errors.As(err, &refused):
			out.Refused = append(out.Refused, RefusedTree{Root: root, Err: refused.err})
			continue
		case err != nil:
			return out, fmt.Errorf("tree %s: %w", root, err)
		}
		out.Trees = append(out.Trees, root)
		out.Runs += n
	}
	return out, nil
}

// reached reports whether the cutoff reaches the tree of root: its root
// expired before it, or, with no root record to say, any run did. A child
// never outlives its parent when it opens, so a live root with an expired
// child is a tree still in use and is not reached.
func reached(root string, members []Record, cutoff time.Time) bool {
	if i := slices.IndexFunc(members, func(r Record) bool { return r.ID == root }); i >= 0 {
		return members[i].ExpiresAt.Before(cutoff)
	}
	return slices.ContainsFunc(members, func(r Record) bool { return r.ExpiresAt.Before(cutoff) })
}

func (req PruneRequest) check() error {
	switch {
	case req.Now.IsZero() || req.ExpiredBefore.IsZero():
		return fmt.Errorf("%w: a zero time", ErrPruneTime)
	case req.ExpiredBefore.After(req.Now):
		return fmt.Errorf("%w: the cutoff %s is after %s", ErrPruneTime, formatTime(req.ExpiredBefore), formatTime(req.Now))
	case req.Archive == "":
		return fmt.Errorf("%w: none is named", ErrArchive)
	}
	return nil
}

// treeRefusal is a tree left whole; anything else stops the prune.
type treeRefusal struct{ err error }

func (r *treeRefusal) Error() string { return r.err.Error() }

func refuseTree(format string, args ...any) error {
	return &treeRefusal{err: fmt.Errorf(format, args...)}
}

// trees reads every record and files it under the root it names.
func (d *dir) trees() (map[string][]Record, error) {
	entries, err := d.readDir()
	if err != nil {
		return nil, err
	}
	ids, err := d.scan(entries)
	if err != nil {
		return nil, err
	}
	out := map[string][]Record{}
	for _, id := range ids {
		r, err := d.readRecord(id)
		if err != nil {
			return nil, err
		}
		out[r.Root] = append(out[r.Root], r)
	}
	return out, nil
}

func sortedRoots(trees map[string][]Record) []string {
	roots := make([]string, 0, len(trees))
	for root := range trees {
		roots = append(roots, root)
	}
	slices.Sort(roots)
	return roots
}

// newArchive creates the archive directory for its owner alone, forces its
// entry to disk, and writes the runs directory's marker into it, so the
// archive reads as a runs directory of its own.
func (d *dir) newArchive(path string) (*os.Root, error) {
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrArchive, err)
	}
	here, err := d.root.Stat(".")
	if err != nil {
		return nil, err
	}
	if os.SameFile(parent, here) {
		return nil, fmt.Errorf("%w: %q is inside it", ErrArchive, clip(path))
	}
	if d.role == roleRecords {
		if top, err := os.Stat(filepath.Dir(d.name)); err != nil || os.SameFile(parent, top) {
			return nil, fmt.Errorf("%w: %q is beside records/ and state/", ErrArchive, clip(path))
		}
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrArchive, err)
	}
	//nolint:gosec // G302: a directory needs its owner's search bit
	if err := errors.Join(os.Chmod(path, 0o700), files.SyncDir(filepath.Dir(path))); err != nil {
		return nil, err
	}
	archive, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	marker, err := d.readFile(markerFile)
	if err == nil {
		err = copyInto(archive, markerFile, marker)
	}
	if err != nil {
		return nil, errors.Join(err, archive.Close())
	}
	return archive, nil
}

// pruneTree archives the tree of root and removes it, returning how many
// records went. members are the records naming root.
func (d *dir) pruneTree(root string, members []Record, cutoff time.Time, archive *os.Root, archived func() error) (_ int, err error) {
	order, err := treeOrder(root, members, cutoff)
	if err != nil {
		return 0, err
	}
	if d.role == roleFlat {
		lock, err := d.lockTree(root)
		if err != nil {
			return 0, err
		}
		defer func() { err = errors.Join(err, lock.Close()) }()
	}
	copies, err := d.treeFiles(root, order)
	if err != nil {
		return 0, &treeRefusal{err: err}
	}
	for _, c := range copies {
		if err := copyInto(archive, c.name, c.body); err != nil {
			return 0, err
		}
	}
	if err := syncRoot(archive); err != nil {
		return 0, err
	}
	if archived != nil {
		if err := archived(); err != nil {
			return 0, err
		}
	}
	if err := d.removeTree(root, order); err != nil {
		return 0, err
	}
	return len(order), nil
}

// treeOrder is the tree of root, root first and each run after its parent,
// refused when its root has no record, a run did not expire before the
// cutoff, or a run's parents do not reach the root.
func treeOrder(root string, members []Record, cutoff time.Time) ([]Record, error) {
	head := slices.IndexFunc(members, func(r Record) bool { return r.ID == root })
	if head < 0 {
		return nil, refuseTree("%w: the root %s has no record", ErrTreeBroken, root)
	}
	for _, r := range members {
		if !r.ExpiresAt.Before(cutoff) {
			return nil, refuseTree("%w: %s expires at %s", ErrTreeLive, r.ID, formatTime(r.ExpiresAt))
		}
	}
	order, err := ordered(members[head], slices.Delete(slices.Clone(members), head, head+1))
	if err != nil {
		return nil, &treeRefusal{err: err}
	}
	return order, nil
}

// lockTree takes the root's state lock without waiting, so no plane raises
// the state while the tree is copied and removed. The caller closes it.
func (d *dir) lockTree(root string) (*os.File, error) {
	lock, err := d.openRegular(root+lockSuffix, os.O_RDWR)
	if err != nil {
		return nil, refuseTree("the lock of %s: %w", root, err)
	}
	ok, err := tryLock(lock)
	switch {
	case err != nil:
		return nil, errors.Join(refuseTree("the lock of %s: %w", root, err), lock.Close())
	case !ok:
		return nil, errors.Join(refuseTree("%w: %s", ErrTreeLocked, root), lock.Close())
	}
	return lock, nil
}

type treeFile struct {
	name string
	body []byte
}

// treeFiles reads every record of the tree and the root's state, refusing a
// state that does not decode as the root's.
func (d *dir) treeFiles(root string, order []Record) ([]treeFile, error) {
	names := recordNames(order)
	if d.role == roleFlat {
		if _, err := d.readState(root); err != nil {
			return nil, fmt.Errorf("the state of %s: %w", root, err)
		}
		names = append([]string{root + stateSuffix}, names...)
	}
	out := make([]treeFile, 0, len(names))
	for _, name := range names {
		body, err := d.readFile(name)
		if err != nil {
			return nil, err
		}
		out = append(out, treeFile{name: name, body: body})
	}
	return out, nil
}

func recordNames(order []Record) []string {
	names := make([]string, 0, len(order))
	for _, r := range order {
		names = append(names, r.ID+recordSuffix)
	}
	return names
}

// removeTree removes the runs under the root last first, what a crash left at
// their temporary names, then the root's record, state and lock, and forces
// the directory to disk.
func (d *dir) removeTree(root string, order []Record) error {
	var names []string
	for i := len(order) - 1; i > 0; i-- {
		names = append(names, order[i].ID+recordSuffix, order[i].ID+recordTemp)
	}
	names = append(names, root+recordTemp, root+recordSuffix)
	if d.role == roleFlat {
		names = append(names, root+stateTemp, root+stateSuffix, root+lockSuffix)
	}
	for _, name := range names {
		if err := d.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return d.syncDir()
}

// copyInto creates name in archive for its owner alone, refusing a name that
// is there, and forces it to disk.
func copyInto(archive *os.Root, name string, body []byte) error {
	f, err := archive.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	return errors.Join(err, f.Sync(), f.Close())
}

func syncRoot(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
