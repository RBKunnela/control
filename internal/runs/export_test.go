package runs

import (
	"context"
	"io/fs"
	"os"
)

// SetEffectiveUID makes uid the user a directory has to belong to until the
// returned function restores the real one.
func SetEffectiveUID(uid func() int) (restore func()) {
	saved := effectiveUID
	effectiveUID = uid
	return func() { effectiveUID = saved }
}

// PruneStoppedAfterArchive is Prune with archived called once each tree's
// copy is on disk and before anything of it is removed.
func (a *Admin) PruneStoppedAfterArchive(ctx context.Context, req PruneRequest, archived func() error) (Pruned, error) {
	return a.prune(ctx, req, archived)
}

// RecordsOwnedByAnother holds p's records/ to ownedByAnother from now on,
// as a plane opened without PlaneOwned holds it, whoever owns it.
func (p *Plane) RecordsOwnedByAnother() { p.d.owner = ownedByAnother }

// ChmodMade sets the mode of the directory name under top as a signed
// layout's two directories are set once made.
func ChmodMade(top *os.Root, name string, mode fs.FileMode) error { return chmodMade(top, name, mode) }

// MaxAncestry is how many ancestors a child's first admission reads.
const MaxAncestry = maxAncestry

// FailSyncAfterMaking runs fail before each directory sync once a plane made
// or removed name, answering its error in place of the sync, until the
// returned function restores the real sync.
func FailSyncAfterMaking(name string, fail func() error) (restore func()) {
	saved := syncMade
	syncMade = func(d *dir, made string) error {
		if made == name {
			if err := fail(); err != nil {
				return err
			}
		}
		return saved(d, made)
	}
	return func() { syncMade = saved }
}

// FailFileSyncOf runs fail before each sync of a file a plane made at name,
// answering its error in place of the sync, until the returned function
// restores the real sync.
func FailFileSyncOf(name string, fail func() error) (restore func()) {
	saved := syncFile
	syncFile = func(f *os.File, made string) error {
		if made == name {
			if err := fail(); err != nil {
				return err
			}
		}
		return saved(f, made)
	}
	return func() { syncFile = saved }
}
