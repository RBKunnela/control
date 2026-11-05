package runs

import "context"

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
