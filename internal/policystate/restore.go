package policystate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/guardana/control/internal/policy"
)

// Step is called before each write a restore makes, with what the write
// is; an error it returns stops the restore there, as a crash would.
type Step func(what string) error

// Restored is what a restore of one floor directory did.
type Restored struct {
	// Written names the ids whose floor file a restore wrote, Listed those
	// it added to the marker.
	Written, Listed []string
	// Built is true when no directory stood at the name and the restore
	// made it.
	Built bool
}

// RestorePlane raises the floors of live, a plane floor directory, to the
// floors backup holds, a copy of one, and stamps every floor either holds a
// serial for at now: the higher serial of the two with its digest, issued
// at now and latest at now, so no statement issued before now confirms that
// serial again. A floor only live holds is stamped at its own serial. now is
// rounded up to the whole second, the precision of a statement's issuedAt,
// so none issued earlier in now's second confirms either. It refuses the
// same serial with two digests with policy.ErrFloorSerialReused and a clock
// behind either floor's latest issuedAt with policy.ErrClockBehindFloor,
// before it writes that id. An id neither holds a serial for is listed and
// given no file, so a start refuses until the operator resets it. An empty
// backup is none: live's floors are stamped all the same. A missing live is
// built under a temporary sibling name and renamed into place.
func RestorePlane(ctx context.Context, live, backup string, now time.Time, step Step) (Restored, error) {
	return restoreFloors(ctx, planeKind(now), live, backup, step)
}

// CheckPlane refuses what RestorePlane would refuse, writing nothing.
func CheckPlane(ctx context.Context, live, backup string, now time.Time) error {
	return checkFloors(ctx, planeKind(now), live, backup)
}

func planeKind(now time.Time) floorKind[Record] {
	at := stampAt(now)
	return floorKind[Record]{
		listEmpty:   true,
		stampsLive:  true,
		judge:       func(d *dir, e []os.DirEntry) ([]string, error) { return d.judgeContents(e, KindPlane) },
		writeMarker: func(d *dir, ids []string, create bool) error { return d.writeMarker(KindPlane, ids, create) },
		maxIDs:      MaxBundleIDs,
		tooMany:     ErrTooManyBundleIDs,
		read:        (*dir).readRecord,
		hasSerial:   func(r Record) bool { return r.Floor.HasSerial() },
		restored:    func(cur *Record, bk Record) (Record, bool, error) { return stampFloor(cur, bk, at) },
		write:       (*dir).writeRecord,
	}
}

// stampAt is now rounded up to the whole second.
func stampAt(now time.Time) time.Time {
	at := now.UTC().Truncate(time.Second)
	if at.Before(now) {
		at = at.Add(time.Second)
	}
	return at
}

// stampFloor is the floor a restore at at writes for one bundle id, and false
// when cur holds it already.
func stampFloor(cur *Record, bk Record, at time.Time) (Record, bool, error) {
	top, note := bk.Floor, bk.Reset
	held := []policy.Floor{bk.Floor}
	if cur != nil {
		note = cur.Reset
		held = append(held, cur.Floor)
		var err error
		if top, err = higherFloor(cur.Floor, top); err != nil {
			return Record{}, false, err
		}
	}
	for _, f := range held {
		if f.HasSerial() && at.Before(f.LatestIssuedAt()) {
			return Record{}, false, fmt.Errorf("%w: bundle %s: %s", policy.ErrClockBehindFloor, clip(f.BundleID()), policy.FormatIssuedAt(f.LatestIssuedAt()))
		}
	}
	next, err := policy.NewFloor(top.BundleID(), top.Serial(), top.Digest(), at, at)
	if err != nil {
		return Record{}, false, err
	}
	rec := Record{Floor: next, Reset: note}
	if cur != nil && sameRecord(*cur, rec) {
		return rec, false, nil
	}
	return rec, true, nil
}

// higherFloor is the plane floor of the higher serial of c and top, refusing
// one serial with two digests.
func higherFloor(c, top policy.Floor) (policy.Floor, error) {
	switch {
	case !c.HasSerial():
	case !top.HasSerial() || c.Serial() > top.Serial():
		return c, nil
	case c.Serial() == top.Serial() && c.Digest() != top.Digest():
		return top, fmt.Errorf("%w: bundle %s serial %d", policy.ErrFloorSerialReused, clip(c.BundleID()), c.Serial())
	}
	return top, nil
}

// RestoreRoute raises the floors of live, a route floor directory, to those
// backup holds: per route id the higher serial with its digest. It refuses
// one serial with two digests with ErrRouteForked. An id backup holds no
// serial for is left out; one only live lists is left as it is.
func RestoreRoute(ctx context.Context, live, backup string, step Step) (Restored, error) {
	return restoreFloors(ctx, routeKind(), live, backup, step)
}

// CheckRoute refuses what RestoreRoute would refuse, writing nothing.
func CheckRoute(ctx context.Context, live, backup string) error {
	return checkFloors(ctx, routeKind(), live, backup)
}

func routeKind() floorKind[RouteFloor] {
	return floorKind[RouteFloor]{
		judge:       (*dir).judgeRouteContents,
		writeMarker: (*dir).writeRouteMarker,
		maxIDs:      MaxRouteIDs,
		tooMany:     ErrTooManyRouteIDs,
		read:        (*dir).readRouteFloor,
		hasSerial:   RouteFloor.HasSerial,
		restored:    higherSerial[RouteFloor],
		write:       func(d *dir, f RouteFloor) error { return f.writeTo(d) },
	}
}

// RestoreAuthority is RestoreRoute for an authority floor directory, which
// refuses one serial with two digests with ErrAuthorityForked.
func RestoreAuthority(ctx context.Context, live, backup string, step Step) (Restored, error) {
	return restoreFloors(ctx, authorityKind(), live, backup, step)
}

// CheckAuthority refuses what RestoreAuthority would refuse, writing nothing.
func CheckAuthority(ctx context.Context, live, backup string) error {
	return checkFloors(ctx, authorityKind(), live, backup)
}

func authorityKind() floorKind[AuthorityFloor] {
	return floorKind[AuthorityFloor]{
		judge:       (*dir).judgeAuthorityContents,
		writeMarker: (*dir).writeAuthorityMarker,
		maxIDs:      MaxRosterIDs,
		tooMany:     ErrTooManyRosterIDs,
		read:        (*dir).readAuthorityFloor,
		hasSerial:   AuthorityFloor.HasSerial,
		restored:    higherSerial[AuthorityFloor],
		write:       func(d *dir, f AuthorityFloor) error { return f.writeTo(d) },
	}
}

// RestorePause is RestoreRoute for the pause floor directory of tenant and
// project, which refuses one serial with two digests with ErrPauseForked and
// either directory kept for another tenant or project with ErrPauseScope.
func RestorePause(ctx context.Context, live, backup, tenant, project string, step Step) (Restored, error) {
	if err := checkPauseScope(tenant, project); err != nil {
		return Restored{}, err
	}
	return restoreFloors(ctx, pauseKind(tenant, project), live, backup, step)
}

// CheckPause refuses what RestorePause would refuse, writing nothing.
func CheckPause(ctx context.Context, live, backup, tenant, project string) error {
	if err := checkPauseScope(tenant, project); err != nil {
		return err
	}
	return checkFloors(ctx, pauseKind(tenant, project), live, backup)
}

func pauseKind(tenant, project string) floorKind[PauseFloor] {
	return floorKind[PauseFloor]{
		// read refuses a directory kept for another tenant or project.
		judge: func(d *dir, e []os.DirEntry) ([]string, error) {
			_, err := d.judgePauseContents(e)
			return []string{pauseFloorFile}, err
		},
		writeMarker: func(d *dir, _ []string, _ bool) error {
			body, err := encodePauseMarker(tenant, project)
			if err != nil {
				return err
			}
			return replaceIn(d.root, pauseMarkerFile, body, 0o600)
		},
		maxIDs:    1,
		tooMany:   ErrPauseInvalid,
		read:      func(d *dir, _ string) (PauseFloor, error) { return d.readPauseFloor(tenant, project) },
		hasSerial: PauseFloor.HasSerial,
		restored:  higherSerial[PauseFloor],
		write:     func(d *dir, f PauseFloor) error { return f.writeTo(d) },
	}
}

// higherSerial is the floor a restore writes from cur, nil when its file is
// gone, and bk: bk where it is higher, cur's own otherwise, refusing one
// serial with two digests; false leaves the file as it is.
func higherSerial[F serialFloor[F]](cur *F, bk F) (F, bool, error) {
	if err := bk.check(); err != nil {
		return bk, false, err
	}
	if cur == nil {
		return bk, true, nil
	}
	c, b := (*cur).at(), bk.at()
	if b.serial < c.serial {
		return *cur, false, nil
	}
	raise, err := bk.refusals().takes(c, b)
	return bk, raise, err
}

// floorKind is what restoreFloors needs of one kind of floor directory.
type floorKind[V any] struct {
	// listEmpty lists an id neither directory holds a serial for, with no
	// file, rather than leave it out.
	listEmpty bool
	// stampsLive restores an id only live lists, or one the backup lists
	// with no file, from its own floor, as restored(cur, *cur), rather than
	// leave it as it is.
	stampsLive  bool
	judge       func(*dir, []os.DirEntry) ([]string, error)
	writeMarker func(d *dir, ids []string, create bool) error
	maxIDs      int
	tooMany     Error
	// read is ErrNoFloor where the id's file is gone.
	read      func(*dir, string) (V, error)
	hasSerial func(V) bool
	restored  func(cur *V, bk V) (V, bool, error)
	write     func(*dir, V) error
}

// restoreFloors restores live from backup by k's rules, under live's
// exclusive lock.
func restoreFloors[V any](ctx context.Context, k floorKind[V], live, backup string, step Step) (out Restored, err error) {
	if step == nil {
		step = func(string) error { return nil }
	}
	ids, held, err := readBackup(k, backup)
	if err != nil {
		return Restored{}, fmt.Errorf("the backup's %s: %w", clip(backup), err)
	}
	if _, err := os.Lstat(live); errors.Is(err, fs.ErrNotExist) {
		return buildFloors(k, live, ids, held, step)
	}
	d, err := openDir(live)
	if err != nil {
		return Restored{}, err
	}
	defer func() { err = errors.Join(err, d.close()) }()
	unlock, err := d.lockToWrite(ctx)
	if err != nil {
		return Restored{}, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	entries, err := d.readDir()
	if err != nil {
		return Restored{}, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	listed, err := k.judge(d, entries)
	if err != nil {
		return Restored{}, err
	}
	liveOnly := liveOnlyIDs(k, listed, held)
	for _, id := range ids {
		if err := restoreOne(k, d, &listed, id, held[id], step, &out); err != nil {
			return out, err
		}
	}
	return out, stampLive(k, d, liveOnly, step, &out)
}

// liveOnlyIDs is every id of listed the backup does not list, where k stamps
// such an id, and none otherwise.
func liveOnlyIDs[V any](k floorKind[V], listed []string, held map[string]*V) []string {
	if !k.stampsLive {
		return nil
	}
	var out []string
	for _, id := range listed {
		if _, ok := held[id]; !ok {
			out = append(out, id)
		}
	}
	return out
}

// stampLive restores each of ids, which only live lists, from its own floor.
func stampLive[V any](k floorKind[V], d *dir, ids []string, step Step, out *Restored) error {
	for _, id := range ids {
		if err := stampOwn(k, d, id, step, out); err != nil {
			return err
		}
	}
	return nil
}

// stampOwn restores id from its own floor, where that holds a serial.
func stampOwn[V any](k floorKind[V], d *dir, id string, step Step, out *Restored) error {
	cur, err := k.read(d, id)
	switch {
	case errors.Is(err, ErrNoFloor):
		return nil
	case err != nil:
		return err
	case !k.hasSerial(cur):
		return nil
	}
	next, write, err := k.restored(&cur, cur)
	if err != nil {
		return err
	}
	return writeIf(k, d, id, next, write, step, out)
}

// checkFloors refuses what restoreFloors would refuse by k's rules, writing
// nothing: it runs the same judgement with every write left out.
func checkFloors[V any](ctx context.Context, k floorKind[V], live, backup string) error {
	k.write = func(*dir, V) error { return nil }
	k.writeMarker = func(*dir, []string, bool) error { return nil }
	if _, err := os.Lstat(live); !errors.Is(err, fs.ErrNotExist) {
		_, err := restoreFloors(ctx, k, live, backup, nil)
		return err
	}
	ids, held, err := readBackup(k, backup)
	if err != nil {
		return fmt.Errorf("the backup's %s: %w", clip(backup), err)
	}
	for _, id := range ids {
		if held[id] != nil && k.hasSerial(*held[id]) {
			if _, _, err := k.restored(nil, *held[id]); err != nil {
				return err
			}
		}
	}
	return nil
}

// restoreOne restores one id of live from bk, listing it first where the
// marker does not, as claim does.
func restoreOne[V any](k floorKind[V], d *dir, listed *[]string, id string, bk *V, step Step, out *Restored) error {
	var cur *V
	isListed := slices.Contains(*listed, id)
	if isListed {
		v, err := k.read(d, id)
		switch {
		case errors.Is(err, ErrNoFloor):
		case err != nil:
			return err
		default:
			cur = &v
		}
	}
	next, write, err := nextFloor(k, cur, bk)
	if err != nil {
		return err
	}
	if isListed || (!write && !k.listEmpty) {
		return writeIf(k, d, id, next, write, step, out)
	}
	if len(*listed) >= k.maxIDs {
		return fmt.Errorf("%w: %d listed", k.tooMany, len(*listed))
	}
	if err := step("list " + id); err != nil {
		return err
	}
	ids := append(slices.Clone(*listed), id)
	slices.Sort(ids)
	if err := k.writeMarker(d, ids, false); err != nil {
		return err
	}
	*listed = ids
	out.Listed = append(out.Listed, id)
	return writeIf(k, d, id, next, write, step, out)
}

// nextFloor is the floor a restore writes for one id from cur and bk, and
// false where it writes none: no serial on either side leaves the id as it
// is, and so does a backup with no file, except where k stamps live's own
// floor as it stamps an id only live lists.
func nextFloor[V any](k floorKind[V], cur, bk *V) (V, bool, error) {
	if bk == nil && k.stampsLive && cur != nil && k.hasSerial(*cur) {
		return k.restored(cur, *cur)
	}
	if bk == nil || (!k.hasSerial(*bk) && (cur == nil || !k.hasSerial(*cur))) {
		var none V
		return none, false, nil
	}
	return k.restored(cur, *bk)
}

func writeIf[V any](k floorKind[V], d *dir, id string, next V, write bool, step Step, out *Restored) error {
	if !write {
		return nil
	}
	if err := step("write " + id); err != nil {
		return err
	}
	if err := k.write(d, next); err != nil {
		return err
	}
	out.Written = append(out.Written, id)
	return nil
}

// readBackup reads every id backup lists and the floor it holds for each;
// an id whose file is gone maps to nil. An empty backup lists none.
func readBackup[V any](k floorKind[V], backup string) ([]string, map[string]*V, error) {
	if backup == "" {
		return nil, map[string]*V{}, nil
	}
	d, err := openDir(backup)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = d.close() }()
	entries, err := d.readDir()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	ids, err := k.judge(d, entries)
	if err != nil {
		return nil, nil, err
	}
	held := make(map[string]*V, len(ids))
	for _, id := range ids {
		v, err := k.read(d, id)
		switch {
		case errors.Is(err, ErrNoFloor):
			held[id] = nil
		case err != nil:
			return nil, nil, err
		default:
			held[id] = &v
		}
	}
	return ids, held, nil
}

// buildFloors makes live from the backup's floors under a temporary sibling
// name, which a stopped build leaves for the next to remove, and renames it
// into place, so the name holds either nothing or every floor.
func buildFloors[V any](k floorKind[V], live string, ids []string, held map[string]*V, step Step) (Restored, error) {
	var keep []string
	for _, id := range ids {
		if (held[id] != nil && k.hasSerial(*held[id])) || k.listEmpty {
			keep = append(keep, id)
		}
	}
	if len(keep) == 0 {
		return Restored{}, nil
	}
	tmp := filepath.Join(filepath.Dir(live), "."+filepath.Base(live)+".restoring")
	if err := step("build " + live); err != nil {
		return Restored{}, err
	}
	d, err := freshDir(tmp)
	if err != nil {
		return Restored{}, err
	}
	written, err := fillFloors(k, d, keep, held)
	if err = errors.Join(err, d.close()); err != nil {
		return Restored{}, err
	}
	out := Restored{Built: true, Listed: keep, Written: written}
	if err := step("rename " + live); err != nil {
		return Restored{}, err
	}
	if err := os.Rename(tmp, live); err != nil {
		return Restored{}, err
	}
	return out, syncParent(live)
}

// fillFloors writes into d, a directory just made, the marker listing keep
// and the floor of every id of keep held holds a serial for.
func fillFloors[V any](k floorKind[V], d *dir, keep []string, held map[string]*V) ([]string, error) {
	if err := k.writeMarker(d, keep, true); err != nil {
		return nil, err
	}
	var written []string
	for _, id := range keep {
		if held[id] == nil || !k.hasSerial(*held[id]) {
			continue
		}
		next, _, err := k.restored(nil, *held[id])
		if err == nil {
			err = k.write(d, next)
		}
		if err != nil {
			return written, err
		}
		written = append(written, id)
	}
	return written, nil
}

// freshDir removes what a stopped build left at tmp and makes it again,
// empty and owner-only.
func freshDir(tmp string) (*dir, error) {
	if err := os.RemoveAll(tmp); err != nil {
		return nil, err
	}
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotStateDir, err)
	}
	return openDir(tmp)
}

func syncParent(path string) error {
	f, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
