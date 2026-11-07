package policystate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// RestoreStops raises live, the stop list floor directory of tenant and
// project, to the floor backup holds, in the floor's own order: the higher
// serial; at one serial and head digest, the longer accepted part where one
// of lists, the bytes of a stop list, begins with both parts. It refuses one
// serial with two heads with ErrStopsForked, and two parts at one serial and
// head that no list shows one history with ErrStopsRewritten, before it
// writes, and either directory kept for another tenant or project with
// ErrStopsScope.
func RestoreStops(ctx context.Context, live, backup, tenant, project string, lists [][]byte, step Step) (Restored, error) {
	if err := checkStopsScope(tenant, project); err != nil {
		return Restored{}, err
	}
	return restoreFloors(ctx, stopsKind(tenant, project, lists), live, backup, step)
}

// CheckStops refuses what RestoreStops would refuse, writing nothing.
func CheckStops(ctx context.Context, live, backup, tenant, project string, lists [][]byte) error {
	if err := checkStopsScope(tenant, project); err != nil {
		return err
	}
	return checkFloors(ctx, stopsKind(tenant, project, lists), live, backup)
}

func stopsKind(tenant, project string, lists [][]byte) floorKind[StopsFloor] {
	return floorKind[StopsFloor]{
		judge: func(d *dir, e []os.DirEntry) ([]string, error) {
			scope, err := d.judgeStopsContents(e)
			if err == nil && scope != [2]string{tenant, project} {
				err = ErrStopsScope
			}
			return []string{stopsFloorFile}, err
		},
		writeMarker: func(d *dir, _ []string, _ bool) error {
			body, err := encodeStopsMarker(tenant, project)
			if err != nil {
				return err
			}
			return replaceIn(d.root, stopsMarkerFile, body, 0o600)
		},
		maxIDs:    1,
		tooMany:   ErrStopsInvalid,
		read:      func(d *dir, _ string) (StopsFloor, error) { return d.readStopsFloor(tenant, project) },
		hasSerial: StopsFloor.HasSerial,
		restored:  func(cur *StopsFloor, bk StopsFloor) (StopsFloor, bool, error) { return higherStops(cur, bk, lists) },
		write:     func(d *dir, f StopsFloor) error { return f.writeTo(d) },
	}
}

// higherStops is the stop list floor a restore writes from cur, nil when its
// file is gone, and bk, and false where it leaves cur as it is.
func higherStops(cur *StopsFloor, bk StopsFloor, lists [][]byte) (StopsFloor, bool, error) {
	if err := bk.check(); err != nil {
		return bk, false, err
	}
	if cur == nil {
		return bk, true, nil
	}
	c := *cur
	switch {
	case bk.Serial < c.Serial:
		return c, false, nil
	case bk.Serial > c.Serial:
		return bk, true, nil
	case bk.Digest != c.Digest:
		return c, false, fmt.Errorf("%w: serial %d", ErrStopsForked, c.Serial)
	case bk.Length == c.Length && bk.Prefix == c.Prefix:
		return c, false, nil
	}
	short, long := c, bk
	if bk.Length < c.Length {
		short, long = bk, c
	}
	if !oneHistory(short, long, lists) {
		return c, false, fmt.Errorf("%w: serial %d holds %d accepted bytes here and %d in the backup, and no stop list shows one history",
			ErrStopsRewritten, c.Serial, c.Length, bk.Length)
	}
	return long, long == bk, nil
}

// oneHistory reports whether one of lists begins with long's accepted part
// and, within it, with short's.
func oneHistory(short, long StopsFloor, lists [][]byte) bool {
	for _, l := range lists {
		if int64(len(l)) >= long.Length && prefixSum(l[:long.Length]) == long.Prefix && prefixSum(l[:short.Length]) == short.Prefix {
			return true
		}
	}
	return false
}

func prefixSum(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
