package policystate_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/guardana/control/internal/policystate"
)

// stopList is a list's bytes, and part the floor's spelling of the SHA-256
// of its first n bytes.
var stopList = []byte("header\nstop one\nstop two\nlift\n")

func part(list []byte, n int64) string {
	sum := sha256.Sum256(list[:n])
	return "sha256:" + hex.EncodeToString(sum[:])
}

// stopsFloors is a stop list floor directory of t1/A raised to f; a serial
// of 0 leaves it with none.
func stopsFloors(t *testing.T, f policystate.StopsFloor) string {
	t.Helper()
	dir := stopsDir(t)
	if f.Serial > 0 {
		if _, err := policystate.RaiseStops(t.Context(), dir, f); err != nil {
			t.Fatalf("RaiseStops(%+v): %v", f, err)
		}
	}
	return dir
}

// TestRestoreStopsTakesTheHigherInItsOwnOrder: the higher serial; at one
// serial and head the longer part where a list shows both parts are one
// history; a floor with no serial below any.
func TestRestoreStopsTakesTheHigherInItsOwnOrder(t *testing.T) {
	short, long := stopsAt(5, d5, 16, part(stopList, 16)), stopsAt(5, d5, 25, part(stopList, 25))
	cases := []struct {
		name         string
		live, backup policystate.StopsFloor
		want         policystate.StopsFloor
	}{
		{"a higher live serial", stopsAt(6, d6, 3, d3), long, stopsAt(6, d6, 3, d3)},
		{"a higher backup serial", long, stopsAt(6, d6, 3, d3), stopsAt(6, d6, 3, d3)},
		{"a live floor with no serial", stopsAt(0, "", 0, ""), short, short},
		{"a longer live part", long, short, long},
		{"a longer backup part", short, long, long},
		{"one part", short, short, short},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			live := stopsFloors(t, c.live)
			if _, err := policystate.RestoreStops(t.Context(), live, stopsFloors(t, c.backup), "t1", "A", [][]byte{[]byte("other"), stopList}, nil); err != nil {
				t.Fatalf("RestoreStops: %v", err)
			}
			if got, err := policystate.ReadStops(live, "t1", "A"); err != nil || got != c.want {
				t.Fatalf("floor = %+v, %v; want %+v", got, err, c.want)
			}
		})
	}
}

// TestRestoreStopsRefusesTwoHistoriesBeforeWriting: two heads at one
// serial, two parts no list shows one history of, and two parts of one
// length with other bytes are refused, by the check and by the restore, the
// live floor as it was.
func TestRestoreStopsRefusesTwoHistoriesBeforeWriting(t *testing.T) {
	short, long := stopsAt(5, d5, 16, part(stopList, 16)), stopsAt(5, d5, 25, part(stopList, 25))
	forked := append([]byte("header\nstop one\nstop 2!\n"), stopList[24:]...)
	otherHead := append([]byte("HEADER\n"), stopList[7:]...)
	cases := []struct {
		name         string
		live, backup policystate.StopsFloor
		lists        [][]byte
		want         error
	}{
		{"two heads", short, stopsAt(5, d6, 16, part(stopList, 16)), [][]byte{stopList}, policystate.ErrStopsForked},
		{"no list", short, long, nil, policystate.ErrStopsRewritten},
		{"a list of the longer part only", short, stopsAt(5, d5, 25, part(otherHead, 25)), [][]byte{otherHead}, policystate.ErrStopsRewritten},
		{"a list too short", short, long, [][]byte{stopList[:24]}, policystate.ErrStopsRewritten},
		{"one length, other bytes", long, stopsAt(5, d5, 25, part(forked, 25)), [][]byte{stopList, forked}, policystate.ErrStopsRewritten},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			live, backup := stopsFloors(t, c.live), stopsFloors(t, c.backup)
			if err := policystate.CheckStops(t.Context(), live, backup, "t1", "A", c.lists); !errors.Is(err, c.want) {
				t.Fatalf("CheckStops: err = %v, want %v", err, c.want)
			}
			if _, err := policystate.RestoreStops(t.Context(), live, backup, "t1", "A", c.lists, nil); !errors.Is(err, c.want) {
				t.Fatalf("RestoreStops: err = %v, want %v", err, c.want)
			}
			if got, err := policystate.ReadStops(live, "t1", "A"); err != nil || got != c.live {
				t.Fatalf("floor = %+v, %v; want it as it was", got, err)
			}
		})
	}
}

// TestRestoreStopsBuildsAndRefusesAnotherScope: a lost floor directory is
// built from the backup's; a backup kept for another project is refused.
func TestRestoreStopsBuildsAndRefusesAnotherScope(t *testing.T) {
	backup := stopsFloors(t, stopsAt(5, d5, 16, part(stopList, 16)))
	live := newDir(t)
	if err := policystate.CheckStops(t.Context(), live, backup, "t1", "A", nil); err != nil {
		t.Fatalf("CheckStops over a lost directory: %v", err)
	}
	got, err := policystate.RestoreStops(t.Context(), live, backup, "t1", "A", nil, nil)
	if err != nil || !got.Built {
		t.Fatalf("RestoreStops = %+v, %v; want the directory built", got, err)
	}
	if f, err := policystate.ReadStops(live, "t1", "A"); err != nil || f.Serial != 5 {
		t.Fatalf("floor = %+v, %v", f, err)
	}
	if _, err := policystate.RestoreStops(t.Context(), stopsFloors(t, stopsAt(0, "", 0, "")), backup, "t1", "B", nil, nil); !errors.Is(err, policystate.ErrStopsScope) {
		t.Fatalf("another project: err = %v, want ErrStopsScope", err)
	}
}
