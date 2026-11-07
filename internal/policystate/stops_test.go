package policystate_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardana/control/internal/policystate"
)

const (
	stopsEmptyT1A = `{"schema_version":"1.0","tenant":"t1","project":"A","serial":null,"digest":null,"length":null,"prefix":null}` + "\n"
	stopsAt5T1A   = `{"schema_version":"1.0","tenant":"t1","project":"A","serial":5,"digest":"` + d5 + `","length":40,"prefix":"` + d6 + `"}` + "\n"
)

func stopsDir(t testing.TB) string {
	t.Helper()
	dir := newDir(t)
	if err := policystate.InitStops(t.Context(), dir, "t1", "A"); err != nil {
		t.Fatalf("InitStops(%s): %v", dir, err)
	}
	return dir
}

func stopsAt(serial int64, digest string, length int64, prefix string) policystate.StopsFloor {
	return policystate.StopsFloor{Tenant: "t1", Project: "A", Serial: serial, Digest: digest, Length: length, Prefix: prefix}
}

// TestRaiseStopsHoldsTheAcceptedPartAtItsSerial: at the floor's serial and
// head a longer part is taken, and a shorter one or one of its length with
// other bytes is refused, the file left as it was.
func TestRaiseStopsHoldsTheAcceptedPartAtItsSerial(t *testing.T) {
	dir := stopsDir(t)
	file := filepath.Join(dir, "stops.floor.json")
	if got := readFile(t, file); got != stopsEmptyT1A {
		t.Fatalf("the floor file = %q, want %q", got, stopsEmptyT1A)
	}
	for _, what := range []string{"RaiseStops to 5", "RaiseStops at the floor, taken as it is"} {
		if f, err := policystate.RaiseStops(t.Context(), dir, stopsAt(5, d5, 40, d6)); err != nil || f.Length != 40 {
			t.Fatalf("%s = %+v, %v", what, f, err)
		}
		if got := readFile(t, file); got != stopsAt5T1A {
			t.Errorf("%s: the floor file = %q, want %q", what, got, stopsAt5T1A)
		}
	}
	expectStopsRefusals(t, dir)
	if f, err := policystate.RaiseStops(t.Context(), dir, stopsAt(5, d5, 41, d5)); err != nil || f.Length != 41 || f.Prefix != d5 {
		t.Errorf("RaiseStops to one byte more = %+v, %v", f, err)
	}
	if f, err := policystate.RaiseStops(t.Context(), dir, stopsAt(6, d6, 10, d6)); err != nil || f.Serial != 6 || f.Length != 10 {
		t.Errorf("RaiseStops to the next serial with a shorter list = %+v, %v; a new serial is a new list", f, err)
	}
}

// expectStopsRefusals expects each raise off the floor at serial 5 of 40
// bytes refused, the file left as it was.
func expectStopsRefusals(t *testing.T, dir string) {
	t.Helper()
	for _, c := range []struct {
		name string
		next policystate.StopsFloor
		want error
	}{
		{"one byte shorter", stopsAt(5, d5, 39, d6), policystate.ErrStopsRewritten},
		{"its length with other bytes", stopsAt(5, d5, 40, d5), policystate.ErrStopsRewritten},
		{"a longer part of another head", stopsAt(5, d6, 41, d6), policystate.ErrStopsForked},
		{"a lower serial", stopsAt(4, d5, 400, d6), policystate.ErrStopsBelowFloor},
	} {
		if _, err := policystate.RaiseStops(t.Context(), dir, c.next); !errors.Is(err, c.want) {
			t.Errorf("%s: RaiseStops = %v, want %v", c.name, err, c.want)
		}
	}
	if got := readFile(t, filepath.Join(dir, "stops.floor.json")); got != stopsAt5T1A {
		t.Errorf("a refused raise changed the floor file to %q", got)
	}
}

// TestAStopsFloorRefusesWhatNoListCarries: a raise to a length below one or
// a digest that is not one is refused, and a floor file setting only some
// of serial, digest, length and prefix does not read.
func TestAStopsFloorRefusesWhatNoListCarries(t *testing.T) {
	dir := stopsDir(t)
	for _, c := range []struct {
		name string
		next policystate.StopsFloor
	}{
		{"length 0", stopsAt(1, d5, 0, d6)},
		{"no prefix", stopsAt(1, d5, 1, "")},
		{"serial 0", stopsAt(0, d5, 1, d6)},
		{"no tenant", policystate.StopsFloor{Project: "A", Serial: 1, Digest: d5, Length: 1, Prefix: d6}},
	} {
		if _, err := policystate.RaiseStops(t.Context(), dir, c.next); !errors.Is(err, policystate.ErrStopsInvalid) {
			t.Errorf("%s: RaiseStops = %v, want ErrStopsInvalid", c.name, err)
		}
	}
	if f, err := policystate.RaiseStops(t.Context(), dir, stopsAt(1, d5, 1, d6)); err != nil || f.Length != 1 {
		t.Errorf("RaiseStops to length 1 = %+v, %v", f, err)
	}
	partial := `{"schema_version":"1.0","tenant":"t1","project":"A","serial":5,"digest":"` + d5 + `","length":null,"prefix":null}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "stops.floor.json"), []byte(partial), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := policystate.ReadStops(dir, "t1", "A"); !errors.Is(err, policystate.ErrMalformed) {
		t.Errorf("ReadStops of a floor without its part = %v, want ErrMalformed", err)
	}
}
