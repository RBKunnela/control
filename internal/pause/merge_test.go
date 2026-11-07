package pause_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/guardana/control/internal/pause"
)

// backupOf is the bytes of a pause file holding entries, as a backup keeps
// them.
func backupOf(t *testing.T, entries ...pause.Entry) []byte {
	t.Helper()
	raw, err := pause.Marshal(pause.Document{Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// withTwo is a pause file holding addTwo's two entries.
func withTwo(t *testing.T, path string) {
	t.Helper()
	if err := pause.Init(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	addTwo(t, path)
}

var orders = pause.Scope{Kind: pause.ScopeProvider, Provider: "orders"}

func TestMergeKeepsEveryPauseOfBoth(t *testing.T) {
	ctx := context.Background()
	path := emptyDir(t)
	withTwo(t, path)
	n, err := pause.Merge(ctx, path, backupOf(t, entry("p1", pause.Scope{Kind: "action", Action: "tool", Provider: "orders", Name: "refund"}), entry("p7", orders)))
	if err != nil || n != 1 {
		t.Fatalf("Merge = %d, %v; want one entry added", n, err)
	}
	if got := ids(t, path); fmt.Sprint(got) != "[p1 p2 p7]" {
		t.Fatalf("entries = %v, want [p1 p2 p7]", got)
	}
}

func TestMergeWritesAMissingFile(t *testing.T) {
	path := emptyDir(t)
	if n, err := pause.Merge(context.Background(), path, backupOf(t, entry("p7", orders))); err != nil || n != 1 {
		t.Fatalf("Merge = %d, %v", n, err)
	}
	if got := ids(t, path); fmt.Sprint(got) != "[p7]" {
		t.Fatalf("entries = %v", got)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
}

func TestMergeRefusesBeforeWriting(t *testing.T) {
	ctx := context.Background()
	full := make([]pause.Entry, 0, pause.MaxEntries)
	for i := range pause.MaxEntries - 1 {
		full = append(full, entry(fmt.Sprintf("b%02d", i), orders))
	}
	cases := []struct {
		name   string
		backup []byte
		want   error
	}{
		{"one id, two pauses", backupOf(t, entry("p2", orders)), pause.ErrMergeConflict},
		{"a union past MaxEntries", backupOf(t, full...), pause.ErrMalformed},
		{"a backup that is not a pause file", []byte(`{"schema_version":"2"`), pause.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := emptyDir(t)
			withTwo(t, path)
			before, err := os.ReadFile(path) //nolint:gosec // G304: the test's own file
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pause.Merge(ctx, path, c.backup); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			after, err := os.ReadFile(path) //nolint:gosec // G304: the test's own file
			if err != nil || string(after) != string(before) {
				t.Fatalf("a refused merge changed the file: %v", err)
			}
		})
	}
}

// TestMergeAtTheBound: a union of exactly MaxEntries is written.
func TestMergeAtTheBound(t *testing.T) {
	path := emptyDir(t)
	withTwo(t, path)
	full := make([]pause.Entry, 0, pause.MaxEntries-2)
	for i := range pause.MaxEntries - 2 {
		full = append(full, entry(fmt.Sprintf("b%02d", i), orders))
	}
	if n, err := pause.Merge(context.Background(), path, backupOf(t, full...)); err != nil || n != pause.MaxEntries-2 {
		t.Fatalf("Merge = %d, %v", n, err)
	}
}
