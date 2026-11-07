package recovery_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/recovery"
	"github.com/guardana/control/internal/runs"
)

// TestRestoreRefusesAConflictBeforeWriting: a conflict a later class finds,
// one run id held as two runs or one pause id as two pauses, refuses the
// restore before the floor it would stamp first is written.
func TestRestoreRefusesAConflictBeforeWriting(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(t *testing.T, p *plane, rec runs.Record)
		want  error
	}{
		{"one run id, two runs", func(t *testing.T, p *plane, rec runs.Record) {
			path := p.path("runs/" + rec.ID + ".run.json")
			var m map[string]json.RawMessage
			if err := json.Unmarshal(readOrFail(t, path), &m); err != nil {
				t.Fatal(err)
			}
			m["secret_sha256"] = json.RawMessage(`"` + strings.Repeat("0", 64) + `"`)
			out, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, out)
		}, runs.ErrTwoHistories},
		{"one pause id, two pauses", func(t *testing.T, p *plane, _ runs.Record) {
			if err := os.Remove(p.path("pause/pause.json")); err != nil {
				t.Fatal(err)
			}
			if err := pause.Init(t.Context(), p.path("pause/pause.json")); err != nil {
				t.Fatal(err)
			}
			e := pause.Entry{ID: "p1", Scope: pause.Scope{Kind: pause.ScopeProvider, Provider: "orders"}, CreatedAt: t0, Reason: "another"}
			if err := pause.Add(t.Context(), p.path("pause/pause.json"), e); err != nil {
				t.Fatal(err)
			}
		}, pause.ErrMergeConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, dir, rec := backedUp(t)
			p.raiseFloor(t, 2, d2, t0.Add(time.Hour))
			c.spoil(t, p, rec)
			before := tree(t, p.root)
			if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if after := tree(t, p.root); fmt.Sprint(after) != fmt.Sprint(before) {
				t.Fatal("a refused restore changed the plane's tree")
			}
		})
	}
}

// TestSignedRestoreRefusesALostRunsLayoutBeforeWriting: with runs.dir gone,
// a signed restore cannot carry the closes, and refuses before it raises
// any floor.
func TestSignedRestoreRefusesALostRunsLayoutBeforeWriting(t *testing.T) {
	p, dir, _ := signedPlane(t)
	for _, lost := range []string{"runs", "trust/floors"} {
		if err := os.RemoveAll(p.path(lost)); err != nil {
			t.Fatal(err)
		}
	}
	before := tree(t, p.root)
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); !errors.Is(err, runs.ErrNotRunsDir) {
		t.Fatalf("err = %v, want ErrNotRunsDir", err)
	}
	if after := tree(t, p.root); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatal("a refused restore changed the plane's tree")
	}
}
