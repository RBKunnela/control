package recovery_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stoplist"
	"github.com/guardana/control/internal/reaction/stopwrite"
	"github.com/guardana/control/internal/recovery"
	"github.com/guardana/control/internal/supervise"
)

const stopsBlock = `reaction:
  route: route/route.json
  public_key: route/route.pub
  floor_dir: routefloor
  stops: stops
`

var (
	routeKey  = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	liftKey   = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4c}, ed25519.SeedSize))
	stopRoute reaction.Route
)

// route is a v1alpha1 route of the refund example's procedure, whose rule
// stops a run for at most an hour, lifts signed by liftKey.
func route(t *testing.T) reaction.Route {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "refund-supervision", "refund.procedure.json"))
	if err != nil {
		t.Fatal(err)
	}
	proc, err := supervise.ReadProcedure(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc := `{"kind":"reaction-route/v1alpha1","route_id":"refunds","serial":1,"tenant_id":"acme","scope":"run","lift_public_key":"` +
		base64.StdEncoding.EncodeToString(liftKey.Public().(ed25519.PublicKey)) +
		`","rules":[{"procedure_id":"refund","version":"1","digest":"` + proc.Digest() +
		`","rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1","expires_seconds":3600}]}`
	r, err := reaction.ParseRoute([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// stopsPlane is a directory plane with a route and a stop list holding a
// stop of run-a and one of run-b, and a backup of it.
func stopsPlane(t *testing.T) (*plane, string, reaction.Header) {
	t.Helper()
	p := newPlane(t, directoryBlock+stopsBlock)
	// The route is held to four distinct keys, so the plane's policy and
	// freshness keys have to be keys.
	cfg := string(readOrFail(t, p.path("plane.yaml")))
	for i, old := range []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="} {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x60 + i)}, ed25519.SeedSize))
		cfg = strings.Replace(cfg, old, policykey.FormatPublic(key.Public().(ed25519.PublicKey)), 1)
	}
	writeFile(t, p.path("plane.yaml"), []byte(cfg))
	p.load(t)
	stopRoute = route(t)
	env, err := reaction.SignRoute(stopRoute, routeKey)
	if err != nil {
		t.Fatal(err)
	}
	file, err := reaction.MarshalRouteFile(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"route", "stops"} {
		if err := os.Mkdir(p.path(d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, p.path("route/route.json"), file)
	writeFile(t, p.path("route/route.pub"), []byte(policykey.FormatPublic(routeKey.Public().(ed25519.PublicKey))+"\n"))
	h, err := stopwrite.Init(t.Context(), p.path("stops"), stopRoute, t0)
	if err != nil {
		t.Fatal(err)
	}
	p.addStop(t, "f-a", "run-a")
	p.addStop(t, "f-b", "run-b")
	dir := filepath.Join(t.TempDir(), "backup")
	if _, err := recovery.Backup(t.Context(), p.cfg, dir, t0); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	return p, dir, h
}

func readOrFail(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a file under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (p *plane) addStop(t *testing.T, finding, run string) {
	t.Helper()
	clock := func() time.Time { return t0 }
	stopAt := func(now time.Time) (reaction.Stop, error) {
		rule := stopRoute.Rules()[0]
		return reaction.Stop{EntryID: reaction.EntryID(finding), TenantID: "acme", RunID: run, FindingID: finding,
			ProcedureID: rule.ProcedureID, ProcedureVersion: rule.ProcedureVersion, ProcedureDigest: rule.ProcedureDigest,
			RuleID: rule.RuleID, RuleVersion: rule.RuleVersion, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, nil
	}
	if _, _, _, err := stopwrite.AppendFinding(t.Context(), p.path("stops"), stopRoute, clock, stopAt); err != nil {
		t.Fatalf("a stop of %s: %v", run, err)
	}
}

// liftLine is a lift of run through line, signed for the list listID.
func liftLine(t *testing.T, listID, run string, through int64) reaction.LiftLine {
	t.Helper()
	env, err := reaction.SignLift(reaction.Lift{Version: "1.0", ListID: listID, RouteDigest: stopRoute.Digest(), RunID: run, ThroughLine: through}, liftKey)
	if err != nil {
		t.Fatal(err)
	}
	return reaction.LiftLine{RunID: run, ThroughLine: through, Envelope: env}
}

func (p *plane) stopList(t *testing.T) []byte {
	t.Helper()
	return readOrFail(t, p.path("stops/"+stoplist.FileName))
}

// stopped is the runs the plane's list stops, judged as a plane judges it.
func (p *plane) stopped(t *testing.T) (reaction.Header, []string) {
	t.Helper()
	l, err := reaction.Judge(stopRoute, reaction.Prefix{}, p.stopList(t), t0, 0)
	if err != nil {
		t.Fatalf("the restored list: %v", err)
	}
	var out []string
	for _, e := range l.Entries() {
		out = append(out, e.RunID)
	}
	slices.Sort(out)
	return l.Header(), out
}

// TestRestoreCarriesTheBackupsStopsIntoANewList is the acceptance path:
// after the backup a stop is added and another lifted, then the list is
// lost. The restore carries the backup's stops into a list of a new id, so
// the lifted stop is back, and the lift, bound to the old list, does not
// verify there. A second restore keeps the carried list.
func TestRestoreCarriesTheBackupsStopsIntoANewList(t *testing.T) {
	p, dir, old := stopsPlane(t)
	p.addStop(t, "f-c", "run-c")
	lift := liftLine(t, old.ListID, "run-a", 2)
	if _, err := stopwrite.AppendLift(t.Context(), p.path("stops"), stopRoute, lift, t0); err != nil {
		t.Fatalf("the lift before the loss: %v", err)
	}
	if err := os.Remove(p.path("stops/" + stoplist.FileName)); err != nil {
		t.Fatal(err)
	}
	report, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	h, runs := p.stopped(t)
	if h.ListID == old.ListID || fmt.Sprint(runs) != "[run-a run-b]" {
		t.Fatalf("restored list %s stops %v; want a new list stopping run-a and run-b", h.ListID, runs)
	}
	if !slices.ContainsFunc(report.Done, func(s string) bool { return bytes.Contains([]byte(s), []byte(h.ListID)) }) {
		t.Fatalf("Done = %q names no carried list", report.Done)
	}
	if _, err := stopwrite.AppendLift(t.Context(), p.path("stops"), stopRoute, lift, restoreAt); !errors.Is(err, stopwrite.ErrRefused) {
		t.Fatalf("the old lift in the new list: err = %v, want ErrRefused", err)
	}
	carried := tree(t, p.root)
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt.Add(time.Minute)); err != nil {
		t.Fatalf("a second restore over the carried list: %v", err)
	}
	if again := tree(t, p.root, "runs", "floors"); fmt.Sprint(again) != fmt.Sprint(withoutKeys(carried, "runs", "floors")) {
		t.Fatal("a second restore changed the carried list or the pause file")
	}
}

// withoutKeys is tr without the files under the paths named.
func withoutKeys(tr map[string]string, skip ...string) map[string]string {
	out := map[string]string{}
	for k, v := range tr {
		keep := true
		for _, s := range skip {
			if k == s || bytes.HasPrefix([]byte(k), []byte(s+"/")) {
				keep = false
			}
		}
		if keep {
			out[k] = v
		}
	}
	return out
}

// TestRestoreKeepsAListThatGrewFromTheBackups: a live list that begins with
// the backup's, here one holding a lift a carry would leave out, is left as
// it is.
func TestRestoreKeepsAListThatGrewFromTheBackups(t *testing.T) {
	p, _, h := stopsPlane(t)
	if _, err := stopwrite.AppendLift(t.Context(), p.path("stops"), stopRoute, liftLine(t, h.ListID, "run-a", 2), t0); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "lifted")
	if _, err := recovery.Backup(t.Context(), p.cfg, dir, t0); err != nil {
		t.Fatal(err)
	}
	p.addStop(t, "f-c", "run-c")
	before := p.stopList(t)
	if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !bytes.Equal(p.stopList(t), before) {
		t.Fatal("the restore rewrote a list that holds the backup's")
	}
}

// TestRestoreRefusesTwoStopHistories: a live list that neither begins with
// the backup's nor carries it, a fresh one or one cut and grown again, is
// refused before anything is written, the floor among it.
func TestRestoreRefusesTwoStopHistories(t *testing.T) {
	cases := map[string]func(t *testing.T, p *plane, backup []byte){
		"a fresh list": func(t *testing.T, p *plane, _ []byte) {
			if err := os.Remove(p.path("stops/" + stoplist.FileName)); err != nil {
				t.Fatal(err)
			}
			if _, err := stopwrite.Init(t.Context(), p.path("stops"), stopRoute, t0); err != nil {
				t.Fatal(err)
			}
		},
		"a list cut and grown again": func(t *testing.T, p *plane, backup []byte) {
			second := bytes.IndexByte(backup[bytes.IndexByte(backup, '\n')+1:], '\n') + bytes.IndexByte(backup, '\n') + 2
			writeFile(t, p.path("stops/"+stoplist.FileName), backup[:second])
			p.addStop(t, "f-c", "run-c")
		},
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			p, dir, _ := stopsPlane(t)
			p.raiseFloor(t, 1, d1, t0)
			p.raiseFloor(t, 2, d2, t0.Add(time.Hour))
			spoil(t, p, p.stopList(t))
			before := tree(t, p.root)
			if _, err := recovery.Restore(t.Context(), p.cfg, dir, restoreAt); !errors.Is(err, recovery.ErrStopHistories) {
				t.Fatalf("err = %v, want ErrStopHistories", err)
			}
			if after := tree(t, p.root); fmt.Sprint(after) != fmt.Sprint(before) {
				t.Fatal("a refused restore changed the plane's tree")
			}
		})
	}
}

// TestRestoreRefusesACarryWithoutItsRoute: a list to carry and a route that
// does not verify is refused before anything is written.
func TestRestoreRefusesACarryWithoutItsRoute(t *testing.T) {
	p, dir, _ := stopsPlane(t)
	if err := os.Remove(p.path("stops/" + stoplist.FileName)); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p.path("route/route.pub"), []byte(policykey.FormatPublic(liftKey.Public().(ed25519.PublicKey))+"\n"))
	before := tree(t, p.root)
	if _, err := recovery.Restore(context.Background(), p.cfg, dir, restoreAt); !errors.Is(err, reaction.ErrRouteKey) {
		t.Fatalf("a route under another key: err = %v, want ErrRouteKey", err)
	}
	if after := tree(t, p.root); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatal("a refused restore changed the plane's tree")
	}
}
