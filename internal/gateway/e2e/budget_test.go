package e2e_test

import (
	"path/filepath"
	"testing"

	"github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/internal/segmentlog"
	"github.com/guardana/control/internal/trailfile"
)

// trailBudget bounds the collector's segments in the case about its budget:
// twice the spool's budget, so a full spool drains into a log only once its
// sealed segments are pruned.
const (
	trailBudget  = 2 * spoolBudget
	trailSegment = trailBudget / 4
)

// startLogCollector is the collector over a directory of trail segments
// bound to the plane's tenant and project, as collect runs it.
func startLogCollector(t *testing.T, cfg trailfile.LogConfig, addr string) (*fileCollector, *trailfile.Log) {
	t.Helper()
	l, err := trailfile.OpenLog(cfg)
	if err != nil {
		t.Fatalf("trailfile.OpenLog: %v", err)
	}
	return serveCollector(t, l, l, addr), l
}

// TestAtTheTrailsBudgetAMaterialCallIsBlocked: a plane exporting to a
// collector whose segments reach their bound has its requests answered 503;
// its spool fills, and a material call is blocked with EVIDENCE_UNAVAILABLE
// without reaching the upstream. Nothing is pruned to make room, and the
// collector back without a prune leaves the call blocked. Once an operator
// prunes the sealed segments and the collector is back under the same bound,
// the spool drains and the same call runs.
func TestAtTheTrailsBudgetAMaterialCallIsBlocked(t *testing.T) {
	p := newPlane(t, options{
		kind: mcp.KindStatelessHTTP, mode: modeEnforce, rules: []string{allowReads, allowDeletes},
		spoolBytes: spoolBudget, closingReserve: closingBytes, noExport: true,
	})
	dir := filepath.Join(t.TempDir(), "trail")
	cfg := trailfile.LogConfig{Dir: dir, Tenant: "t1", Project: "p1", SegmentBytes: trailSegment, MaxBytes: trailBudget}
	c, l := startLogCollector(t, cfg, restartableAddr(t))
	exporter := exportTo(t, p, c.url())
	agent := p.connect(t, "agent-a")

	fillUntilBlocked(t, p, agent)
	if st := exporter.Stats(); st.RetriedServer == 0 {
		t.Errorf("the collector never answered 503 at its budget: %+v", st)
	}
	full := l.Manifest()
	if full.Retained > trailBudget || len(full.Segments) == 0 {
		t.Fatalf("the trail holds %d bytes in %d sealed segments, bound %d", full.Retained, len(full.Segments), trailBudget)
	}
	for _, s := range full.Segments {
		if s.State != segmentlog.StateSealed {
			t.Errorf("segment %d is %s: something was pruned without an operator", s.Seq, s.State)
		}
	}

	c.stop()
	c, l = startLogCollector(t, cfg, c.addr)
	retried := exporter.Stats().RetriedServer
	eventually(t, func() bool { return exporter.Stats().RetriedServer > retried+2 })
	blockedWith(t, call(t, agent, toolDelete, map[string]any{"path": "/before-prune"}), codeEvidenceUnavailable)
	if again := l.Manifest(); again.Retained != full.Retained {
		t.Errorf("the full trail changed with no prune: %d bytes, was %d", again.Retained, full.Retained)
	}

	c.stop()
	pruned := pruneThrough(t, dir, full.Segments[len(full.Segments)-1].Seq)
	if pruned >= full.Retained || pruned > trailSegment {
		t.Fatalf("the prune left %d bytes of %d", pruned, full.Retained)
	}
	startLogCollector(t, cfg, c.addr)
	eventually(t, func() bool {
		st, err := p.spool.Stats()
		return err == nil && st.Unacknowledged == 0
	})
	allowed(t, agent, toolDelete, map[string]any{"path": "/after-prune"})
}

// pruneThrough prunes the log in dir as an operator does, and returns the
// bytes it retains after.
func pruneThrough(t *testing.T, dir string, through int) int64 {
	t.Helper()
	pruner, err := trailfile.OpenLog(trailfile.LogConfig{Dir: dir, Tenant: "t1", Project: "p1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := pruner.Prune(through); err != nil {
		t.Fatal(err)
	}
	retained := pruner.Manifest().Retained
	if err := pruner.Close(); err != nil {
		t.Fatal(err)
	}
	return retained
}

// TestACollectorTakesNothingWithoutItsCredential: a plane sending another
// credential is answered 401 every time, the trail stays empty, and the
// plane's spool fills until a material call is blocked.
func TestACollectorTakesNothingWithoutItsCredential(t *testing.T) {
	p := newPlane(t, options{
		kind: mcp.KindStatelessHTTP, mode: modeEnforce, rules: []string{allowReads, allowDeletes},
		spoolBytes: spoolBudget, closingReserve: closingBytes, noExport: true,
	})
	dir := filepath.Join(t.TempDir(), "trail")
	c, l := startLogCollector(t, trailfile.LogConfig{Dir: dir, Tenant: "t1", Project: "p1", SegmentBytes: 1 << 20,
		MaxBytes: 2 << 20}, "127.0.0.1:0")
	exporter := exportWith(t, p, c.url(), "Bearer "+collectorToken[1:]+"x")
	agent := p.connect(t, "agent-a")

	fillUntilBlocked(t, p, agent)
	if st := exporter.Stats(); st.RetriedAuth == 0 || st.Acknowledged != 0 {
		t.Errorf("the exporter reports %+v, want 401s and nothing acknowledged", st)
	}
	if m := l.Manifest(); m.Retained != 0 {
		t.Errorf("a plane without the credential wrote %d bytes", m.Retained)
	}
}

// TestAnotherProjectsEvidenceIsQuarantinedByThePlane: a collector bound to
// another project answers the plane's records 400, the plane quarantines
// them, and the trail holds none of them.
func TestAnotherProjectsEvidenceIsQuarantinedByThePlane(t *testing.T) {
	p := newPlane(t, options{
		kind: mcp.KindStatelessHTTP, mode: modeEnforce, rules: []string{allowReads}, noExport: true,
	})
	dir := filepath.Join(t.TempDir(), "trail")
	c, l := startLogCollector(t, trailfile.LogConfig{Dir: dir, Tenant: "t1", Project: "p2", SegmentBytes: 1 << 20,
		MaxBytes: 2 << 20}, "127.0.0.1:0")
	exporter := exportTo(t, p, c.url())
	agent := p.connect(t, "agent-a")

	allowed(t, agent, toolRead, map[string]any{"path": "/r"})
	recorded := uint64(len(p.sink.events()))
	eventually(t, func() bool { return exporter.Stats().Quarantined == recorded })
	if m := l.Manifest(); m.Retained != 0 {
		t.Errorf("a collector of another project wrote %d bytes of this plane's", m.Retained)
	}
}
