package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/gateway"
)

// sweptBound is the approvals.max_records these cases run under.
const sweptBound = 2

// sweptTTL is the approval lifetime boundedPlane serves under.
const sweptTTL = 15 * time.Minute

// boundedPlane is holdingPlane with approvals.max_records at sweptBound.
func boundedPlane(t *testing.T, provider provider) (tree, *plane) {
	t.Helper()
	return boundedPlaneIn(t, newTree(t), provider, sweptTTL)
}

// boundedPlaneIn is boundedPlane over a tree the case has configured.
func boundedPlaneIn(t *testing.T, tr tree, provider provider, ttl time.Duration) (tree, *plane) {
	t.Helper()
	provider.configure(t, tr)
	writeBundle(t, filepath.Join(tr.dir, "holding.bundle"), holdingDocument)
	setEnv(t, "policy.bundle_file", filepath.Join(tr.dir, "holding.bundle"))
	writeStatement(t, filepath.Join(tr.dir, "policy.statement"), filepath.Join(tr.dir, "holding.bundle"), time.Now().Truncate(time.Second))
	setEnv(t, "mode", "ENFORCE")
	setEnv(t, "approvals.ttl", ttl.String())
	setEnv(t, "approvals.max_records", strconv.Itoa(sweptBound))
	return tr, tr.plane(t)
}

// transferOn is one material call on account: each account is a binding of
// its own, so each call is a hold of its own.
func transferOn(t *testing.T, p *plane, account, requestID string) gateway.Disposition {
	t.Helper()
	env := transferEnvelope(t, requestID)
	env.Resource.Id = account
	return p.pipeline.Admit(context.Background(), gateway.Admission{Envelope: env, Arguments: transferArgs})
}

// holdAndRun holds a call on account, has it approved and runs its retry.
func holdAndRun(t *testing.T, tr tree, provider provider, p *plane, account string) gateway.Disposition {
	t.Helper()
	held := transferOn(t, p, account, account+"-hold")
	if held.Action != core.AwaitApproval || held.Pending == nil {
		t.Fatalf("the call on %s is %v with %v, want a hold", account, held.Action, held.Decision.GetReasonCodes())
	}
	provider.answer(t, tr, p, held.Pending.ApprovalID, time.Now())
	run := transferOn(t, p, account, account+"-run")
	if run.Action != core.Execute {
		t.Fatalf("the approved retry on %s is %v with %v, want an execution", account, run.Action, run.Decision.GetReasonCodes())
	}
	closeExecution(t, p, run)
	return held
}

// TestASweptPlaneKeepsHoldingPastItsBound: a plane that sweeps its approval
// stores holds, resumes and spends three times approvals.max_records worth of
// approvals over time, under either store; every record and every mark it
// swept is counted. The control is the file store with no sweep, which
// refuses the hold past its bound.
func TestASweptPlaneKeepsHoldingPastItsBound(t *testing.T) {
	const ttl = sweptTTL
	for _, provider := range providers() {
		t.Run(provider.name, func(t *testing.T) {
			tr, p := boundedPlane(t, provider)
			for i := range 3 * sweptBound {
				holdAndRun(t, tr, provider, p, "acct-"+strconv.Itoa(i))
				if (i+1)%sweptBound == 0 {
					p.sweepStores(context.Background(), time.Now().Add(ttl+time.Minute))
				}
			}
			wantRecords := uint64(0)
			if provider.name == "file" {
				wantRecords = 3 * sweptBound
			}
			want := map[string]any{
				"records_forgotten": wantRecords, "records_failed": uint64(0),
				"marks_forgotten": uint64(3 * sweptBound), "marks_failed": uint64(0),
				"answers_forgotten": uint64(0), "answers_failed": uint64(0), "answers_refused": uint64(0),
			}
			if got := p.sweeps.counters(); !equalCounters(got, want) {
				t.Errorf("the sweeps counted %v, want %v", got, want)
			}
		})
	}
	t.Run("the control: no sweep", func(t *testing.T) {
		provider := fileProviderOf(t)
		tr, p := boundedPlane(t, provider)
		for i := range sweptBound {
			holdAndRun(t, tr, provider, p, "acct-"+strconv.Itoa(i))
		}
		if d := transferOn(t, p, "acct-past", "acct-past-hold"); d.Action == core.AwaitApproval {
			t.Errorf("a file store at its bound held one more call with no sweep, so the case above examines nothing")
		}
	})
}

func equalCounters(got, want map[string]any) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// TestASweepKeepsTheMarkOfALiveRecord: a sweep at the last instant a spent
// approval's record lives keeps the ledger's mark, so the next identical call
// is refused as already used and is not held anew. A sweep one lifetime past
// the record's expiry forgets both.
func TestASweepKeepsTheMarkOfALiveRecord(t *testing.T) {
	const ttl = sweptTTL
	provider := fileProviderOf(t)
	tr, p := boundedPlane(t, provider)
	held := holdAndRun(t, tr, provider, p, "acct-1")
	p.sweepStores(context.Background(), held.Pending.ExpiresAt.Add(-time.Nanosecond))
	used := transferOn(t, p, "acct-1", "acct-1-again")
	if used.Action != core.Block || !slices.Contains(used.Decision.GetReasonCodes(), "APPROVAL_ALREADY_USED") {
		t.Errorf("after a sweep while the record lives the retry is %v with %v, want APPROVAL_ALREADY_USED",
			used.Action, used.Decision.GetReasonCodes())
	}
	if got := p.sweeps.counters(); got["records_forgotten"] != uint64(0) || got["marks_forgotten"] != uint64(0) {
		t.Errorf("a sweep while the record lives forgot %v", got)
	}
	p.sweepStores(context.Background(), held.Pending.ExpiresAt.Add(ttl))
	if got := p.sweeps.counters(); got["records_forgotten"] != uint64(1) || got["marks_forgotten"] != uint64(1) {
		t.Errorf("a sweep a lifetime past the expiry forgot %v, want the record and the mark", got)
	}
}

// TestAFailedSweepIsCountedAndLoggedOncePerCause: a records directory moved
// away fails every sweep of it, each counted, and the cause is logged once;
// those passes leave the ledger's marks alone, and /healthz reports the
// count. Moved back, the next sweep runs whole, forgets the record and its
// mark, and says so once.
func TestAFailedSweepIsCountedAndLoggedOncePerCause(t *testing.T) {
	provider := fileProviderOf(t)
	tr, p := boundedPlane(t, provider)
	held := holdAndRun(t, tr, provider, p, "acct-1")
	past := held.Pending.ExpiresAt.Add(sweptTTL)
	var log bytes.Buffer
	p.logger = slog.New(slog.NewTextHandler(&log, nil))
	records := filepath.Join(tr.dir, recordsDir)
	if err := os.Rename(records, records+".moved"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		p.sweepStores(context.Background(), past)
	}
	got := p.sweeps.counters()
	if got["records_failed"] != uint64(3) || got["marks_failed"] != uint64(0) || got["marks_forgotten"] != uint64(0) {
		t.Errorf("three sweeps of a moved directory counted %v, want 3 records failures and the marks left alone", got)
	}
	if n := strings.Count(log.String(), "stopped early"); n != 1 {
		t.Errorf("three failures of one cause logged %d line(s), want 1:\n%s", n, log.String())
	}
	expectHealthSweepFailures(t, p, 3)
	if err := os.Rename(records+".moved", records); err != nil {
		t.Fatal(err)
	}
	p.sweepStores(context.Background(), past)
	p.sweepStores(context.Background(), past)
	expectRecovered(t, p, &log)
}

// expectHealthSweepFailures holds /healthz to reporting failed records
// sweeps.
func expectHealthSweepFailures(t *testing.T, p *plane, failed int) {
	t.Helper()
	_, body := ask(t, p, "/healthz")
	sweep, _ := approvalsAnswer(t, body)["sweep"].(map[string]any)
	if sweep["records_failed"] != float64(failed) {
		t.Errorf("/healthz reports the sweep as %v, want records_failed %d", sweep, failed)
	}
}

// expectRecovered holds a plane whose records directory came back after three
// failed sweeps to forgetting the record and its mark, keeping the failures
// counted, and saying once that it reads the store again.
func expectRecovered(t *testing.T, p *plane, log *bytes.Buffer) {
	t.Helper()
	got := p.sweeps.counters()
	if got["records_forgotten"] != uint64(1) || got["marks_forgotten"] != uint64(1) || got["records_failed"] != uint64(3) {
		t.Errorf("sweeps after the recovery counted %v, want the record and its mark forgotten and the 3 failures kept", got)
	}
	if n := strings.Count(log.String(), "reads the whole store again"); n != 1 {
		t.Errorf("a recovery logged %d line(s), want 1:\n%s", n, log.String())
	}
}

// TestTheSweepRunsAQuarterOfALifetimeApart: a quarter of the approval
// lifetime, and never less than a second.
func TestTheSweepRunsAQuarterOfALifetimeApart(t *testing.T) {
	for ttl, want := range map[time.Duration]time.Duration{
		time.Nanosecond: time.Second, 4 * time.Second: time.Second, 8 * time.Second: 2 * time.Second, 15 * time.Minute: 225 * time.Second,
	} {
		if got := recordSweepEvery(ttl); got != want {
			t.Errorf("recordSweepEvery(%s) = %s, want %s", ttl, got, want)
		}
	}
}

// TestARunningPlaneSweepsItsRecords: a plane serving under a one-second
// lifetime forgets the record of a hold that expired without any call
// reaching it, so the store's bound is never what refuses the next one.
func TestARunningPlaneSweepsItsRecords(t *testing.T) {
	provider := fileProviderOf(t)
	tr := newTree(t)
	collector := newAcceptingCollector(t)
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	setEnv(t, "export.endpoint", collector.url)
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "")
	_, p := boundedPlaneIn(t, tr, provider, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := p.startUpstreams(ctx); err != nil {
		t.Fatalf("startUpstreams: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- p.run(ctx, io.Discard, listenTCP, 0) }()
	if d := transferOn(t, p, "acct-1", "acct-1-hold"); d.Action != core.AwaitApproval {
		t.Fatalf("the call is %v, want a hold", d.Action)
	}
	records := filepath.Join(tr.dir, recordsDir)
	deadline := time.Now().Add(10 * time.Second)
	for len(recordsUnder(t, records)) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("a running plane kept the expired record: %v", recordsUnder(t, records))
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("run: %v", err)
	}
}
