package gateway_test

import (
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/gateway"
)

const ledgerBinding = approval.Binding("sha256:ledger")

// TestMemoryLedgerSpendsOnce: many concurrent spends of one approval, and
// exactly one makes the mark.
func TestMemoryLedgerSpendsOnce(t *testing.T) {
	var l gateway.MemoryLedger
	var wg sync.WaitGroup
	results := make([]error, 32)
	resolutions := make([]gateway.Resolution, 32)
	for i := range results {
		wg.Go(func() {
			resolutions[i], results[i] = l.Spend(ctx(), ledgerBinding, "req-1", "a-1", "alice", base())
		})
	}
	wg.Wait()
	won, lost := 0, 0
	for i, err := range results {
		switch {
		case err == nil && resolutions[i] == gateway.ResolutionConsumed:
			won++
		case errors.Is(err, gateway.ErrApprovalConsumed) && resolutions[i] == gateway.ResolutionConsumed:
			lost++
		default:
			t.Errorf("Spend = %v, %v", resolutions[i], err)
		}
	}
	if won != 1 || lost != 31 {
		t.Errorf("%d spends won and %d lost; want 1 and 31", won, lost)
	}
}

// TestMemoryLedgerSpendAndSettleRefuseEachOther: a settled approval is never
// spent, a spent one is never settled, and each mark repeated is what it was.
func TestMemoryLedgerSpendAndSettleRefuseEachOther(t *testing.T) {
	var l gateway.MemoryLedger
	expect := func(what string, res gateway.Resolution, err error, wantRes gateway.Resolution, want error) {
		t.Helper()
		if res != wantRes || !errors.Is(err, want) || (want == nil) != (err == nil) {
			t.Errorf("%s = %v, %v; want %v, %v", what, res, err, wantRes, want)
		}
	}
	res, err := l.Settle(ctx(), ledgerBinding, "req-1", "a-1", base())
	expect("Settle", res, err, gateway.ResolutionNotResumed, nil)
	res, err = l.Settle(ctx(), ledgerBinding, "req-1", "a-1", base())
	expect("a second Settle", res, err, gateway.ResolutionNotResumed, nil)
	res, err = l.Spend(ctx(), ledgerBinding, "req-1", "a-1", "alice", base())
	expect("Spend after Settle", res, err, gateway.ResolutionNotResumed, gateway.ErrNoApproval)
	res, err = l.Spend(ctx(), ledgerBinding, "req-2", "a-2", "alice", base())
	expect("Spend", res, err, gateway.ResolutionConsumed, nil)
	res, err = l.Settle(ctx(), ledgerBinding, "req-2", "a-2", base())
	expect("Settle after Spend", res, err, gateway.ResolutionConsumed, gateway.ErrApprovalConsumed)
	// Another binding, request or approval is another mark.
	res, err = l.Spend(ctx(), "sha256:other", "req-1", "a-1", "alice", base())
	expect("Spend under another binding", res, err, gateway.ResolutionConsumed, nil)
	res, err = l.Spend(ctx(), ledgerBinding, "req-1", "a-3", "alice", base())
	expect("Spend of another approval of a settled request", res, err, gateway.ResolutionConsumed, nil)

	want := map[string]gateway.Resolution{"req-1": gateway.ResolutionConsumed, "req-2": gateway.ResolutionConsumed}
	settleThenSpend(t, &l, want)
	marks, err := l.Lookup(ctx(), ledgerBinding, base())
	if err != nil || !maps.Equal(marks, want) {
		t.Errorf("Lookup = %v, %v; want %v, a spend winning over a settle of the same request", marks, err, want)
	}
	if _, err := l.Settle(ctx(), ledgerBinding, "req-3", "a-4", base()); err != nil {
		t.Fatal(err)
	}
	if marks, _ := l.Lookup(ctx(), ledgerBinding, base()); marks["req-3"] != gateway.ResolutionNotResumed {
		t.Errorf("Lookup of a settled request = %v, want not resumed", marks["req-3"])
	}
	if none, err := l.Lookup(ctx(), "sha256:nobody", base()); err != nil || none == nil || len(none) != 0 {
		t.Errorf("Lookup of a binding with no marks = %v, %v; want an empty map", none, err)
	}
}

// TestMemoryLedgerRefusesWhatNamesNoApproval: nothing is read as "any
// approval will do", and a zero clock dates nothing.
func TestMemoryLedgerRefusesWhatNamesNoApproval(t *testing.T) {
	var l gateway.MemoryLedger
	cases := map[string]struct {
		call func() error
		want error
	}{
		"a spend at zero":        {func() error { _, err := l.Spend(ctx(), ledgerBinding, "r", "a", "p", time.Time{}); return err }, gateway.ErrZeroTime},
		"a settle at zero":       {func() error { _, err := l.Settle(ctx(), ledgerBinding, "r", "a", time.Time{}); return err }, gateway.ErrZeroTime},
		"a lookup at zero":       {func() error { _, err := l.Lookup(ctx(), ledgerBinding, time.Time{}); return err }, gateway.ErrZeroTime},
		"a prune before zero":    {func() error { _, err := l.Prune(ctx(), time.Time{}); return err }, gateway.ErrZeroTime},
		"no binding":             {func() error { _, err := l.Spend(ctx(), "", "r", "a", "p", base()); return err }, gateway.ErrLedgerEntry},
		"no request":             {func() error { _, err := l.Spend(ctx(), ledgerBinding, "", "a", "p", base()); return err }, gateway.ErrLedgerEntry},
		"no approval":            {func() error { _, err := l.Settle(ctx(), ledgerBinding, "r", "", base()); return err }, gateway.ErrLedgerEntry},
		"no proof":               {func() error { _, err := l.Spend(ctx(), ledgerBinding, "r", "a", "", base()); return err }, gateway.ErrLedgerEntry},
		"a lookup of no binding": {func() error { _, err := l.Lookup(ctx(), "", base()); return err }, gateway.ErrLedgerEntry},
	}
	for name, c := range cases {
		if err := c.call(); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if marks, err := l.Lookup(ctx(), ledgerBinding, base()); err != nil || len(marks) != 0 {
		t.Errorf("after the refusals the ledger holds %v, %v; want nothing", marks, err)
	}
}

// TestMemoryLedgerPrunesOnlyWhatWasWrittenBefore: a mark written at the
// bound stays and one a nanosecond older goes.
func TestMemoryLedgerPrunesOnlyWhatWasWrittenBefore(t *testing.T) {
	var l gateway.MemoryLedger
	cut := base().Add(time.Minute)
	if _, err := l.Spend(ctx(), ledgerBinding, "old", "a-old", "alice", cut.Add(-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Settle(ctx(), ledgerBinding, "edge", "a-edge", cut); err != nil {
		t.Fatal(err)
	}
	if n, err := l.Prune(ctx(), cut); n != 1 || err != nil {
		t.Fatalf("Prune = %d, %v; want 1, nil", n, err)
	}
	marks, err := l.Lookup(ctx(), ledgerBinding, cut)
	if err != nil || !maps.Equal(marks, map[string]gateway.Resolution{"edge": gateway.ResolutionNotResumed}) {
		t.Errorf("Lookup after the prune = %v, %v; want the mark at the bound alone", marks, err)
	}
}

// settleThenSpend settles eight requests under one approval each and spends
// them under another, adding each to want as spent: map order is random, so
// eight give a settle many chances to come last.
func settleThenSpend(t *testing.T, l *gateway.MemoryLedger, want map[string]gateway.Resolution) {
	t.Helper()
	for _, req := range []string{"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"} {
		if _, err := l.Settle(ctx(), ledgerBinding, req, "settled-"+req, base()); err != nil {
			t.Fatal(err)
		}
		if _, err := l.Spend(ctx(), ledgerBinding, req, "spent-"+req, "alice", base()); err != nil {
			t.Fatal(err)
		}
		want[req] = gateway.ResolutionConsumed
	}
}
