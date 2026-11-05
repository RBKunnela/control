package holdjournal_test

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/holdjournal"
)

const ledgerBinding = approval.Binding("bind-ledger")

// openLedger opens the ledger of a journal over dir, closed with the journal
// when the test ends.
func openLedger(t *testing.T, dir string, opts ...holdjournal.Option) (*holdjournal.Journal, *holdjournal.Ledger) {
	t.Helper()
	j := openJournal(t, dir, opts...)
	l, err := j.Ledger()
	if err != nil {
		t.Fatalf("opening the ledger: %v", err)
	}
	return j, l
}

// ledgerFiles is the names under the ledger directory, read from the
// directory itself.
func ledgerFiles(t *testing.T, dir string) []string {
	t.Helper()
	listed, err := os.ReadDir(filepath.Join(dir, "ledger"))
	if err != nil {
		t.Fatalf("reading the ledger directory: %v", err)
	}
	var names []string
	for _, e := range listed {
		names = append(names, e.Name())
	}
	return names
}

// TestSixteenSpendsOfOneApprovalSpendItOnce: the spend is one
// compare-and-swap, however many retries race for it, and a plane that comes
// back finds the mark.
func TestSixteenSpendsOfOneApprovalSpendItOnce(t *testing.T) {
	dir := newDir(t)
	j, l := openLedger(t, dir)
	var wg sync.WaitGroup
	results := make([]error, 16)
	for i := range results {
		wg.Go(func() {
			results[i] = l.Spend(context.Background(), ledgerBinding, "req-1", "appr-1", "duty-officer", base())
		})
	}
	wg.Wait()
	spent, refused := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			spent++
		case errors.Is(err, holdjournal.ErrSpent):
			refused++
		default:
			t.Errorf("a spend answered %v", err)
		}
	}
	if spent != 1 || refused != 15 {
		t.Fatalf("16 spends: %d spent, %d refused as spent; want 1 and 15", spent, refused)
	}
	if again, err := j.Ledger(); err != nil || again != l {
		t.Errorf("a second Ledger call answered %p, %v; want the same handle", again, err)
	}
	if _, err := holdjournal.Open(dir); !errors.Is(err, holdjournal.ErrLocked) {
		t.Errorf("a second plane over the directory: %v, want ErrLocked, so no second writer reaches the ledger", err)
	}
	expectSpentAfterRestart(t, dir, j, l)
}

// expectSpentAfterRestart closes j, holds its ledger l to refusing a spend
// once closed, and holds the ledger a plane coming back opens to the mark.
func expectSpentAfterRestart(t *testing.T, dir string, j *holdjournal.Journal, l *holdjournal.Ledger) {
	t.Helper()
	if err := j.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	if err := l.Spend(context.Background(), ledgerBinding, "req-1", "appr-1", "duty-officer", base()); !errors.Is(err, holdjournal.ErrClosed) {
		t.Errorf("a spend on a closed journal's ledger: %v, want ErrClosed", err)
	}
	_, back := openLedger(t, dir)
	if err := back.Spend(context.Background(), ledgerBinding, "req-1", "appr-1", "duty-officer", base().Add(time.Second)); !errors.Is(err, holdjournal.ErrSpent) {
		t.Errorf("the same spend after a restart: %v, want ErrSpent", err)
	}
	marks, err := back.Lookup(context.Background(), ledgerBinding, base())
	if err != nil || !maps.Equal(marks, map[string]holdjournal.Mark{"req-1": holdjournal.MarkConsumed}) {
		t.Errorf("Lookup after a restart = %v, %v; want req-1 consumed", marks, err)
	}
}

// TestASpendAndASettleRefuseEachOther: an approval the plane gave up on is
// never spent, and a spent one is never given up on; each call repeated is
// what it was.
func TestASpendAndASettleRefuseEachOther(t *testing.T) {
	dir := newDir(t)
	_, l := openLedger(t, dir)
	ctx := context.Background()
	if err := l.Settle(ctx, ledgerBinding, "req-1", "appr-1", base()); err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if err := l.Settle(ctx, ledgerBinding, "req-1", "appr-1", base()); err != nil {
		t.Errorf("a second Settle: %v, want nil, since the mark asked for is the mark on disk", err)
	}
	if err := l.Spend(ctx, ledgerBinding, "req-1", "appr-1", "duty-officer", base()); !errors.Is(err, holdjournal.ErrSettled) {
		t.Errorf("Spend after Settle: %v, want ErrSettled", err)
	}
	if err := l.Spend(ctx, ledgerBinding, "req-2", "appr-2", "duty-officer", base()); err != nil {
		t.Fatalf("Spend: %v", err)
	}
	if err := l.Settle(ctx, ledgerBinding, "req-2", "appr-2", base()); !errors.Is(err, holdjournal.ErrSpent) {
		t.Errorf("Settle after Spend: %v, want ErrSpent", err)
	}
	// The same request under another approval id is another mark.
	if err := l.Spend(ctx, ledgerBinding, "req-1", "appr-3", "duty-officer", base()); err != nil {
		t.Errorf("a spend of another approval of a settled request: %v, want nil", err)
	}
	if got := len(ledgerFiles(t, dir)); got != 4 {
		t.Errorf("the ledger directory holds %d names, want three marks and the marker", got)
	}
}

// TestLookupAnswersItsBindingAndASpendWins: a lookup reads the marks under
// its binding and no other, and a request with a settled approval and a
// spent one reads as spent, whichever mark the directory lists first.
func TestLookupAnswersItsBindingAndASpendWins(t *testing.T) {
	_, l := openLedger(t, newDir(t))
	ctx := context.Background()
	want := map[string]holdjournal.Mark{}
	for _, req := range []string{"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"} {
		if err := l.Settle(ctx, ledgerBinding, req, "settled-"+req, base()); err != nil {
			t.Fatalf("Settle %s: %v", req, err)
		}
		if err := l.Spend(ctx, ledgerBinding, req, "spent-"+req, "duty-officer", base()); err != nil {
			t.Fatalf("Spend %s: %v", req, err)
		}
		want[req] = holdjournal.MarkConsumed
	}
	if err := l.Settle(ctx, ledgerBinding, "only-settled", "appr-x", base()); err != nil {
		t.Fatalf("Settle: %v", err)
	}
	want["only-settled"] = holdjournal.MarkNotResumed
	if err := l.Spend(ctx, "bind-other", "elsewhere", "appr-y", "duty-officer", base()); err != nil {
		t.Fatalf("Spend under another binding: %v", err)
	}
	marks, err := l.Lookup(ctx, ledgerBinding, base())
	if err != nil || !maps.Equal(marks, want) {
		t.Errorf("Lookup = %v, %v; want %v", marks, err, want)
	}
	none, err := l.Lookup(ctx, "bind-nobody", base())
	if err != nil || none == nil || len(none) != 0 {
		t.Errorf("Lookup of a binding with no marks = %v, %v; want an empty map", none, err)
	}
}

// TestTheLedgerRefusesWhatNamesNoApproval: no call is read as "any approval
// will do", and each bound is held at its edge.
func TestTheLedgerRefusesWhatNamesNoApproval(t *testing.T) {
	dir := newDir(t)
	_, l := openLedger(t, dir)
	ctx := context.Background()
	at128, at129 := strings.Repeat("r", 128), strings.Repeat("r", 129)
	cases := map[string]struct {
		call func() error
		want error
	}{
		"a zero now":             {func() error { return l.Spend(ctx, ledgerBinding, "r", "a", "p", time.Time{}) }, holdjournal.ErrZeroTime},
		"a zero settle":          {func() error { return l.Settle(ctx, ledgerBinding, "r", "a", time.Time{}) }, holdjournal.ErrZeroTime},
		"no binding":             {func() error { return l.Spend(ctx, "", "r", "a", "p", base()) }, holdjournal.ErrLedgerEntry},
		"no request":             {func() error { return l.Spend(ctx, ledgerBinding, "", "a", "p", base()) }, holdjournal.ErrLedgerEntry},
		"no approval":            {func() error { return l.Settle(ctx, ledgerBinding, "r", "", base()) }, holdjournal.ErrLedgerEntry},
		"no proof":               {func() error { return l.Spend(ctx, ledgerBinding, "r", "a", "", base()) }, holdjournal.ErrLedgerEntry},
		"a proof over 512":       {func() error { return l.Spend(ctx, ledgerBinding, "r", "a", strings.Repeat("p", 513), base()) }, holdjournal.ErrLedgerEntry},
		"a request over 128":     {func() error { return l.Spend(ctx, ledgerBinding, at129, "a", "p", base()) }, holdjournal.ErrLedgerEntry},
		"a lookup of no binding": {func() error { _, err := l.Lookup(ctx, "", base()); return err }, holdjournal.ErrLedgerEntry},
		"a lookup at zero":       {func() error { _, err := l.Lookup(ctx, ledgerBinding, time.Time{}); return err }, holdjournal.ErrZeroTime},
		"a prune before zero":    {func() error { _, err := l.Prune(ctx, time.Time{}); return err }, holdjournal.ErrZeroTime},
	}
	for name, c := range cases {
		if err := c.call(); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if err := l.Spend(ctx, ledgerBinding, at128, "a", strings.Repeat("p", 512), base()); err != nil {
		t.Errorf("a request id and a proof at their bounds: %v", err)
	}
	if got := len(ledgerFiles(t, dir)); got != 2 {
		t.Errorf("the ledger holds %d names after the refusals, want one mark and the marker", got)
	}
}

// TestPruneRemovesOnlyWhatWasWrittenBefore: a mark written at the bound
// stays, one a nanosecond older goes, and the room it took is given back.
func TestPruneRemovesOnlyWhatWasWrittenBefore(t *testing.T) {
	_, l := openLedger(t, newDir(t), holdjournal.WithMaxEntries(2))
	ctx := context.Background()
	cut := base().Add(time.Minute)
	if err := l.Spend(ctx, ledgerBinding, "old", "a-old", "p", cut.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("Spend: %v", err)
	}
	if err := l.Settle(ctx, ledgerBinding, "edge", "a-edge", cut); err != nil {
		t.Fatalf("Settle: %v", err)
	}
	if err := l.Spend(ctx, ledgerBinding, "third", "a-third", "p", cut); !errors.Is(err, holdjournal.ErrTooManyEntries) {
		t.Fatalf("a third mark under a bound of two: %v, want ErrTooManyEntries", err)
	}
	if n, err := l.Prune(ctx, cut); n != 1 || err != nil {
		t.Fatalf("Prune = %d, %v; want 1, nil", n, err)
	}
	marks, err := l.Lookup(ctx, ledgerBinding, cut)
	if err != nil || !maps.Equal(marks, map[string]holdjournal.Mark{"edge": holdjournal.MarkNotResumed}) {
		t.Errorf("Lookup after the prune = %v, %v; want the mark at the bound alone", marks, err)
	}
	if err := l.Spend(ctx, ledgerBinding, "third", "a-third", "p", cut); err != nil {
		t.Errorf("a mark in the room the prune gave back: %v", err)
	}
	if n, err := l.Prune(ctx, cut); n != 0 || err != nil {
		t.Errorf("a second Prune = %d, %v; want 0, nil", n, err)
	}
}

// TestTheLedgerDirectoryIsTheJournals: a temporary file a crash left is swept
// when the ledger opens, a name the ledger did not write refuses it, a mark
// that disagrees with its name or will not decode refuses the lookup that
// reads it, and the journal lists its entries with the ledger beside them.
func TestTheLedgerDirectoryIsTheJournals(t *testing.T) {
	dir := newDir(t)
	j, l := openLedger(t, dir)
	record(t, j, "req-held")
	if err := l.Spend(context.Background(), ledgerBinding, "req-1", "appr-1", "p", base()); err != nil {
		t.Fatalf("Spend: %v", err)
	}
	listing, err := j.List(context.Background(), 10)
	if err != nil || len(listing.Held) != 1 || !listing.Complete {
		t.Fatalf("the journal beside its ledger lists %+v, %v; want its one entry, complete", listing, err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	torn := filepath.Join(dir, "ledger", "tmp.TORN.part")
	writeFile(t, torn, []byte("half a mark"))
	_, l = openLedger(t, dir)
	if _, err := os.Lstat(torn); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the torn temporary file is still there after the ledger opened: %v", err)
	}
	stray := filepath.Join(dir, "ledger", "consumed")
	writeFile(t, stray, []byte("a planted name"))
	if _, err := l.Lookup(context.Background(), ledgerBinding, base()); !errors.Is(err, holdjournal.ErrForeignFile) {
		t.Errorf("a lookup beside a foreign name: %v, want ErrForeignFile", err)
	}
	if err := os.Remove(stray); err != nil {
		t.Fatal(err)
	}
	var mark string
	for _, name := range ledgerFiles(t, dir) {
		if strings.HasSuffix(name, ".consumed") {
			mark = filepath.Join(dir, "ledger", name)
		}
	}
	raw := readFile(t, mark)
	raw[len(raw)-3] ^= 0x01
	writeFile(t, mark, raw)
	if _, err := l.Lookup(context.Background(), ledgerBinding, base()); !errors.Is(err, holdjournal.ErrCorrupt) {
		t.Errorf("a lookup of a mark whose checksum fails: %v, want ErrCorrupt", err)
	}
}

// TestAForeignNameOrAFileAtTheLedgerNameRefusesTheLedger: the ledger opens
// over nothing but what it wrote, and the journal reads a regular file named
// like the ledger as the foreign name it is.
func TestAForeignNameOrAFileAtTheLedgerNameRefusesTheLedger(t *testing.T) {
	dir := newDir(t)
	j, _ := openLedger(t, dir)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "ledger", "stray.json"), []byte("{}"))
	j = openJournal(t, dir)
	if _, err := j.Ledger(); !errors.Is(err, holdjournal.ErrForeignFile) {
		t.Errorf("a ledger holding a foreign name: %v, want ErrForeignFile", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	other := newDir(t)
	if err := openJournal(t, other).Close(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(other, "ledger"), []byte("not a directory"))
	if _, err := holdjournal.Open(other); !errors.Is(err, holdjournal.ErrForeignFile) {
		t.Errorf("a journal with a regular file at the ledger's name: %v, want ErrForeignFile", err)
	}
	reader, err := holdjournal.OpenReadOnly(dir)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer func() { _ = reader.Close() }()
	if _, err := reader.Ledger(); !errors.Is(err, holdjournal.ErrReadOnly) {
		t.Errorf("a read-only journal's ledger: %v, want ErrReadOnly", err)
	}
}
