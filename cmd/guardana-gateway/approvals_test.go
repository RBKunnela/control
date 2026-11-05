package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/evidence"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/holdjournal"
	"github.com/guardana/control/internal/spool"
)

// The two directories the directory authority runs on inside a test tree. Neither is
// the spool's and neither is the other's.
const (
	recordsDir = "approvals"
	holdsDir   = "holds"
)

// The bundle digest the fixture holds are bound to, and the request the plane
// is made to lose.
const (
	fixtureBundleDigest = "sha256:" + "11111111111111111111111111111111111111111111111111111111111111ab"
	lostRequest         = "req-lost-1"
	lostApproval        = "apr-lost-1"
	lostEvent           = "evt-lost-1"
)

// fileProvider points the tree's configuration at a directory of records and a
// journal of the plane's own holds, each with its own directory.
func (tr tree) fileProvider(t *testing.T) (records, holds string) {
	t.Helper()
	records, holds = filepath.Join(tr.dir, recordsDir), filepath.Join(tr.dir, holdsDir)
	for _, dir := range []string{records, holds} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("making %s: %v", dir, err)
		}
	}
	setEnv(t, "approvals.authority", "directory")
	setEnv(t, "approvals.dir", records)
	setEnv(t, "approvals.hold_journal_dir", holds)
	return records, holds
}

// lostHold writes what a plane that died holding a call leaves behind: the
// record under the approvals directory and the entry in the journal, both
// naming one request. Nothing here goes through the pipeline, so the fixture
// cannot take its expected values from the code that would close it.
func lostHold(t *testing.T, records, holds string, expires time.Time) approval.Binding {
	t.Helper()
	return lostHoldOf(t, records, holds, expires, lostCall{lostApproval, lostRequest, lostEvent, readEnvelope()})
}

// lostCall is the ids and the envelope of one lost hold.
type lostCall struct {
	approval, request, event string
	envelope                 *controlv1.ActionEnvelope
}

// lostHoldOf is lostHold for the call lost names.
func lostHoldOf(t *testing.T, records, holds string, expires time.Time, lost lostCall) approval.Binding {
	t.Helper()
	digest, binding, err := approval.Bind(lost.envelope, []byte("{}"), fixtureBundleDigest)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	held := &controlv1.Approval{
		SchemaVersion:      "1.0",
		ApprovalId:         lost.approval,
		RequestId:          lost.request,
		ActionDigest:       string(digest),
		PolicyBundleDigest: fixtureBundleDigest,
		State:              controlv1.ApprovalState_APPROVAL_STATE_PENDING,
		RequestedAt:        timestamppb.New(expires.Add(-time.Minute)),
		ExpiresAt:          timestamppb.New(expires),
	}
	ctx := context.Background()
	store, err := approvals.OpenPlane(records)
	if err != nil {
		t.Fatalf("OpenPlane: %v", err)
	}
	err = store.Hold(ctx, approvals.Hold{
		Approval: held, Binding: binding,
		Envelope: lost.envelope, Decision: &controlv1.Decision{RequestId: lost.request},
	}, expires.Add(-time.Minute))
	if closeErr := store.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("holding the fixture request: %v", err)
	}
	journal, err := holdjournal.Open(holds)
	if err != nil {
		t.Fatalf("holdjournal.Open: %v", err)
	}
	err = journal.Record(ctx, holdjournal.Entry{
		SchemaVersion: "1.0",
		State:         holdjournal.StateHeld,
		IDs:           evidence.IDs{RequestID: lost.request, ProjectID: "orders", TenantID: "acme"},
		LastEventID:   lost.event,
		Binding:       binding,
		Approval:      held,
		Expires:       expires,
	})
	if closeErr := journal.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("recording the fixture entry: %v", err)
	}
	return binding
}

// records is every approval record under the directory, as an approver reads
// them back: the id, what the store can say about it, and the answer on it.
func recordsUnder(t *testing.T, dir string) []string {
	t.Helper()
	approver, err := approvals.OpenApprover(dir)
	if err != nil {
		t.Fatalf("OpenApprover: %v", err)
	}
	listing, err := approver.List(context.Background())
	if closeErr := approver.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("listing the records: %v", err)
	}
	out := make([]string, 0, len(listing.Entries))
	for _, e := range listing.Entries {
		out = append(out, fmt.Sprintf("%s %s %q", e.Record.ApprovalID,
			e.Record.Approval.GetState(), e.Record.Approval.GetApproverId()))
	}
	slices.Sort(out)
	return out
}

// ledgerMarks is every mark the ledger beside the journal under dir holds
// under binding, read by a plane's handle once no plane holds it.
func ledgerMarks(t *testing.T, dir string, binding approval.Binding) map[string]holdjournal.Mark {
	t.Helper()
	journal, err := holdjournal.Open(dir)
	if err != nil {
		t.Fatalf("holdjournal.Open: %v", err)
	}
	defer func() {
		if err := journal.Close(); err != nil {
			t.Errorf("closing the journal: %v", err)
		}
	}()
	ledger, err := journal.Ledger()
	if err != nil {
		t.Fatalf("the ledger: %v", err)
	}
	marks, err := ledger.Lookup(context.Background(), binding, time.Now())
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	return marks
}

// entriesUnder is every journal entry, from the handle that takes no lock.
func entriesUnder(t *testing.T, dir string) []string {
	t.Helper()
	journal, err := holdjournal.OpenReadOnly(dir)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	listing, err := journal.List(context.Background(), 64)
	if closeErr := journal.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("listing the journal: %v", err)
	}
	out := make([]string, 0, len(listing.Held))
	for _, e := range listing.Held {
		out = append(out, fmt.Sprintf("%s %s %s", e.IDs.RequestID, e.State, e.LastEventID))
	}
	out = append(out, fmt.Sprintf("interrupted %d unreadable %d complete %t",
		listing.Interrupted, listing.Unreadable, listing.Complete))
	slices.Sort(out)
	return out
}

// namesUnder is every file name under a directory. It is what a listing of
// records or of entries cannot show: a marker, a temporary file or anything
// else a command left behind appears here and nowhere else.
func namesUnder(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

// spoolStats reads the spool the way an operator does, from a handle opened
// and released again.
func spoolStats(t *testing.T, at spoolAt) spool.Stats {
	t.Helper()
	sp, err := spool.Open(spool.Options{
		Dir: at.dir, MaxBytes: at.maxBytes, SegmentBytes: at.segmentBytes, ClosingReserve: at.reserve,
	})
	if err != nil {
		t.Fatalf("spool.Open: %v", err)
	}
	stats, err := sp.Stats()
	if closeErr := sp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("spool.Stats: %v", err)
	}
	return stats
}

// spoolAt is where the spool is and the bounds it runs with, so a reading is
// taken the way the plane takes one.
type spoolAt struct {
	dir                             string
	maxBytes, segmentBytes, reserve int64
}

func spoolOptions(t *testing.T, tr tree) spoolAt {
	t.Helper()
	cfg := tr.load(t)
	return spoolAt{
		dir: cfg.Resolve(cfg.Evidence.Dir), maxBytes: cfg.Evidence.MaxBytes,
		segmentBytes: cfg.Evidence.SegmentBytes, reserve: cfg.Evidence.ClosingReserve,
	}
}

// TestDoctorWritesNoEventAndResolvesNoRecord is the rule `doctor` and `run`
// share a `build` for: a reconciliation writes evidence and resolves records,
// and a command documented as serving nothing does neither. The fixture is one
// lost hold, which the run below does close, so a `doctor` that reconciled
// would be seen here.
func TestDoctorWritesNoEventAndResolvesNoRecord(t *testing.T) {
	tr := newTree(t)
	records, holds := tr.fileProvider(t)
	lostHold(t, records, holds, time.Now().Add(10*time.Minute))
	options := spoolOptions(t, tr)

	beforeSpool, beforeRecords, beforeEntries := spoolStats(t, options), recordsUnder(t, records), entriesUnder(t, holds)
	beforeNames, beforeHoldNames := namesUnder(t, records), namesUnder(t, holds)
	var out bytes.Buffer
	doctor(context.Background(), tr.config, &out, &out)
	if !strings.Contains(out.String(), "ok      approvals") {
		t.Fatalf("the approvals check did not pass, so nothing about it was examined:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "would close 1 lost hold(s)") {
		t.Errorf("doctor did not report the lost hold it would close:\n%s", out.String())
	}

	if got := spoolStats(t, options); got != beforeSpool {
		t.Errorf("the spool changed across a doctor run:\nbefore %+v\nafter  %+v", beforeSpool, got)
	}
	if got := recordsUnder(t, records); !slices.Equal(got, beforeRecords) {
		t.Errorf("the approvals listing changed across a doctor run:\nbefore %v\nafter  %v", beforeRecords, got)
	}
	if got := entriesUnder(t, holds); !slices.Equal(got, beforeEntries) {
		t.Errorf("the hold journal changed across a doctor run:\nbefore %v\nafter  %v", beforeEntries, got)
	}
	// A listing shows records and entries. A file a command wrote beside them
	// shows in neither, so the names are compared too.
	if got := namesUnder(t, records); !slices.Equal(got, beforeNames) {
		t.Errorf("the approvals directory holds other files after a doctor run:\nbefore %v\nafter  %v", beforeNames, got)
	}
	if got := namesUnder(t, holds); !slices.Equal(got, beforeHoldNames) {
		t.Errorf("the journal directory holds other files after a doctor run:\nbefore %v\nafter  %v", beforeHoldNames, got)
	}
}

// TestDoctorLeavesAnUnusedDirectoryEmpty is the case a listing cannot see: on
// directories no plane has opened, `doctor` has nothing to report and must
// still write nothing, not even the marker that would make either directory a
// store of its own.
func TestDoctorLeavesAnUnusedDirectoryEmpty(t *testing.T) {
	tr := newTree(t)
	records, holds := tr.fileProvider(t)
	var out bytes.Buffer
	doctor(context.Background(), tr.config, &out, &out)
	if !strings.Contains(out.String(), "ok      approvals") {
		t.Fatalf("the approvals check did not pass on two empty directories:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "no plane has written a hold here yet") {
		t.Errorf("doctor did not say the journal is unused:\n%s", out.String())
	}
	for _, dir := range []string{records, holds} {
		if names := namesUnder(t, dir); len(names) != 0 {
			t.Errorf("doctor wrote %v into %s, which no plane has opened", names, dir)
		}
	}
}

// TestDoctorTakesNoLockOnTheApprovalsDirectory: a command that serves nothing
// holds nothing. A plane's lock on that directory is what an approver reads as
// "something is running that will consume my answer", so `doctor` must neither
// wait for that lock nor take it.
func TestDoctorTakesNoLockOnTheApprovalsDirectory(t *testing.T) {
	tr := newTree(t)
	records, holds := tr.fileProvider(t)
	lostHold(t, records, holds, time.Now().Add(10*time.Minute))

	// The lock is held for the whole run, as a serving plane holds it.
	held, err := approvals.OpenPlane(records)
	if err != nil {
		t.Fatalf("OpenPlane: %v", err)
	}
	t.Cleanup(func() {
		if err := held.Close(); err != nil {
			t.Errorf("closing the held store: %v", err)
		}
	})

	done := make(chan string, 1)
	go func() {
		var out bytes.Buffer
		doctor(context.Background(), tr.config, &out, &out)
		done <- out.String()
	}()
	select {
	case out := <-done:
		// Both checks have to pass: the one that reports the directory, and
		// the one that builds every seam. A command that took the lock here
		// would be refused by the plane that holds it, and a command that
		// waited for it would never reach the deadline below.
		for _, check := range []string{"ok      approvals", "ok      seams"} {
			if !strings.Contains(out, check) {
				t.Errorf("%q is missing beside a plane holding the directory:\n%s", check, out)
			}
		}
	case <-time.After(15 * time.Second):
		t.Fatal("doctor did not finish: it waited for the lock a serving plane holds")
	}
}

// TestDoctorTakesNoLockOnTheHoldJournal: the journal's lock is exclusive to
// the plane that serves, so a command that only inspects must neither wait for
// it nor take it. A doctor that opened the journal for writing would be
// refused here, and one that queued for the lock would never finish.
func TestDoctorTakesNoLockOnTheHoldJournal(t *testing.T) {
	tr := newTree(t)
	records, holds := tr.fileProvider(t)
	lostHold(t, records, holds, time.Now().Add(10*time.Minute))

	// The lock is held for the whole run, as a serving plane holds it.
	held, err := holdjournal.Open(holds)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := held.Close(); err != nil {
			t.Errorf("closing the held journal: %v", err)
		}
	})

	done := make(chan string, 1)
	go func() {
		var out bytes.Buffer
		doctor(context.Background(), tr.config, &out, &out)
		done <- out.String()
	}()
	select {
	case out := <-done:
		for _, check := range []string{"ok      approvals", "ok      seams"} {
			if !strings.Contains(out, check) {
				t.Errorf("%q is missing beside a plane holding the journal:\n%s", check, out)
			}
		}
	case <-time.After(15 * time.Second):
		t.Fatal("doctor did not finish: it waited for the lock a serving plane holds")
	}
}

// TestDoctorIsNotReadAsAPlaneWaitingToConsume watches the flag an approver
// acts on while doctor runs. The reading is sampled, so it cannot prove the
// absence of a window; it does catch a lock held for any part of a run, which
// is what building the serving plane's stores here would take.
func TestDoctorIsNotReadAsAPlaneWaitingToConsume(t *testing.T) {
	tr := newTree(t)
	records, holds := tr.fileProvider(t)
	lostHold(t, records, holds, time.Now().Add(10*time.Minute))
	if probePlane(t, records) {
		t.Fatal("a plane held the directory before the test started anything")
	}

	done := make(chan struct{})
	go func() {
		var out bytes.Buffer
		doctor(context.Background(), tr.config, &out, &out)
		close(done)
	}()
	reads := 0
	for {
		select {
		case <-done:
			if reads == 0 {
				t.Fatal("the flag was never read while doctor ran, so nothing was examined")
			}
			return
		default:
		}
		reads++
		if probePlane(t, records) {
			t.Fatalf("an approver read a plane holding the directory while doctor ran, after %d reading(s)", reads)
		}
	}
}

// probePlane is the reading an approver takes before filing an answer: whether
// a plane holds the directory and would consume it.
func probePlane(t *testing.T, dir string) bool {
	t.Helper()
	approver, err := approvals.OpenApprover(dir)
	if err != nil {
		t.Fatalf("OpenApprover: %v", err)
	}
	listing, err := approver.List(context.Background())
	if closeErr := approver.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("listing the records: %v", err)
	}
	return listing.PlaneRunning
}

// TestRunClosesTheHoldsItLostAndPrunesAfterwards is the other side of the same
// rule, and what gives the case above its teeth: `run` reconciles at start,
// the lost hold's record is resolved not-resumed rather than spent, and the
// expired records are forgotten only after that.
func TestRunClosesTheHoldsItLostAndPrunesAfterwards(t *testing.T) {
	tr := newTree(t)
	records, holds := tr.fileProvider(t)
	binding := lostHold(t, records, holds, time.Now().Add(10*time.Minute))
	setEnv(t, "upstreams.0.endpoint", upstream(t))
	setEnv(t, "listener.address", "127.0.0.1:0")
	setEnv(t, "health.address", "127.0.0.1:0")
	options := spoolOptions(t, tr)
	before := spoolStats(t, options)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() { done <- serve(ctx, tr.config, "", &stdout, &stderr) }()
	line := waitFor(t, &stdout, "lost holds:")
	if !strings.Contains(line, "1 closed") || !strings.Contains(line, "the pass read every entry") {
		t.Errorf("the reconciliation reported %q", line)
	}
	if pruned := waitFor(t, &stdout, "expired approval records:"); !strings.Contains(pruned, "0 forgotten") {
		t.Errorf("the sweep reported %q, and the fixture record has not expired", pruned)
	}
	cancel()
	if status := <-done; status != exitOK {
		t.Fatalf("run answered %d; stderr: %s", status, stderr.String())
	}

	if got := recordsUnder(t, records); len(got) != 0 {
		t.Errorf("the records after the reconciliation are %v; a settled hold leaves the directory", got)
	}
	if marks := ledgerMarks(t, holds, binding); !maps.Equal(marks, map[string]holdjournal.Mark{lostRequest: holdjournal.MarkNotResumed}) {
		t.Errorf("the ledger after the reconciliation marks %v; a lost hold is settled not resumed and never spent", marks)
	}
	if got := entriesUnder(t, holds); !slices.Equal(got, []string{"interrupted 0 unreadable 0 complete true"}) {
		t.Errorf("the journal after the reconciliation is %v; a closed trail's entry is forgotten", got)
	}
	if got := spoolStats(t, options); got.Bytes <= before.Bytes {
		t.Errorf("the reconciliation wrote no evidence: %+v after %+v", got, before)
	}
}

// TestTheConfigurationBoundsAreTheStoresOwn: the defaults in the field table
// and the defaults the stores were built with are one pair of numbers, so an
// operator who reads the reference page reads what the directory enforces.
func TestTheConfigurationBoundsAreTheStoresOwn(t *testing.T) {
	cfg := newTree(t).load(t)
	if cfg.Approvals.MaxRecords != approvals.DefaultMaxRecords {
		t.Errorf("approvals.max_records defaults to %d, and the store's own default is %d",
			cfg.Approvals.MaxRecords, approvals.DefaultMaxRecords)
	}
	if cfg.Approvals.MaxRecordBytes != approvals.DefaultMaxRecordBytes {
		t.Errorf("approvals.max_record_bytes defaults to %d, and the store's own default is %d",
			cfg.Approvals.MaxRecordBytes, approvals.DefaultMaxRecordBytes)
	}
}

// refusalRig is one approvals directory holding the lost request, with a
// plane, an approver and the seam over the plane, all read at one clock.
type refusalRig struct {
	store    *approvals.Plane
	approver *approvals.Approver
	seam     *approvalStore
	records  string
	binding  approval.Binding
	digest   string
	now      time.Time
}

func openRefusalRig(t *testing.T) refusalRig {
	t.Helper()
	tr := newTree(t)
	records, holds := tr.fileProvider(t)
	binding := lostHold(t, records, holds, time.Now().Add(10*time.Minute))
	digest, _, err := approval.Bind(readEnvelope(), []byte("{}"), fixtureBundleDigest)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	store, err := approvals.OpenPlane(records)
	if err != nil {
		t.Fatalf("OpenPlane: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("closing the store: %v", err)
		}
	})
	approver, err := approvals.OpenApprover(records)
	if err != nil {
		t.Fatalf("OpenApprover: %v", err)
	}
	t.Cleanup(func() {
		if err := approver.Close(); err != nil {
			t.Errorf("closing the approver: %v", err)
		}
	})
	return refusalRig{
		store: store, approver: approver, seam: &approvalStore{plane: store},
		records: records, binding: binding, digest: string(digest), now: time.Now(),
	}
}

// held is the hold of request req-<id> under approval apr-<id>.
func (r refusalRig) held(id string, multiUse bool) gateway.Held {
	return gateway.Held{
		Approval: &controlv1.Approval{
			SchemaVersion:      "1.0",
			ApprovalId:         "apr-" + id,
			RequestId:          "req-" + id,
			ActionDigest:       r.digest,
			PolicyBundleDigest: fixtureBundleDigest,
			State:              controlv1.ApprovalState_APPROVAL_STATE_PENDING,
			RequestedAt:        timestamppb.New(r.now),
			ExpiresAt:          timestamppb.New(r.now.Add(10 * time.Minute)),
			MultiUse:           multiUse,
		},
		Binding:  r.binding,
		Envelope: readEnvelope(),
		Decision: &controlv1.Decision{RequestId: "req-" + id},
	}
}

func (r refusalRig) hold(t *testing.T, id string, multiUse bool) {
	t.Helper()
	if err := r.seam.Hold(context.Background(), r.held(id, multiUse), r.now); err != nil {
		t.Fatalf("holding req-%s: %v", id, err)
	}
}

func (r refusalRig) answer(id string, state controlv1.ApprovalState, approverID string) error {
	_, err := r.approver.Answer(context.Background(), "apr-"+id, state, approverID, "", r.now)
	return err
}

func (r refusalRig) answered(t *testing.T, id string, state controlv1.ApprovalState, approverID string) {
	t.Helper()
	if err := r.answer(id, state, approverID); err != nil {
		t.Fatalf("answering apr-%s: %v", id, err)
	}
}

const (
	approvedState = controlv1.ApprovalState_APPROVAL_STATE_APPROVED
	rejectedState = controlv1.ApprovalState_APPROVAL_STATE_REJECTED
	pendingState  = controlv1.ApprovalState_APPROVAL_STATE_PENDING
)

// storeRefusals makes each refusal storeErrors translates with a real store.
// The seam carries no answer, so the approver's two refusals are handed to the
// translation directly.
var storeRefusals = []struct {
	store   approvals.Error
	want    gateway.Error
	refusal func(*testing.T, refusalRig) error
}{
	{approvals.ErrNoApproval, gateway.ErrNoApproval, func(_ *testing.T, r refusalRig) error {
		_, err := r.seam.Find(context.Background(), r.binding, r.now.Add(time.Hour))
		return err
	}},
	{approvals.ErrZeroTime, gateway.ErrZeroTime, func(_ *testing.T, r refusalRig) error {
		return r.seam.Hold(context.Background(), gateway.Held{}, time.Time{})
	}},
	{approvals.ErrInvalidHold, gateway.ErrInvalidHold, func(_ *testing.T, r refusalRig) error {
		return r.seam.Hold(context.Background(), gateway.Held{}, r.now)
	}},
	{approvals.ErrAlreadyHeld, gateway.ErrAlreadyHeld, func(t *testing.T, r refusalRig) error {
		r.hold(t, "twice", false)
		again := r.held("twice", false)
		again.Approval.ApprovalId = "apr-twice-again"
		return r.seam.Hold(context.Background(), again, r.now)
	}},
	{approvals.ErrApprovalAnswered, gateway.ErrApprovalAnswered, func(t *testing.T, r refusalRig) error {
		r.hold(t, "answered", false)
		r.answered(t, "answered", approvedState, "approver-1")
		return storeError(r.answer("answered", approvedState, "approver-2"))
	}},
	{approvals.ErrApprovalAnswer, gateway.ErrApprovalAnswer, func(t *testing.T, r refusalRig) error {
		r.hold(t, "pending", false)
		return storeError(r.answer("pending", pendingState, "approver-1"))
	}},
}

// TestAStoreRefusalIsTheGatewaysOwnVocabulary: the directory's refusals reach
// the pipeline as the sentinels it names, and the store's own words travel
// beside them so an operator reads which record refused. Every entry of the
// translation has a case.
func TestAStoreRefusalIsTheGatewaysOwnVocabulary(t *testing.T) {
	r := openRefusalRig(t)
	ctx := context.Background()

	// Nobody has approved the held request, so it reads as pending, and a
	// read writes nothing.
	found, err := r.seam.Find(ctx, r.binding, r.now)
	if err != nil || len(found) != 1 || found[0].Approval.GetState() != pendingState {
		t.Errorf("reading the unanswered record answered %v, %v; want it pending", found, err)
	}
	if got := recordsUnder(t, r.records); !slices.Equal(got, []string{
		lostApproval + ` APPROVAL_STATE_PENDING ""`,
	}) {
		t.Errorf("a read changed the record: %v", got)
	}

	covered := map[approvals.Error]bool{}
	for _, c := range storeRefusals {
		t.Run(string(c.want), func(t *testing.T) {
			err := c.refusal(t, r)
			if !errors.Is(err, c.want) {
				t.Errorf("answered %v, want %v", err, c.want)
			}
			if !errors.Is(err, c.store) {
				t.Errorf("answered %v, and the store's own %v did not travel beside it", err, c.store)
			}
		})
		covered[c.store] = true
	}
	for from := range storeErrors {
		if !covered[from] {
			t.Errorf("no case makes the store refuse with %v", from)
		}
	}
}

// TestALedgerRefusalIsTheGatewaysOwnVocabulary: the ledger's refusals reach
// the pipeline as the sentinels it names, beside the resolution the gateway's
// Ledger documents for each, and the ledger's own words travel with them.
// Every entry of the translation has a case.
func TestALedgerRefusalIsTheGatewaysOwnVocabulary(t *testing.T) {
	journal, err := holdjournal.Open(t.TempDir())
	if err != nil {
		t.Fatalf("holdjournal.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Errorf("closing the journal: %v", err)
		}
	})
	ledger, err := journal.Ledger()
	if err != nil {
		t.Fatalf("the ledger: %v", err)
	}
	seam := &spentLedger{ledger: ledger}
	ctx, now, b := context.Background(), time.Now(), approval.Binding("sha256:ledger")
	if res, err := seam.Spend(ctx, b, "req-1", "apr-1", "duty-officer", now); res != gateway.ResolutionConsumed || err != nil {
		t.Fatalf("the first spend answered %v, %v", res, err)
	}
	res, err := seam.Spend(ctx, b, "req-1", "apr-1", "duty-officer", now)
	expectLedgerAnswer(t, "a second spend", res, err, gateway.ResolutionConsumed, gateway.ErrApprovalConsumed, holdjournal.ErrSpent)
	res, err = seam.Settle(ctx, b, "req-1", "apr-1", now)
	expectLedgerAnswer(t, "a settle of a spent approval", res, err, gateway.ResolutionConsumed, gateway.ErrApprovalConsumed, holdjournal.ErrSpent)
	if res, err := seam.Settle(ctx, b, "req-2", "apr-2", now); res != gateway.ResolutionNotResumed || err != nil {
		t.Fatalf("a settle answered %v, %v", res, err)
	}
	res, err = seam.Spend(ctx, b, "req-2", "apr-2", "duty-officer", now)
	expectLedgerAnswer(t, "a spend of a settled approval", res, err, gateway.ResolutionNotResumed, gateway.ErrNoApproval, holdjournal.ErrSettled)
	res, err = seam.Spend(ctx, b, "", "apr-3", "duty-officer", now)
	expectLedgerAnswer(t, "a spend naming no request", res, err, gateway.ResolutionUnspecified, gateway.ErrLedgerEntry, holdjournal.ErrLedgerEntry)
	res, err = seam.Settle(ctx, b, "req-3", "apr-3", time.Time{})
	expectLedgerAnswer(t, "a settle at the zero time", res, err, gateway.ResolutionUnspecified, gateway.ErrZeroTime, holdjournal.ErrZeroTime)
	expectLedgerMarks(t, seam, b, now)
}

// expectLedgerAnswer holds one ledger call to the resolution and the two
// refusals, the pipeline's and the ledger's own, it should answer.
func expectLedgerAnswer(t *testing.T, what string, res gateway.Resolution, err error, wantRes gateway.Resolution, want gateway.Error, from holdjournal.Error) {
	t.Helper()
	if res != wantRes || !isGateway(err, want) || !errors.Is(err, from) {
		t.Errorf("%s answered %v, %v; want %v beside %v and the ledger's own %v", what, res, err, wantRes, want, from)
	}
}

// expectLedgerMarks holds the seam's lookup to the two marks the vocabulary
// test made, and the translation to the four refusals it made.
func expectLedgerMarks(t *testing.T, seam *spentLedger, b approval.Binding, now time.Time) {
	t.Helper()
	marks, err := seam.Lookup(context.Background(), b, now)
	if err != nil || !maps.Equal(marks, map[string]gateway.Resolution{"req-1": gateway.ResolutionConsumed, "req-2": gateway.ResolutionNotResumed}) {
		t.Errorf("Lookup answered %v, %v", marks, err)
	}
	for from := range ledgerErrors {
		if !slices.Contains([]holdjournal.Error{holdjournal.ErrSpent, holdjournal.ErrSettled, holdjournal.ErrLedgerEntry, holdjournal.ErrZeroTime}, from) {
			t.Errorf("no case makes the ledger refuse with %v", from)
		}
	}
}

// TestAJournalRefusalIsTheGatewaysOwnVocabulary is the same for the journal,
// whose refusals the pipeline names and whose others travel as themselves.
func TestAJournalRefusalIsTheGatewaysOwnVocabulary(t *testing.T) {
	dir := t.TempDir()
	journal, err := holdjournal.Open(dir)
	if err != nil {
		t.Fatalf("holdjournal.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Errorf("closing the journal: %v", err)
		}
	})
	seam := &holdJournal{journal: journal}
	ctx := context.Background()
	if err := seam.Record(ctx, gateway.HoldEntry{}); !isGateway(err, gateway.ErrHoldEntry) {
		t.Errorf("an empty entry answered %v, want %v", err, gateway.ErrHoldEntry)
	}
	if err := seam.Mark(ctx, "req-nobody-recorded", gateway.HoldClosing); !isGateway(err, gateway.ErrNoHoldEntry) {
		t.Errorf("a flip of an entry nobody recorded answered %v, want %v", err, gateway.ErrNoHoldEntry)
	}
	// A state this build cannot name is refused rather than recorded as one it
	// could act on later.
	if err := seam.Mark(ctx, "req-nobody-recorded", gateway.HoldUnknown); !isGateway(err, gateway.ErrHoldFlip) {
		t.Errorf("a flip into no state answered %v, want %v", err, gateway.ErrHoldFlip)
	}
	listing, err := seam.List(ctx, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if listing.Complete {
		t.Error("a pass with no bound reported itself complete; it examined nothing")
	}
	// A record that failed after its link cannot be made to fail from here, so
	// its refusal is translated directly.
	maybe := fmt.Errorf("%w: the directory could not be forced to disk", holdjournal.ErrMaybeRecorded)
	if err := journalError(maybe); !isGateway(err, gateway.ErrHoldMaybeRecorded) || !errors.Is(err, holdjournal.ErrMaybeRecorded) {
		t.Errorf("a record that may have filed its entry answered %v, want %v beside the journal's own", err, gateway.ErrHoldMaybeRecorded)
	}
}

// isGateway reports whether err carries want, which is what the pipeline
// matches on.
func isGateway(err error, want gateway.Error) bool {
	return errors.Is(err, want)
}

// TestHealthSaysWhetherALostHoldIsClosed: a plane without a durable journal
// closes no hold it loses, which is ADR-0016's declared limit. It is reported
// where an operator reads, not left to be discovered, and it never makes the
// plane answer that it takes no material call.
func TestHealthSaysWhetherALostHoldIsClosed(t *testing.T) {
	status, body := ask(t, newTree(t).plane(t), "/healthz")
	if status != http.StatusOK {
		t.Fatalf("a plane with no hold journal answered %d: %v", status, body)
	}
	answer := approvalsAnswer(t, body)
	authority, _ := answer["authority"].(map[string]any)
	if authority["kind"] != "memory" || authority["state"] != "usable" || answer["hold_journal"] != false {
		t.Errorf("the answer is %v, want the memory authority, usable, and no journal", answer)
	}
	if claim, ok := authority["limits"].([]any); !ok || len(claim) != 1 || !strings.Contains(claim[0].(string), "unauthenticated claim") {
		t.Errorf("the memory authority does not say its approver is a claim: %v", authority["limits"])
	}
	limits, ok := answer["limits"].([]any)
	if !ok || len(limits) != 1 || !strings.Contains(limits[0].(string), "never closed") {
		t.Errorf("the declared limit is not reported: %v", answer["limits"])
	}
}

// TestHealthCountsWhatTheReconciliationSettled: with a journal the limit is
// gone, the pass reports itself complete, and the lost hold it closed is
// counted where an operator reads.
func TestHealthCountsWhatTheReconciliationSettled(t *testing.T) {
	tr := newTree(t)
	records, holds := tr.fileProvider(t)
	lostHold(t, records, holds, time.Now().Add(10*time.Minute))
	p := tr.plane(t)
	if r := p.pipeline.Reconcile(context.Background()); r.Closed != 1 || !r.Complete {
		t.Fatalf("the reconciliation settled %+v, so the counters below examine nothing", r)
	}
	status, body := ask(t, p, "/healthz")
	if status != http.StatusOK {
		t.Fatalf("a plane that closed a lost hold answered %d: %v", status, body)
	}
	answer := approvalsAnswer(t, body)
	for key, want := range map[string]any{
		"hold_journal": true, "reconcile_incomplete": false,
		"holds_closed": float64(1), "holds_unmeasured": float64(0), "journal_refusals": float64(0),
		"held_trails_left_open": float64(0),
	} {
		if answer[key] != want {
			t.Errorf("approvals.%s is %v, want %v", key, answer[key], want)
		}
	}
	if authority, _ := answer["authority"].(map[string]any); authority["kind"] != "directory" {
		t.Errorf("approvals.authority is %v, want the directory kind", answer["authority"])
	}
	if _, reported := answer["limits"]; reported {
		t.Errorf("a plane that closes a lost hold still reports the limit: %v", answer["limits"])
	}
}

// approvalsAnswer is the approvals object of a health answer.
func approvalsAnswer(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	answer, ok := body["approvals"].(map[string]any)
	if !ok {
		t.Fatalf("no approvals in the health answer: %v", body)
	}
	return answer
}
