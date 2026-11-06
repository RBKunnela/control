package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/core/approval"
	"github.com/guardana/control/internal/gateway"
)

const (
	rowApproval = "apr-row-1"
	rowRequest  = "req-row-1"
	rowDigest   = "sha256:" + "22222222222222222222222222222222222222222222222222222222222222cd"
)

var (
	rowRequestedAt = time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	rowNow         = rowRequestedAt.Add(10 * time.Minute)
)

type rowDecided uint8

const (
	rowDecidedNever rowDecided = iota
	rowDecidedBeforeRequest
	rowDecidedAtRequest
	rowDecidedAtNow
	rowDecidedAfterNow
)

type rowExpires uint8

const (
	rowExpiresNever rowExpires = iota
	rowExpiresBeforeNow
	rowExpiresAtNow
	rowExpiresAfterNow
)

// consumeRow is one combination of what a store hands back, and the moment
// it is read at.
type consumeRow struct {
	state    controlv1.ApprovalState
	approver string
	multiUse bool
	decided  rowDecided
	expires  rowExpires
	zeroNow  bool
}

func (r consumeRow) String() string {
	return fmt.Sprintf("%s/approver=%q/multi=%t/decided=%d/expires=%d/zero=%t",
		r.state, r.approver, r.multiUse, r.decided, r.expires, r.zeroNow)
}

func (r consumeRow) now() time.Time {
	if r.zeroNow {
		return time.Time{}
	}
	return rowNow
}

// decidedAt is the moment the row's answer is dated, if it has one.
func (r consumeRow) decidedAt() (time.Time, bool) {
	at, ok := map[rowDecided]time.Time{
		rowDecidedBeforeRequest: rowRequestedAt.Add(-time.Nanosecond),
		rowDecidedAtRequest:     rowRequestedAt,
		rowDecidedAtNow:         rowNow,
		rowDecidedAfterNow:      rowNow.Add(time.Nanosecond),
	}[r.decided]
	return at, ok
}

// pending is the row's approval as the plane mints it, before any answer.
func (r consumeRow) pending() *controlv1.Approval {
	a := r.approval()
	a.State, a.ApproverId, a.DecidedAt = controlv1.ApprovalState_APPROVAL_STATE_PENDING, "", nil
	return a
}

// answerable reports whether an approver's route can give the row's answer:
// an approval naming its approver, or a rejection, dated at some moment.
func (r consumeRow) answerable() bool {
	approved := r.state == controlv1.ApprovalState_APPROVAL_STATE_APPROVED && r.approver != ""
	rejected := r.state == controlv1.ApprovalState_APPROVAL_STATE_REJECTED
	return (approved || rejected) && r.decided != rowDecidedNever
}

// asHeld is the row the memory store ends up holding: the row itself where
// its answer can be given, and the pending approval it was held as where it
// cannot.
func (r consumeRow) asHeld() consumeRow {
	if r.answerable() {
		return r
	}
	r.state, r.approver, r.decided = controlv1.ApprovalState_APPROVAL_STATE_PENDING, "", rowDecidedNever
	return r
}

func (r consumeRow) approval() *controlv1.Approval {
	a := &controlv1.Approval{
		SchemaVersion:      "1.0",
		ApprovalId:         rowApproval,
		RequestId:          rowRequest,
		ActionDigest:       rowDigest,
		PolicyBundleDigest: fixtureBundleDigest,
		State:              r.state,
		ApproverId:         r.approver,
		MultiUse:           r.multiUse,
		RequestedAt:        timestamppb.New(rowRequestedAt),
	}
	if at, ok := r.decidedAt(); ok {
		a.DecidedAt = timestamppb.New(at)
	}
	expires := map[rowExpires]time.Time{
		rowExpiresBeforeNow: rowNow.Add(-time.Nanosecond),
		rowExpiresAtNow:     rowNow,
		rowExpiresAfterNow:  rowNow.Add(time.Nanosecond),
	}
	if at, ok := expires[r.expires]; ok {
		a.ExpiresAt = timestamppb.New(at)
	}
	return a
}

func consumeRows() []consumeRow {
	var out []consumeRow
	for _, state := range []controlv1.ApprovalState{
		controlv1.ApprovalState_APPROVAL_STATE_APPROVED,
		controlv1.ApprovalState_APPROVAL_STATE_REJECTED,
		controlv1.ApprovalState_APPROVAL_STATE_PENDING,
		controlv1.ApprovalState_APPROVAL_STATE_EXPIRED,
		controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED,
		controlv1.ApprovalState(99),
	} {
		for _, approver := range []string{"", "duty-officer"} {
			for _, multiUse := range []bool{false, true} {
				for decided := rowDecidedNever; decided <= rowDecidedAfterNow; decided++ {
					for expires := rowExpiresNever; expires <= rowExpiresAfterNow; expires++ {
						for _, zero := range []bool{false, true} {
							out = append(out, consumeRow{state, approver, multiUse, decided, expires, zero})
						}
					}
				}
			}
		}
	}
	return out
}

// The classes of what a store hands back about one row at one reading, as
// the pipeline judges it.
const (
	classUsable   = "usable"
	classRejected = "rejected"
	classMultiUse = "multi-use"
	classUnusable = "no answer yet"
	classGone     = "gone"
	classZeroTime = "zero time"
	classNotHeld  = "not held"
)

// classOf names what Find handed back at now, judged as the pipeline judges
// it. Anything else is spelled out, so it can match no expected class.
func classOf(found []gateway.Held, err error, now time.Time) string {
	switch {
	case errors.Is(err, gateway.ErrZeroTime):
		return classZeroTime
	case errors.Is(err, gateway.ErrNoApproval):
		return classGone
	case err != nil:
		return fmt.Sprintf("refused: %v", err)
	case len(found) != 1:
		return fmt.Sprintf("%d records", len(found))
	}
	switch approval.Consumable(found[0].Approval, now) {
	case approval.StandingUsable:
		return classUsable
	case approval.StandingRejected:
		return classRejected
	case approval.StandingMultiUse:
		return classMultiUse
	case approval.StandingUnusable:
		return classUnusable
	}
	return fmt.Sprintf("standing %v", approval.Consumable(found[0].Approval, now))
}

// wantClass is the order restated over the row's names: no time and no
// store in it. A store hides what expired, so an expiry is a record gone.
func wantClass(r consumeRow) string {
	switch {
	case r.zeroNow:
		return classZeroTime
	case r.expires != rowExpiresAfterNow:
		return classGone
	case r.multiUse:
		return classMultiUse
	case r.decided != rowDecidedAtRequest && r.decided != rowDecidedAtNow:
		return classUnusable
	case r.state == controlv1.ApprovalState_APPROVAL_STATE_REJECTED:
		return classRejected
	case r.state == controlv1.ApprovalState_APPROVAL_STATE_APPROVED && r.approver != "":
		return classUsable
	}
	return classUnusable
}

// unreadable is a row the directory refuses to read at all: no expiry, an
// answer dated before the request, or one dated past the expiry.
func unreadable(r consumeRow) bool {
	switch {
	case r.expires == rowExpiresNever, r.decided == rowDecidedBeforeRequest:
		return true
	case r.decided == rowDecidedAtNow:
		return r.expires == rowExpiresBeforeNow
	case r.decided == rowDecidedAfterNow:
		return r.expires != rowExpiresAfterNow
	}
	return false
}

func rowBinding(t *testing.T) approval.Binding {
	t.Helper()
	b, err := canon.ApprovalBinding(rowDigest, fixtureBundleDigest)
	if err != nil {
		t.Fatalf("ApprovalBinding: %v", err)
	}
	return approval.Binding(b)
}

// later is a moment past every expiry a row can carry.
var later = rowNow.Add(time.Hour)

// storeAnswer is what one store handed back about one row: the class of a
// Find, of the same Find again, and of one at a later moment, with the errors
// the directory's two Finds came back with and the names it holds afterwards.
type storeAnswer struct {
	first, again, later string
	firstErr, againErr  error
	names               []string
	answered            bool
}

// findInMemory holds the row's approval pending, answers it through Answer
// where an approver could, and reads it three times. A hold the store refuses
// is held nowhere.
func findInMemory(t *testing.T, r consumeRow, binding approval.Binding) storeAnswer {
	t.Helper()
	var store gateway.MemoryApprovals
	err := store.Hold(context.Background(), gateway.Held{
		Approval: r.pending(),
		Envelope: &controlv1.ActionEnvelope{},
		Decision: &controlv1.Decision{},
		Binding:  binding,
	}, rowRequestedAt)
	if errors.Is(err, gateway.ErrInvalidHold) {
		return storeAnswer{first: classNotHeld, again: classNotHeld, later: classNotHeld}
	}
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	var out storeAnswer
	if at, ok := r.decidedAt(); ok {
		out.answered = store.Answer(rowApproval, r.state, r.approver, "", at) == nil
	}
	found, err := store.Find(context.Background(), binding, r.now())
	out.first = classOf(found, err, r.now())
	found, err = store.Find(context.Background(), binding, r.now())
	out.again = classOf(found, err, r.now())
	found, err = store.Find(context.Background(), binding, later)
	out.later = classOf(found, err, later)
	return out
}

// findInDirectory holds the row's approval pending through the plane,
// answers it as an approver would where the approvers' command takes the
// answer, and otherwise writes the row's record by hand, as any writer of the
// directory can. It then reads it three times through the seam.
func findInDirectory(t *testing.T, r consumeRow, binding approval.Binding) storeAnswer {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "records")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("making %s: %v", dir, err)
	}
	made, err := approvals.OpenPlane(dir)
	if err != nil {
		t.Fatalf("OpenPlane: %v", err)
	}
	held := made.Hold(context.Background(), approvals.Hold{
		Approval: r.pending(), Binding: binding,
		Envelope: &controlv1.ActionEnvelope{}, Decision: &controlv1.Decision{},
	}, rowRequestedAt)
	if err := made.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var out storeAnswer
	if held == nil {
		out.answered = answerInDirectory(t, dir, r)
	}
	if !out.answered {
		writeRecord(t, filepath.Join(dir, rowApproval+".0-held.rec"), r.approval(), binding)
	}
	plane, err := approvals.OpenPlane(dir)
	if err != nil {
		t.Fatalf("OpenPlane: %v", err)
	}
	store := &approvalStore{plane: plane}
	found, err := store.Find(context.Background(), binding, r.now())
	out.first, out.firstErr = classOf(found, err, r.now()), err
	found, err = store.Find(context.Background(), binding, r.now())
	out.again, out.againErr = classOf(found, err, r.now()), err
	out.names = namesUnder(t, dir)
	found, err = store.Find(context.Background(), binding, later)
	out.later = classOf(found, err, later)
	if err := plane.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return out
}

// answerInDirectory gives the row's answer through the approvers' command,
// and reports whether the command took it.
func answerInDirectory(t *testing.T, dir string, r consumeRow) bool {
	t.Helper()
	at, ok := r.decidedAt()
	if !ok || !r.answerable() {
		return false
	}
	approver, err := approvals.OpenApprover(dir)
	if err != nil {
		t.Fatalf("OpenApprover: %v", err)
	}
	_, err = approver.Answer(context.Background(), rowApproval, r.state, r.approver, "", at)
	if closeErr := approver.Close(); closeErr != nil {
		t.Fatalf("closing the approver: %v", closeErr)
	}
	return err == nil
}

// writeRecord frames one record as the store's format states it.
func writeRecord(t *testing.T, path string, a *controlv1.Approval, binding approval.Binding) {
	t.Helper()
	raw, err := protojson.Marshal(a)
	if err != nil {
		t.Fatalf("protojson: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"schema_version": approvals.SchemaVersion,
		"approval_id":    a.GetApprovalId(),
		"request_id":     a.GetRequestId(),
		"binding":        string(binding),
		"approval":       json.RawMessage(raw),
		"authority":      approvals.HeldUnderDirectory,
		"tenant":         "acme",
		"project":        "orders",
	})
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	writeFramed(t, path, body)
}

// writeFramed writes body in the record frame.
func writeFramed(t *testing.T, path string, body []byte) {
	t.Helper()
	out := make([]byte, recordHeader, recordHeader+len(body))
	copy(out, recordMagic)
	binary.BigEndian.PutUint32(out[len(recordMagic):], uint32(len(body))) //nolint:gosec // G115: a test record is a few hundred bytes
	binary.BigEndian.PutUint32(out[len(recordMagic)+4:], crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)))
	if err := os.WriteFile(path, append(out, body...), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// TestBothStoresHandBackEveryRowAlike: each store holds the row pending and
// takes its answer through its own route, and hands back what the order names
// at that reading; where both hold the row itself, they hand back alike, a
// second read included, since a read changes nothing. Past its expiry every
// record is gone from a read, and no read writes a name. A row the directory
// refuses to read is usable in neither store.
func TestBothStoresHandBackEveryRowAlike(t *testing.T) {
	binding := rowBinding(t)
	unread, alike := 0, 0
	for _, r := range consumeRows() {
		read, compared := findRowAlike(t, r, binding)
		if !read {
			unread++
		}
		if compared {
			alike++
		}
	}
	if unread != 264 || alike != 36 {
		t.Errorf("%d rows were refused at read and %d compared across the stores, want 264 and 36", unread, alike)
	}
}

// findRowAlike reads one row in both stores and holds each to the class the
// order names for what it holds. It reports whether the directory read the
// row rather than refusing it at read, and whether both stores held the row
// itself and were compared.
func findRowAlike(t *testing.T, r consumeRow, binding approval.Binding) (read, compared bool) {
	t.Helper()
	mem := findInMemory(t, r, binding)
	dir := findInDirectory(t, r, binding)
	memoryAsHeld(t, r, mem)
	if unreadable(r) && (!r.zeroNow || r.expires == rowExpiresNever) {
		refusedByOne(t, r, mem, dir)
		return r.zeroNow, false
	}
	want := wantClass(r)
	if dir.first != want || dir.again != want {
		t.Errorf("%s: the directory handed back %q then %q, want %q twice", r, dir.first, dir.again, want)
	}
	if r.answerable() && (dir.first != mem.first || dir.again != mem.again) {
		t.Errorf("%s: the directory handed back %q then %q, the memory store %q then %q", r, dir.first, dir.again, mem.first, mem.again)
	}
	keptAlike(t, r, mem, dir)
	return true, r.answerable() && !r.zeroNow
}

// memoryAsHeld holds the memory store to the class the order names for what
// it holds: nothing for a row with no expiry, the row itself where its answer
// could be given, and the pending approval otherwise.
func memoryAsHeld(t *testing.T, r consumeRow, mem storeAnswer) {
	t.Helper()
	want := wantClass(r.asHeld())
	if r.expires == rowExpiresNever {
		want = classNotHeld
	} else if mem.answered != r.answerable() {
		t.Errorf("%s: the memory store took the answer: %t, want %t", r, mem.answered, r.answerable())
	}
	if mem.first != want || mem.again != want {
		t.Errorf("%s: the memory store handed back %q then %q, want %q twice", r, mem.first, mem.again, want)
	}
}

// keptAlike holds what each store keeps of a row it read: past every expiry
// the record is gone from a read, and the directory holds the record under
// the name it was held or answered under and no other.
func keptAlike(t *testing.T, r consumeRow, mem, dir storeAnswer) {
	t.Helper()
	// A record the directory refuses at read is refused at every reading.
	dirGone := dir.later == classGone
	if unreadable(r) {
		dirGone = strings.HasPrefix(dir.later, "refused: ")
	}
	if r.expires != rowExpiresNever && (mem.later != classGone || !dirGone) {
		t.Errorf("%s: past every expiry the record read %q in memory and %q in the directory, want %q, or a refusal of what the directory cannot read", r, mem.later, dir.later, classGone)
	}
	want := rowApproval + ".0-held.rec"
	if dir.answered {
		want = rowApproval + ".1-answered.rec"
	}
	var records []string
	for _, n := range dir.names {
		if strings.HasPrefix(n, rowApproval+".") && !strings.HasSuffix(n, ".view.json") {
			records = append(records, n)
		}
	}
	if !slices.Equal(records, []string{want}) {
		t.Errorf("%s: read %q and the directory holds %v, want %s alone", r, dir.first, dir.names, want)
	}
}

// refusedByOne holds a row one store refuses to keep to being usable in
// neither: the directory refuses it at read, or at the zero time before it
// reads, both times, and leaves the record where it was.
func refusedByOne(t *testing.T, r consumeRow, mem, dir storeAnswer) {
	t.Helper()
	readRefusal := func(err error) bool {
		return errors.Is(err, approvals.ErrInvalidHold) || errors.Is(err, approvals.ErrDecidedAt)
	}
	switch {
	case r.zeroNow:
		if dir.first != classZeroTime || dir.again != classZeroTime {
			t.Errorf("%s: the directory handed back %q then %q, want %q twice", r, dir.first, dir.again, classZeroTime)
		}
	case !readRefusal(dir.firstErr) || !readRefusal(dir.againErr):
		t.Errorf("%s: the directory answered %v then %v, want the record refused at read twice", r, dir.firstErr, dir.againErr)
	}
	if !slices.Contains(dir.names, rowApproval+".0-held.rec") {
		t.Errorf("%s: a record the directory refused leaves %v, want it in place", r, dir.names)
	}
	if mem.first == classUsable {
		t.Errorf("%s: a record the directory refuses to read is usable in memory", r)
	}
}
