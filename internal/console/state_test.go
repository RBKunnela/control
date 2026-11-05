package console

import (
	"context"
	"errors"
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
)

// TestAnIncompleteListingSaysSo: a record that will not decode makes the
// listing incomplete and is named in the banner, the record beside it is
// still listed, and a record whose projection is gone says so instead of
// showing empty fields.
func TestAnIncompleteListingSaysSo(t *testing.T) {
	l := brokenListing(t)
	if l.Complete || len(l.Problems) == 0 || l.Error != "" || l.Empty != "" {
		t.Fatalf("the listing reads complete %v with problems %+v, error %q and empty %q", l.Complete, l.Problems, l.Error, l.Empty)
	}
	namesTheBrokenRecord(t, l)
	listsTheRecordsBesideIt(t, l)
}

// namesTheBrokenRecord fails unless the problems and the banner name the
// record that would not decode, under the banner's first line.
func namesTheBrokenRecord(t *testing.T, l approvalsReply) {
	t.Helper()
	if !slices.ContainsFunc(l.Problems, func(p problemReply) bool { return p.Name == "BROKEN.0-held.rec" }) {
		t.Errorf("no problem names the broken record: %+v", l.Problems)
	}
	if len(l.Banner) < 2 || l.Banner[0] != "This listing is incomplete: it is not every record in the directory." ||
		!slices.ContainsFunc(l.Banner, func(line string) bool { return strings.HasPrefix(line, "BROKEN.0-held.rec: ") }) {
		t.Errorf("the banner is %q", l.Banner)
	}
}

// listsTheRecordsBesideIt fails unless the whole record shows its fields and
// the one without a projection says it has none.
func listsTheRecordsBesideIt(t *testing.T, l approvalsReply) {
	t.Helper()
	notes := map[string]string{}
	for _, r := range l.Records {
		notes[r.ApprovalID] = r.ReadableNote
		if r.ApprovalID == "GOOD1" && (r.Readable == nil || r.Readable.Resource != "payment pay-good1") {
			t.Errorf("GOOD1 shows %+v", r.Readable)
		}
	}
	if len(notes) != 2 || notes["BLIND1"] != "none: the projection is missing or would not decode" {
		t.Errorf("the records are %+v", notes)
	}
}

// brokenListing is the page's listing of a directory holding a record that
// will not decode, a record without its projection and a whole one.
func brokenListing(t *testing.T) approvalsReply {
	t.Helper()
	dir, plane := newPlane(t)
	hold(t, plane, "GOOD1")
	hold(t, plane, "BLIND1")
	if err := os.WriteFile(filepath.Join(dir, "BROKEN.0-held.rec"), []byte("not a record"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "BLIND1.view.json")); err != nil {
		t.Fatal(err)
	}
	s := serve(t, dir, "")
	return readListing(t, s)
}

// readListing reads the page's listing, and fails on anything but 200.
func readListing(t *testing.T, s *site) approvalsReply {
	t.Helper()
	a := s.do(t, s.readState())
	if a.status != http.StatusOK {
		t.Fatalf("answered %d %q", a.status, a.body)
	}
	var st stateReply
	decode(t, a, &st)
	return st.Approvals
}

// TestAFailedListingCannotSayWhetherAPlaneHoldsIt: a plane holds the
// directory and no listing can be made. Nothing measured the plane, so the
// page says it cannot tell, not that none holds it, and the banner says the
// empty list is not an empty directory.
func TestAFailedListingCannotSayWhetherAPlaneHoldsIt(t *testing.T) {
	dir, plane := newPlane(t)
	hold(t, plane, "HELD1")
	s := serve(t, dir, "")
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: a directory needs its execute bit; 0700 is owner-only
	a := s.do(t, s.readState())
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs its execute bit; 0700 is owner-only
		t.Fatal(err)
	}
	var st stateReply
	decode(t, a, &st)
	l := st.Approvals
	if l.Error == "" || l.Complete || len(l.Records) != 0 || l.Empty != "" {
		t.Fatalf("the listing did not fail: %+v", l)
	}
	if !strings.Contains(a.body, `"plane_running":null`) || l.PlaneRunning != nil {
		t.Errorf("an unmeasured plane reads %v in %s", l.PlaneRunning, a.body)
	}
	if l.Plane != "Cannot say whether a plane holds this directory: no listing could be made." {
		t.Errorf("the plane line is %q", l.Plane)
	}
	if !slices.Equal(l.Banner, []string{"No listing could be made: " + l.Error + ".", "This is not an empty directory; nothing below is known."}) {
		t.Errorf("the banner is %q", l.Banner)
	}
}

// TestThePlaneLineSaysWhatTheProbeFound: a held lock reads as a plane, a free
// one as none that will consume an answer, and an empty whole listing says
// there are no records.
func TestThePlaneLineSaysWhatTheProbeFound(t *testing.T) {
	dir, plane := newPlane(t)
	s := serve(t, dir, "")
	l := readListing(t, s)
	if l.PlaneRunning == nil || !*l.PlaneRunning || l.Plane != "A plane holds this directory." || l.Empty != "No records." || len(l.Banner) != 0 {
		t.Errorf("with a plane the listing reads %+v", l)
	}
	if err := plane.Close(); err != nil {
		t.Fatal(err)
	}
	l = readListing(t, s)
	if l.PlaneRunning == nil || *l.PlaneRunning || l.Plane != "No plane holds this directory, so nothing will consume an answer." {
		t.Errorf("with no plane the listing reads %+v", l)
	}
}

// TestCardsStandInTheOrderTheirCallsWereHeld: approval ids are random, so an
// order by id would put a new hold anywhere. The listing is ordered by the
// time each request was held, ties by id, and a later hold with the smallest
// id comes last.
func TestCardsStandInTheOrderTheirCallsWereHeld(t *testing.T) {
	dir, plane := newPlane(t)
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	for i, id := range []string{"C3", "A1", "B2"} {
		holdAt(t, plane, id, base.Add(time.Duration(i)*time.Second))
	}
	holdAt(t, plane, "Z9", base.Add(3*time.Second))
	holdAt(t, plane, "Y8", base.Add(3*time.Second))
	s := serve(t, dir, "")
	if got := idsOf(readListing(t, s)); !slices.Equal(got, []string{"C3", "A1", "B2", "Y8", "Z9"}) {
		t.Errorf("the cards stand as %v", got)
	}
	holdAt(t, plane, "A0", base.Add(4*time.Second))
	if got := idsOf(readListing(t, s)); !slices.Equal(got, []string{"C3", "A1", "B2", "Y8", "Z9", "A0"}) {
		t.Errorf("after a later hold the cards stand as %v", got)
	}
}

func idsOf(l approvalsReply) []string {
	var ids []string
	for _, r := range l.Records {
		ids = append(ids, r.ApprovalID)
	}
	return ids
}

// The clock and the digest the record table is built against.
var (
	tableNow    = time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	tableDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// tableEntry is one record, held a minute before tableNow and expiring after
// it by expiresIn, answered half a minute before tableNow by approver when
// approver is not empty.
func tableEntry(state controlv1.ApprovalState, expiresIn time.Duration, approver string, view *approvals.View) approvals.Entry {
	a := &controlv1.Approval{
		ApprovalId:   "REC1",
		RequestId:    "req-rec1",
		ActionDigest: tableDigest,
		State:        state,
		RequestedAt:  timestamppb.New(tableNow.Add(-time.Minute)),
		ExpiresAt:    timestamppb.New(tableNow.Add(expiresIn)),
		ApproverId:   approver,
	}
	if approver != "" {
		a.DecidedAt = timestamppb.New(tableNow.Add(-30 * time.Second))
	}
	return approvals.Entry{Record: approvals.Record{ApprovalID: "REC1", RequestID: "req-rec1", Approval: a}, View: view}
}

func tableView() *approvals.View {
	return &approvals.View{
		ApprovalID: "REC1", ActionDigest: tableDigest, Principal: "user-1", Agent: "agent-1", Action: "refund",
		Provider: "payments", ResourceType: "payment", ResourceID: "pay-1", EffectClass: "EFFECT_CLASS_TRANSACT",
		RuleIDs: []string{"rule-a", "rule-b"}, RequestedAt: tableNow.Add(-time.Minute),
	}
}

// TestEachRecordSaysWhatItCan: every sentence a card says, over state, expiry
// and whether a plane holds the directory. Each case differs from a neighbour
// in one of them, and the expiry cases sit on either side of the instant an
// answer is refused at. No card says an approval was spent: that is the
// plane's own record, which the page does not read.
func TestEachRecordSaysWhatItCan(t *testing.T) {
	const (
		pendingState  = controlv1.ApprovalState_APPROVAL_STATE_PENDING
		approvedState = controlv1.ApprovalState_APPROVAL_STATE_APPROVED
		rejectedState = controlv1.ApprovalState_APPROVAL_STATE_REJECTED
	)
	for _, c := range []struct {
		name       string
		entry      approvals.Entry
		plane      bool
		status     string
		answerable bool
	}{
		{"waiting", tableEntry(pendingState, time.Second, "", tableView()), true,
			"Waiting for an answer until 2026-03-01T12:00:01Z.", true},
		{"waiting with no plane", tableEntry(pendingState, time.Second, "", tableView()), false,
			"Waiting for an answer until 2026-03-01T12:00:01Z.", true},
		{"expiring now", tableEntry(pendingState, 0, "", tableView()), true,
			"Past its expiry. No answer is accepted.", false},
		{"approved", tableEntry(approvedState, time.Minute, "duty-officer", tableView()), true,
			"Approved by duty-officer. The call can resume on the agent's retry before 2026-03-01T12:01:00Z, once; this page cannot see whether a retry spent it.", false},
		{"approved with no plane", tableEntry(approvedState, time.Minute, "duty-officer", tableView()), false,
			"Approved by duty-officer. No plane holds this directory, so the call it was held for will not run.", false},
		{"approved and expired", tableEntry(approvedState, 0, "duty-officer", tableView()), true,
			"Approved by duty-officer. It expired before a retry used it.", false},
		{"rejected", tableEntry(rejectedState, time.Minute, "duty-officer", tableView()), true,
			"Rejected by duty-officer.", false},
		{"rejected by nobody named", tableEntry(rejectedState, time.Minute, "", tableView()), true,
			"Rejected.", false},
		{"a state no answer names", tableEntry(controlv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED, time.Minute, "", tableView()), true,
			"State APPROVAL_STATE_UNSPECIFIED.", false},
	} {
		r := recordOf(c.entry, tableNow, c.plane)
		if r.Status != c.status {
			t.Errorf("%s: says %q, want %q", c.name, r.Status, c.status)
		}
		if got := fieldValue(r, "resolution"); got != "(no field resolution)" {
			t.Errorf("%s: a card reads a resolution %q, which the directory no longer holds", c.name, got)
		}
		if r.Answerable != c.answerable {
			t.Errorf("%s: answerable %v, want %v", c.name, r.Answerable, c.answerable)
		}
		if r.Title != "Approval REC1" {
			t.Errorf("%s: title %q", c.name, r.Title)
		}
	}
}

func fieldValue(r recordReply, label string) string {
	for _, f := range r.Fields {
		if f.Label == label {
			return f.Value
		}
	}
	return "(no field " + label + ")"
}

// TestACardShowsTheListingsFieldsInItsOrder: an answered record with its
// projection shows every field the listing prints, in the listing's order,
// and names the call and the head of its digest for a confirmation.
func TestACardShowsTheListingsFieldsInItsOrder(t *testing.T) {
	r := recordOf(tableEntry(controlv1.ApprovalState_APPROVAL_STATE_REJECTED, time.Minute, "duty-officer", tableView()), tableNow, true)
	want := []fieldReply{
		{"state", "rejected"},
		{"request", "req-rec1"},
		{"action digest", tableDigest},
		{"bundle digest", ""},
		{"expires", "2026-03-01T12:01:00Z"},
		{"answered by", "duty-officer"},
		{"answered at", "2026-03-01T11:59:30Z"},
		{"principal", "user-1"},
		{"agent", "agent-1"},
		{"action", "refund"},
		{"upstream", "payments"},
		{"resource", "payment pay-1"},
		{"effect class", "EFFECT_CLASS_TRANSACT"},
		{"rule ids", "rule-a, rule-b"},
		{"requested", "2026-03-01T11:59:00Z"},
	}
	if !slices.Equal(r.Fields, want) {
		t.Errorf("the fields are\n%v\nwant\n%v", r.Fields, want)
	}
	if r.Confirm != "tool refund on upstream payments, action digest 0123456789ab" {
		t.Errorf("the confirmation names %q", r.Confirm)
	}
}

// TestAProjectionThatIsNotThisRecordsShowsNone: a projection naming another
// approval or another digest, or none at all, lends the card no field and no
// tool to confirm.
func TestAProjectionThatIsNotThisRecordsShowsNone(t *testing.T) {
	otherID, otherDigest := tableView(), tableView()
	otherID.ApprovalID = "REC2"
	otherDigest.ActionDigest = "sha256:" + strings.Repeat("f", 64)
	for name, c := range map[string]struct {
		view *approvals.View
		note string
	}{
		"another approval": {otherID, "none: the projection beside this record describes another approval"},
		"another digest":   {otherDigest, "none: the projection beside this record describes another approval"},
		"none":             {nil, "none: the projection is missing or would not decode"},
	} {
		r := recordOf(tableEntry(controlv1.ApprovalState_APPROVAL_STATE_PENDING, time.Minute, "", c.view), tableNow, true)
		if r.Readable != nil || r.ReadableNote != c.note || fieldValue(r, "readable") != c.note || fieldValue(r, "principal") != "(no field principal)" {
			t.Errorf("%s: readable %+v, note %q, fields %v", name, r.Readable, r.ReadableNote, r.Fields)
		}
		if r.Confirm != "a tool this page cannot read on an upstream this page cannot read, action digest 0123456789ab" {
			t.Errorf("%s: the confirmation names %q", name, r.Confirm)
		}
	}
}

// TestThePagesApproverCheckIsTheStores: the page refuses at start exactly
// the approver ids the store refuses an answer under. The store is asked
// about an approval it does not hold, so it refuses every id either way, and
// only the refusal's kind tells the two apart.
func TestThePagesApproverCheckIsTheStores(t *testing.T) {
	dir, _ := newPlane(t)
	store, err := approvals.OpenApprover(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	accepted, refused := 0, 0
	for _, id := range []string{
		"", "a", strings.Repeat("a", 128), strings.Repeat("a", 129), "duty-officer", "duty.officer_1", "duty officer",
		"duty ", " duty", "duty\tofficer", "duty\nofficer", "duty\u202eofficer", "duty\u200bofficer", "duty\u00a0officer",
		"ok\xff", "zoë", "日本", "a/b", "a:b", "duty\ufe0fofficer",
	} {
		page := CheckApproverID(id) == nil
		_, err := store.Answer(context.Background(), "NOPE", controlv1.ApprovalState_APPROVAL_STATE_APPROVED, id, "", time.Now())
		if err == nil {
			t.Fatalf("the store answered an approval it does not hold under %q", id)
		}
		storeAccepts := !errors.Is(err, approvals.ErrApproverID)
		if page != storeAccepts {
			t.Errorf("%q: the page accepts %v, the store %v (%v)", id, page, storeAccepts, err)
		}
		if page {
			accepted++
		} else {
			refused++
		}
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("the table holds %d accepted and %d refused ids; it cannot tell the two checks apart", accepted, refused)
	}
}
