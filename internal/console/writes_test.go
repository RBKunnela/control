package console

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/pause"
)

func newPauseFile(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pause")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "pause.json")
	if err := pause.Init(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	return file
}

// onlyEntry reads the pause file as pause list does and fails unless it
// holds exactly one entry.
func onlyEntry(t *testing.T, file string) pause.Entry {
	t.Helper()
	doc, err := pause.List(file)
	if err != nil || len(doc.Entries) != 1 {
		t.Fatalf("the file holds %+v, %v; want one entry", doc.Entries, err)
	}
	return doc.Entries[0]
}

// TestPauseAndLiftThroughThePage: an entry added through the page is in the
// file as pause list reads it, under the id the page answered with, and
// lifting it leaves a file that pauses nothing.
func TestPauseAndLiftThroughThePage(t *testing.T) {
	dir, _ := newPlane(t)
	file := newPauseFile(t)
	s := serve(t, dir, file)
	a := s.do(t, s.write("/api/pause", `{"scope":{"kind":"action","provider":"payments","action":"tool","name":"refund"},"reason":"card fraud"}`))
	if a.status != http.StatusOK {
		t.Fatalf("pause answered %d %q", a.status, a.body)
	}
	var added struct{ ID string }
	decode(t, a, &added)
	if e := onlyEntry(t, file); e.ID != added.ID || e.Reason != "card fraud" ||
		e.Scope != (pause.Scope{Kind: pause.ScopeAction, Provider: "payments", Action: "tool", Name: "refund"}) {
		t.Fatalf("the file holds %+v, want the entry %q", e, added.ID)
	}
	showsThePause(t, s, added.ID)
	liftsThePause(t, s, file, added.ID)
}

// showsThePause fails unless the page shows one pause, id, over the tool the
// test paused.
func showsThePause(t *testing.T, s *site, id string) {
	t.Helper()
	var st stateReply
	decode(t, s.do(t, s.readState()), &st)
	if st.Pause == nil || st.Pause.State != "paused" || st.Pause.Status != "Paused:" || len(st.Pause.Entries) != 1 ||
		st.Pause.Entries[0].ID != id || st.Pause.Entries[0].Covers != "tool refund of payments" {
		t.Fatalf("the page shows %+v", st.Pause)
	}
}

// liftsThePause lifts id through the page and fails unless the file and the
// page are clear after it.
func liftsThePause(t *testing.T, s *site, file, id string) {
	t.Helper()
	if a := s.do(t, s.write("/api/unpause", `{"id":"`+id+`"}`)); a.status != http.StatusOK {
		t.Fatalf("unpause answered %d %q", a.status, a.body)
	}
	if doc, err := pause.List(file); err != nil || len(doc.Entries) != 0 {
		t.Fatalf("after the lift the file holds %+v, %v", doc.Entries, err)
	}
	var st stateReply
	decode(t, s.do(t, s.readState()), &st)
	if st.Pause == nil || st.Pause.State != "clear" || st.Pause.Status != "Clear: this file pauses nothing." || len(st.Pause.Entries) != 0 {
		t.Errorf("after the lift the page shows %+v", st.Pause)
	}
}

// TestPauseRefusalsWriteNothing: a scope the file cannot hold, an id it does
// not hold, and a page with no pause file are each refused, and the file is
// byte for byte what it was.
func TestPauseRefusalsWriteNothing(t *testing.T) {
	dir, _ := newPlane(t)
	file := newPauseFile(t)
	before, err := os.ReadFile(file) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	s := serve(t, dir, file)
	for _, c := range []struct {
		name, path, body string
		want             int
		says             string
	}{
		{"a global scope naming a provider", "/api/pause", `{"scope":{"kind":"global","provider":"payments","action":"","name":""},"reason":""}`, http.StatusBadRequest, "a global scope names nothing else"},
		{"a prompt by name", "/api/pause", `{"scope":{"kind":"action","provider":"p","action":"prompt","name":"x"},"reason":""}`, http.StatusBadRequest, "paused by its provider only"},
		{"a principal scope", "/api/pause", `{"scope":{"kind":"principal","provider":"","action":"","name":""},"reason":""}`, http.StatusBadRequest, "scope.kind"},
		{"an id the file lacks", "/api/unpause", `{"id":"NOPE"}`, http.StatusConflict, pause.ErrNoEntry.Error()},
		{"a scope with an unknown member", "/api/pause", `{"scope":{"kind":"global","tenant":"t"},"reason":""}`, http.StatusBadRequest, `the member \"tenant\" is not one this write takes`},
		{"a scope naming its kind twice", "/api/pause", `{"scope":{"kind":"provider","kind":"global","provider":"","action":"","name":""},"reason":""}`, http.StatusBadRequest, "a member named twice"},
		{"a scope member in capitals", "/api/pause", `{"scope":{"KIND":"global","provider":"","action":"","name":""},"reason":""}`, http.StatusBadRequest, `the member \"KIND\" is not one this write takes`},
	} {
		a := s.do(t, s.write(c.path, c.body))
		if a.status != c.want || !strings.Contains(a.body, c.says) {
			t.Errorf("%s: answered %d %q, want %d saying %q", c.name, a.status, a.body, c.want, c.says)
		}
	}
	if after, err := os.ReadFile(file); err != nil || string(after) != string(before) { //nolint:gosec // G304: the test's own temporary directory
		t.Errorf("a refused write changed the file: %q, %v", after, err)
	}
	none := serve(t, dir, "")
	for _, path := range []string{"/api/pause", "/api/unpause"} {
		body := `{"id":"X"}`
		if path == "/api/pause" {
			body = `{"scope":{"kind":"global","provider":"","action":"","name":""},"reason":""}`
		}
		if a := none.do(t, none.write(path, body)); a.status != http.StatusNotFound {
			t.Errorf("%s with no pause file answered %d %q, want 404", path, a.status, a.body)
		}
	}
}

// TestAnUnreadablePauseFileSaysItBlocksEveryCall: a file the group may write
// is one a plane refuses, and the page says what a plane does about it.
func TestAnUnreadablePauseFileSaysItBlocksEveryCall(t *testing.T) {
	dir, _ := newPlane(t)
	file := newPauseFile(t)
	if err := os.Chmod(file, 0o620); err != nil { //nolint:gosec // G302: the mode a plane refuses
		t.Fatal(err)
	}
	s := serve(t, dir, file)
	var st stateReply
	decode(t, s.do(t, s.readState()), &st)
	if st.Pause == nil || st.Pause.State != "unreadable" || !strings.HasSuffix(st.Pause.Error, "; a plane reading this file blocks every call") ||
		!strings.Contains(st.Pause.Error, pause.ErrFileMode.Error()) {
		t.Errorf("the page shows %+v", st.Pause)
	}
}

// TestStoreRefusalsKeepTheirSentence: an answer the store refuses reaches the
// page as the store's own sentence, and one it files says whether a plane
// holds the directory.
func TestStoreRefusalsKeepTheirSentence(t *testing.T) {
	dir, plane := newPlane(t)
	hold(t, plane, "HELD1")
	s := serve(t, dir, "")
	digest := s.digestOf(t, "HELD1")
	for _, c := range []struct{ name, body, says string }{
		{"an unknown id", `{"id":"NOPE","reason":"","action_digest":"` + digest + `"}`, approvals.ErrNoApproval.Error()},
		{"a reason with a line break", s.answering(t, "HELD1", "a\nb"), approvals.ErrReason.Error()},
		{"an id that cannot name a file", `{"id":"../x","reason":"","action_digest":"` + digest + `"}`, approvals.ErrRecordName.Error()},
		{"an empty id", `{"id":"","reason":"","action_digest":"` + digest + `"}`, approvals.ErrRecordName.Error()},
		{"another record's digest", `{"id":"HELD1","reason":"","action_digest":"` + otherDigest(digest) + `"}`, digestMismatch},
	} {
		a := s.do(t, s.write("/api/approve", c.body))
		if a.status != http.StatusConflict || !strings.Contains(a.body, c.says) {
			t.Errorf("%s: answered %d %q, want 409 saying %q", c.name, a.status, a.body, c.says)
		}
	}
	approvesHeld1UnderAPlane(t, s)
	if a := s.do(t, s.write("/api/reject", s.answering(t, "HELD1", ""))); a.status != http.StatusConflict ||
		!strings.Contains(a.body, approvals.ErrApprovalAnswered.Error()) {
		t.Errorf("a second answer: %d %q", a.status, a.body)
	}
	var st stateReply
	decode(t, s.do(t, s.readState()), &st)
	if len(st.Approvals.Records) != 1 || st.Approvals.Records[0].AnsweredBy != testApprover || !st.Approvals.Complete ||
		st.Approvals.PlaneRunning == nil || !*st.Approvals.PlaneRunning {
		t.Errorf("the page shows %+v", st.Approvals)
	}
}

// TestAnAnswerToABrokenRecordSaysWhatIsWrongWithIt: the listing names the
// record among its problems, and an answer to it is refused with that
// problem's own sentence, not as an approval nobody holds.
func TestAnAnswerToABrokenRecordSaysWhatIsWrongWithIt(t *testing.T) {
	dir, plane := newPlane(t)
	hold(t, plane, "HELD1")
	if err := os.WriteFile(filepath.Join(dir, "BROKEN.0-held.rec"), []byte("not a record"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := serve(t, dir, "")
	a := s.do(t, s.write("/api/approve", `{"id":"BROKEN","reason":"","action_digest":"`+s.digestOf(t, "HELD1")+`"}`))
	if a.status != http.StatusConflict || !strings.Contains(a.body, `record \"BROKEN.0-held.rec\": `) ||
		strings.Contains(a.body, approvals.ErrNoApproval.Error()) {
		t.Errorf("an answer to a broken record: %d %q, want 409 naming the record and what is wrong with it", a.status, a.body)
	}
	if got := s.stateOf(t, "HELD1"); got != pending {
		t.Errorf("the record beside it is %s", got)
	}
}

// TestAnAnswerToAnIDAnIncompleteListingLeftOutIsNotNoApproval: the listing
// the page reads the digest from stops at the store's bound, so an id past it
// may be held all the same. The answer is refused as one the page could not
// look up, never as an approval nobody holds, and nothing is written.
func TestAnAnswerToAnIDAnIncompleteListingLeftOutIsNotNoApproval(t *testing.T) {
	dir, plane := newPlane(t)
	hold(t, plane, "HELDA")
	hold(t, plane, "HELDB")
	whole := serve(t, dir, "")
	digest := whole.digestOf(t, "HELDB")
	s := serveAs(t, dir, "", testApprover, nil, approvals.WithMaxRecords(1))
	s.token = s.trade(t)
	a := s.do(t, s.write("/api/approve", `{"id":"HELDB","reason":"","action_digest":"`+digest+`"}`))
	if a.status != http.StatusConflict || !strings.Contains(a.body, "listing of the directory was incomplete") ||
		strings.Contains(a.body, approvals.ErrNoApproval.Error()) {
		t.Errorf("an answer to an id past the listing's bound: %d %q, want 409 saying the listing was incomplete", a.status, a.body)
	}
	if got := whole.stateOf(t, "HELDB"); got != pending {
		t.Errorf("a refused answer left the record %s", got)
	}
}

// TestAnAnswerIsBoundToTheRecordsDigestNotItsProjections: the projection
// beside a record names another digest, as any writer of the directory can
// make it. An answer carrying the projection's digest is refused and writes
// nothing; one carrying the record's is filed.
func TestAnAnswerIsBoundToTheRecordsDigestNotItsProjections(t *testing.T) {
	dir, plane := newPlane(t)
	hold(t, plane, "VIEWED")
	forged := "sha256:" + strings.Repeat("ab", 32)
	changeView(t, dir, "VIEWED", func(v *approvals.View) { v.ActionDigest = forged })
	s := serve(t, dir, "")
	record := s.digestOf(t, "VIEWED")
	if record == forged {
		t.Fatal("the fixture's projection names the record's own digest")
	}
	if a := s.do(t, s.write("/api/approve", `{"id":"VIEWED","reason":"","action_digest":"`+forged+`"}`)); a.status != http.StatusConflict ||
		!strings.Contains(a.body, digestMismatch) {
		t.Errorf("an answer with the projection's digest: %d %q, want 409", a.status, a.body)
	}
	if got := s.stateOf(t, "VIEWED"); got != pending {
		t.Fatalf("a refused answer left the record %s", got)
	}
	if a := s.do(t, s.write("/api/approve", `{"id":"VIEWED","reason":"","action_digest":"`+record+`"}`)); a.status != http.StatusOK {
		t.Errorf("an answer with the record's digest: %d %q, want 200", a.status, a.body)
	}
}

// approvesHeld1UnderAPlane approves HELD1 through the page and fails unless
// the answer is filed and says the call can resume on its retry.
func approvesHeld1UnderAPlane(t *testing.T, s *site) {
	t.Helper()
	a := s.do(t, s.write("/api/approve", s.answering(t, "HELD1", "")))
	var done answerReply
	decode(t, a, &done)
	if a.status != http.StatusOK || done.ApprovalID != "HELD1" || done.Answer != "approved" || !done.PlaneRunning ||
		!slices.Equal(done.Notice, []string{"Approval HELD1: approved.", "The call can resume on the agent's retry before the approval expires."}) {
		t.Fatalf("answered %d %+v", a.status, done)
	}
}

// TestAnAnswerWithNoPlaneSaysTheCallWillNotRun: the answer is filed, and the
// page says nothing is waiting for it; a rejection with a plane says only
// what was filed.
func TestAnAnswerWithNoPlaneSaysTheCallWillNotRun(t *testing.T) {
	dir, plane := newPlane(t)
	hold(t, plane, "LATE1")
	hold(t, plane, "NO1")
	s := serve(t, dir, "")
	var done answerReply
	decode(t, s.do(t, s.write("/api/reject", s.answering(t, "NO1", ""))), &done)
	if !slices.Equal(done.Notice, []string{"Approval NO1: rejected."}) {
		t.Errorf("a rejection with a plane says %q", done.Notice)
	}
	if err := plane.Close(); err != nil {
		t.Fatal(err)
	}
	decode(t, s.do(t, s.write("/api/approve", s.answering(t, "LATE1", ""))), &done)
	want := []string{
		"Approval LATE1: approved.",
		"No plane holds this directory, so nothing is waiting for this answer.",
		"The call this approval was held for will not run: a hold does not survive the plane stopping.",
		"The answer is written to the directory all the same.",
		"A plane that keeps a hold journal records it on that call's trail, as a decision that came too late to resume it.",
	}
	if done.PlaneRunning || !slices.Equal(done.Notice, want) {
		t.Errorf("an approval with no plane: running %v, says %q", done.PlaneRunning, done.Notice)
	}
	if got := s.stateOf(t, "LATE1"); got != controlv1.ApprovalState_APPROVAL_STATE_APPROVED {
		t.Errorf("the answer with no plane left the record %s", got)
	}
}

// TestNewRefuses: a page is not built over a host that is not the literal
// loopback address, a token that is not 32 bytes, or an approver id the store
// would refuse on every answer. Each case differs from the one New accepts,
// last, in one field.
func TestNewRefuses(t *testing.T) {
	dir, _ := newPlane(t)
	store, err := approvals.OpenApprover(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	good := Options{Approvals: store, Directory: dir, ApproverID: strings.Repeat("a", 128), Host: "127.0.0.1:8123", Token: NewToken()}
	for name, mutate := range map[string]func(o *Options){
		"no store":                 func(o *Options) { o.Approvals = nil },
		"a name":                   func(o *Options) { o.Host = "localhost:8123" },
		"every interface":          func(o *Options) { o.Host = "0.0.0.0:8123" },
		"another loopback address": func(o *Options) { o.Host = "127.0.0.2:8123" },
		"IPv6 loopback":            func(o *Options) { o.Host = "[::1]:8123" },
		"port zero":                func(o *Options) { o.Host = "127.0.0.1:0" },
		"a padded port":            func(o *Options) { o.Host = "127.0.0.1:08123" },
		"no port":                  func(o *Options) { o.Host = "127.0.0.1" },
		"no token":                 func(o *Options) { o.Token = "" },
		"a short token":            func(o *Options) { o.Token = o.Token[:42] },
		"a padded token":           func(o *Options) { o.Token += "=" },
		"a standard base64 token":  func(o *Options) { o.Token = strings.Repeat("+", 43) },
		"no approver id":           func(o *Options) { o.ApproverID = "" },
		"an approver id of 129":    func(o *Options) { o.ApproverID = strings.Repeat("a", 129) },
		"a trailing space":         func(o *Options) { o.ApproverID = "duty " },
		"a bidirectional override": func(o *Options) { o.ApproverID = "duty\u202eofficer" },
	} {
		o := good
		mutate(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s: New accepted %+v", name, o)
		}
	}
	if _, err := New(good); err != nil {
		t.Fatalf("New refused the well-formed options: %v", err)
	}
}

// TestTheTokenIs32RandomBytes: two tokens differ, and each decodes to 32
// bytes.
func TestTheTokenIs32RandomBytes(t *testing.T) {
	a, b := NewToken(), NewToken()
	if a == b || len(a) != 43 || len(b) != 43 {
		t.Errorf("tokens %q and %q", a, b)
	}
}
