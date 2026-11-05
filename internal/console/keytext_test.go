package console

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/keytext"
	"github.com/guardana/control/internal/pause"
)

// keyBody is a key file's body line for a fixed seed, built from the prefix
// at run time so no fixture here looks like a key.
func keyBody() string {
	seed := sha256.Sum256([]byte("page fixture"))
	return base64.StdEncoding.EncodeToString(append([]byte(keytext.PKCS8Prefix), seed[:]...))
}

// pemOpening is a PEM opening marker, spelled in parts.
var pemOpening = "-----" + "BEGIN PRIVATE KEY" + "-----"

// changeView rewrites the projection beside approvalID with change, as any
// writer of the directory can.
func changeView(t *testing.T, dir, approvalID string, change func(v *approvals.View)) {
	t.Helper()
	path := filepath.Join(dir, approvalID+".view.json")
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	var v approvals.View
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	change(&v)
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestThePageWithholdsKeyTextAsTheListingDoes: key text in a projection's
// fields and in a pause's reason is withheld from every value the page
// shows, as approvals list and pause list withhold it, and the text around it
// is kept.
func TestThePageWithholdsKeyTextAsTheListingDoes(t *testing.T) {
	dir, plane := newPlane(t)
	hold(t, plane, "KEYTEXT")
	body := keyBody()
	changeView(t, dir, "KEYTEXT", func(v *approvals.View) {
		v.ResourceID = "pay " + pemOpening + " " + body[:40]
		v.Action = "refund-" + body + " now"
		v.Principal = body
	})
	file := newPauseFile(t)
	entry := pause.Entry{ID: "HOLD1", Scope: pause.Scope{Kind: pause.ScopeGlobal}, CreatedAt: time.Now().UTC(), Reason: "see " + body}
	if err := pause.Add(context.Background(), file, entry); err != nil {
		t.Fatal(err)
	}
	s := serve(t, dir, file)
	var st stateReply
	decode(t, s.do(t, s.readState()), &st)
	if len(st.Approvals.Records) != 1 {
		t.Fatalf("the listing holds %+v", st.Approvals.Records)
	}
	cardWithholds(t, st.Approvals.Records[0])
	if st.Pause == nil || len(st.Pause.Entries) != 1 || pauseField(st.Pause.Entries[0], "reason") != "see "+keytext.Withheld {
		t.Errorf("the pause reads %+v", st.Pause)
	}
	for _, shown := range shownText(st) {
		if keytext.Holds(shown) {
			t.Errorf("the page shows key text in %q", shown)
		}
	}
}

// cardWithholds fails unless the card of the record the test rewrote shows
// its fields, its readable fields and its confirmation with the key text
// withheld and the rest kept.
func cardWithholds(t *testing.T, r recordReply) {
	t.Helper()
	const w = keytext.Withheld
	for label, want := range map[string]string{
		"resource":  "payment pay " + w,
		"action":    w + " now",
		"principal": w,
	} {
		if got := fieldValue(r, label); got != want {
			t.Errorf("the %s field reads %q, want %q", label, got, want)
		}
	}
	if r.Readable == nil || r.Readable.Resource != "payment pay "+w || r.Readable.Action != w+" now" || r.Readable.Principal != w {
		t.Errorf("the readable fields are %+v", r.Readable)
	}
	if !strings.HasPrefix(r.Confirm, "tool "+w+" now on upstream payments, ") {
		t.Errorf("the confirmation names %q", r.Confirm)
	}
}

// TestThePageQuotesWhatTheListingQuotes: a value holding a bidirectional
// override comes back quoted, whole, as approvals list prints it, so the
// page does not depend on its script to quote it.
func TestThePageQuotesWhatTheListingQuotes(t *testing.T) {
	dir, plane := newPlane(t)
	hold(t, plane, "BIDI")
	changeView(t, dir, "BIDI", func(v *approvals.View) { v.ResourceID = "pay-\u202egpj.exe" })
	s := serve(t, dir, "")
	r := readListing(t, s).Records[0]
	if got, want := fieldValue(r, "resource"), `"payment pay-\u202egpj.exe"`; got != want {
		t.Errorf("the resource field reads %q, want %q", got, want)
	}
}

func pauseField(e entryReply, label string) string {
	for _, f := range e.Fields {
		if f.Label == label {
			return f.Value
		}
	}
	return "(no field " + label + ")"
}

// shownText is every string of the state the page answers with but the
// handles an answer or a lift sends back: the lines of the listing, its
// problems, every field of each record and its projection, and every field
// of the pause file and its entries.
func shownText(st stateReply) []string {
	a := st.Approvals
	out := append([]string{st.ApproverID, a.Directory, a.Error, a.Plane, a.Empty, a.Gone}, a.Banner...)
	for _, pr := range a.Problems {
		out = append(out, pr.Name, pr.Error)
	}
	for _, r := range a.Records {
		out = append(out, r.State, r.Request, r.BundleDigest, r.Expires, r.AnsweredBy, r.AnsweredAt,
			r.ReadableNote, r.Title, r.Status, r.Confirm)
		if v := r.Readable; v != nil {
			out = append(out, v.Principal, v.Agent, v.Action, v.Upstream, v.Resource, v.EffectClass, v.RuleIDs, v.Requested)
		}
		for _, f := range r.Fields {
			out = append(out, f.Label, f.Value)
		}
	}
	if p := st.Pause; p != nil {
		out = append(out, p.File, p.State, p.Status, p.Error)
		for _, e := range p.Entries {
			out = append(out, e.Scope.Kind, e.Scope.Provider, e.Scope.Action, e.Scope.Name, e.Covers, e.Created, e.Reason)
			for _, f := range e.Fields {
				out = append(out, f.Label, f.Value)
			}
		}
	}
	return out
}

// keyStart is the start every key file's body line begins with, from the
// prefix at run time. It is letters and digits alone, so it fits in any id
// and any file name.
func keyStart() string { return keyBody()[:21] }

// TestEveryValueThePageShowsWithholdsKeyText: key text in every string a
// record, its projection, a problem, the pause file, the page's own options
// and a request bring reaches the page withheld, in its state, the notices of
// its writes and the bodies of its refusals. Each value the key text was put
// in must also say it was withheld, so a value it never reached fails.
func TestEveryValueThePageShowsWithholdsKeyText(t *testing.T) {
	ks := keyStart()
	k := keyTextPage(t, ks)
	marked := map[string]string{}
	before := k.s.state(t)
	shown := shownText(before)
	digest := markListing(t, before, k.lifted, marked)

	var answered answerReply
	decode(t, k.s.do(t, k.s.write("/api/approve", k.s.answering(t, ks, ""))), &answered)
	marked["answer notice"] = strings.Join(answered.Notice, " ")
	after := k.s.state(t)
	shown = append(shown, shownText(after)...)
	if len(after.Approvals.Records) == 1 {
		marked["answered by"], marked["status"] = after.Approvals.Records[0].AnsweredBy, after.Approvals.Records[0].Status
	}
	marked["pause notice"] = k.s.notice(t, "/api/pause", `{"scope":{"kind":"provider","provider":"w-`+ks+`","action":"","name":""},"reason":""}`)
	marked["lift notice"] = k.s.notice(t, "/api/unpause", `{"id":"`+k.lifted+`"}`)
	marked["refusal of a problem"] = k.s.refusal(t, "/api/approve", `{"id":"`+k.broken+`","reason":"","action_digest":"`+digest+`"}`)
	marked["refusal of a member"] = k.s.refusal(t, "/api/approve", `{"`+ks+`":1}`)

	if err := os.WriteFile(k.file, []byte(`{"schema_version":"`+ks+`","entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(k.dir, k.dir+"-moved"); err != nil {
		t.Fatal(err)
	}
	failed := k.s.state(t)
	shown = append(shown, shownText(failed)...)
	marked["listing error"] = failed.Approvals.Error
	if failed.Pause != nil {
		marked["pause error"] = failed.Pause.Error
	}
	allWithheld(t, marked, shown)
}

// allWithheld fails unless each of the 30 marked values says key text was
// withheld from it and holds none, and no shown value holds any.
func allWithheld(t *testing.T, marked map[string]string, shown []string) {
	t.Helper()
	if len(marked) != 30 {
		t.Errorf("%d values were marked, want 30: %v", len(marked), marked)
	}
	for name, v := range marked {
		if !strings.Contains(v, keytext.Withheld) || keytext.Holds(v) {
			t.Errorf("the %s reads %q, want the key text withheld", name, v)
		}
	}
	for _, v := range shown {
		if keytext.Holds(v) {
			t.Errorf("the page shows key text in %q", v)
		}
	}
}

// markListing marks every value of the listing and the pause file the
// fixture put key text in, and returns the record's action digest.
func markListing(t *testing.T, st stateReply, lifted string, marked map[string]string) string {
	t.Helper()
	a, p := st.Approvals, st.Pause
	if len(a.Records) != 1 || len(a.Problems) != 1 || p == nil || len(p.Entries) != 2 || a.Records[0].Readable == nil {
		t.Fatalf("the page shows records %+v, problems %+v and pause %+v", a.Records, a.Problems, p)
	}
	r, entry, kept := a.Records[0], p.Entries[0], p.Entries[1]
	if entry.ID != lifted {
		entry, kept = kept, entry
	}
	v := r.Readable
	for name, value := range map[string]string{
		"approver id": st.ApproverID, "directory": a.Directory, "problem name": a.Problems[0].Name,
		"problem error": a.Problems[0].Error, "title": r.Title, "request": r.Request, "confirm": r.Confirm,
		"pause file": p.File, "scope provider": entry.Scope.Provider, "scope name": entry.Scope.Name, "covers": entry.Covers,
		"reason": entry.Reason, "entry id": pauseField(entry, "id"), "another provider": kept.Scope.Provider,
		"principal": v.Principal, "agent": v.Agent, "action": v.Action, "upstream": v.Upstream, "resource": v.Resource,
		"effect class": v.EffectClass, "rule ids": v.RuleIDs,
	} {
		marked[name] = value
	}
	return r.ActionDigest
}

// keyText is a page whose store, record, projection, directory, pause file,
// pause entries and approver id all hold key text.
type keyText struct {
	s                         *site
	dir, file, broken, lifted string
}

func keyTextPage(t *testing.T, ks string) keyText {
	t.Helper()
	dir, plane := newPlaneNamed(t, "approvals-"+ks)
	holdRequest(t, plane, ks, "req-"+ks, time.Now().UTC().Truncate(time.Second))
	changeView(t, dir, ks, func(v *approvals.View) {
		v.Principal, v.Agent, v.Action, v.Provider = "p-"+ks, "a-"+ks, "t-"+ks, "u-"+ks
		v.ResourceType, v.EffectClass, v.RuleIDs = "r-"+ks, "e-"+ks, []string{"rule-" + ks}
	})
	broken := ks + "B"
	if err := os.WriteFile(filepath.Join(dir, broken+".0-held.rec"), []byte("not a record"), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "pause-"+ks+".json")
	if err := pause.Init(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	lifted := ks + "L"
	for _, e := range []pause.Entry{
		{ID: lifted, Scope: pause.Scope{Kind: pause.ScopeAction, Provider: "q-" + ks, Action: pause.ActionTool, Name: "n-" + ks}, Reason: "see " + ks},
		{ID: "KEPT", Scope: pause.Scope{Kind: pause.ScopeProvider, Provider: "v-" + ks}},
	} {
		e.CreatedAt = time.Now().UTC()
		if err := pause.Add(context.Background(), file, e); err != nil {
			t.Fatal(err)
		}
	}
	s := serveAs(t, dir, file, "op-"+ks, nil)
	s.token = s.trade(t)
	return keyText{s: s, dir: dir, file: file, broken: broken, lifted: lifted}
}

// state reads the page's state.
func (s *site) state(t *testing.T) stateReply {
	t.Helper()
	var st stateReply
	decode(t, s.do(t, s.readState()), &st)
	return st
}

// notice sends a pause write and returns the notice it was answered with.
func (s *site) notice(t *testing.T, path, body string) string {
	t.Helper()
	a := s.do(t, s.write(path, body))
	var got struct{ Notice string }
	decode(t, a, &got)
	if a.status != http.StatusOK {
		t.Errorf("%s answered %d %q", path, a.status, a.body)
	}
	return got.Notice
}

// refusal sends a write the page refuses and returns the refusal's sentence.
func (s *site) refusal(t *testing.T, path, body string) string {
	t.Helper()
	a := s.do(t, s.write(path, body))
	var got struct{ Error string }
	decode(t, a, &got)
	if a.status == http.StatusOK {
		t.Errorf("%s answered %d %q, want a refusal", path, a.status, a.body)
	}
	return got.Error
}
