package console

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/brand"
)

// newSignedPlane is newPlane under the signed authority.
func newSignedPlane(t *testing.T) (string, *approvals.Plane) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "approvals")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p, err := approvals.OpenPlane(dir, approvals.WithAuthority(approvals.HeldUnderSigned))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return dir, p
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// TestASignedHoldIsShownWithTheCommandThatSignsIt: a hold under the signed
// authority is listed with its tenant, project and the two commands that
// sign it, and offers no answer.
func TestASignedHoldIsShownWithTheCommandThatSignsIt(t *testing.T) {
	dir, plane := newSignedPlane(t)
	hold(t, plane, "SIGNED1")
	s := serve(t, dir, "")
	var st stateReply
	decode(t, s.do(t, s.readState()), &st)
	if len(st.Approvals.Records) != 1 {
		t.Fatalf("the page lists %d records", len(st.Approvals.Records))
	}
	r := st.Approvals.Records[0]
	wantSign := []string{
		brand.CLI + " approvals approve --key <operator key file> --inbox <the plane's approvals.inbox_dir> -- " + dir + " SIGNED1",
		brand.CLI + " approvals reject --key <operator key file> --inbox <the plane's approvals.inbox_dir> -- " + dir + " SIGNED1",
	}
	if r.Answerable || !r.Signed || r.Tenant != "tenant-1" || r.Project != "proj-1" || !slices.Equal(r.SignWith, wantSign) {
		t.Errorf("the card is %+v", r)
	}
	if !strings.Contains(r.Status, "signed authority") || fieldValue(r, "tenant") != "tenant-1" || fieldValue(r, "sign with") != wantSign[0] {
		t.Errorf("the card says %q with fields %v", r.Status, r.Fields)
	}
}

// TestASignedHoldIsNeverAnswered: an approval or a rejection of a signed hold
// with its own digest is refused naming the signing command and writes
// nothing, and one with a stale digest is refused as stale.
func TestASignedHoldIsNeverAnswered(t *testing.T) {
	dir, plane := newSignedPlane(t)
	hold(t, plane, "SIGNED1")
	s := serve(t, dir, "")
	before := entries(t, dir)
	for _, path := range []string{"/api/approve", "/api/reject"} {
		a := s.do(t, s.write(path, s.answering(t, "SIGNED1", "")))
		if a.status != http.StatusConflict || !strings.Contains(a.body, "approvals approve --key") || !strings.Contains(a.body, "nothing was written") {
			t.Errorf("%s: %d %q, want 409 naming the signing command", path, a.status, a.body)
		}
	}
	stale := `{"id":"SIGNED1","reason":"","action_digest":"sha256:` + strings.Repeat("ab", 32) + `"}`
	if a := s.do(t, s.write("/api/approve", stale)); a.status != http.StatusConflict || !strings.Contains(a.body, digestMismatch) {
		t.Errorf("a stale digest: %d %q, want 409 %q", a.status, a.body, digestMismatch)
	}
	if got := s.stateOf(t, "SIGNED1"); got != pending || !slices.Equal(before, entries(t, dir)) {
		t.Errorf("a refused answer left the record %s and the directory %v", got, entries(t, dir))
	}
}

// TestAReaderPageRefusesThePlanesAccount: a page over a read-only handle
// refuses to start as the account owning the directory, which is the
// plane's; it refuses an approver id; and a page takes exactly one handle.
func TestAReaderPageRefusesThePlanesAccount(t *testing.T) {
	dir, plane := newSignedPlane(t)
	hold(t, plane, "SIGNED1")
	r, err := approvals.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	a, err := approvals.OpenApprover(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	base := Options{Directory: dir, Host: "127.0.0.1:8123", Token: NewToken(), Now: func() time.Time { return time.Now() }}
	for name, c := range map[string]struct {
		o    func(Options) Options
		want string
	}{
		"the plane's account": {func(o Options) Options { o.Reader = r; return o }, "the plane's"},
		"an approver id":      {func(o Options) Options { o.Reader, o.ApproverID = r, testApprover; return o }, "no approver id"},
		"both handles":        {func(o Options) Options { o.Reader, o.Approvals, o.ApproverID = r, a, testApprover; return o }, "one approvals handle"},
		"no handle":           {func(o Options) Options { return o }, "one approvals handle"},
	} {
		if _, err := New(c.o(base)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: New = %v, want a refusal naming %q", name, err, c.want)
		}
	}
	o := base
	o.Approvals, o.ApproverID = a, testApprover
	if _, err := New(o); err != nil {
		t.Errorf("a page over the approver: %v", err)
	}
}

func TestASignCommandQuotesItsWords(t *testing.T) {
	p := &page{o: Options{Directory: "-held dir", Inbox: "/var/the inbox"}}
	got := p.signCommands("ID1")[0]
	want := brand.CLI + " approvals approve --key <operator key file> --inbox '/var/the inbox' -- '-held dir' ID1"
	if got != want {
		t.Errorf("signCommands = %q, want %q", got, want)
	}
	if w := shellWord("it's"); w != `'it'\''s'` {
		t.Errorf("shellWord(it's) = %s", w)
	}
}
