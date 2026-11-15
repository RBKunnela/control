package signedpause_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/pause/signedpause"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
)

// floorSerial is the serial of the pause floor in dir, or 0 where it holds
// none.
func floorSerial(t *testing.T, dir string) int64 {
	t.Helper()
	f, err := policystate.ReadPause(dir, "t1", "A")
	if err != nil {
		t.Fatal(err)
	}
	return f.Serial
}

// TestTheJudgeRefusesADocumentOfAnotherBinding: a document that differs
// from the plane's in its tenant, project, pause file or plane id alone, or
// that names no plane, is refused by the judge and by doctor's check alike,
// and raises no floor; the control, the plane's own, is taken by both.
func TestTheJudgeRefusesADocumentOfAnotherBinding(t *testing.T) {
	p := newPlane(t)
	j := p.judge(t)
	b, err := signedpause.NewBinding(planeID, "t1", "A", p.file)
	if err != nil {
		t.Fatal(err)
	}
	own := pause.Header{KeyID: keyID("alice"), PlaneID: planeID, Tenant: "t1", Project: "A", File: p.bound, Serial: 1}
	other, err := pause.BindingOf(filepath.Join(t.TempDir(), "pause.json"))
	if err != nil {
		t.Fatal(err)
	}
	noPlane := signedHeader(t, "alice", own, global)
	noPlane.Body.PlaneID = ""
	for _, c := range []struct {
		name   string
		change func(*pause.Header)
		f      *pause.Signed
		want   pause.Error
	}{
		{"another tenant", func(h *pause.Header) { h.Tenant = "t2" }, nil, pause.ErrOtherScope},
		{"another project", func(h *pause.Header) { h.Project = "B" }, nil, pause.ErrOtherScope},
		{"another pause file", func(h *pause.Header) { h.File = other }, nil, pause.ErrOtherFile},
		{"another plane", func(h *pause.Header) { h.PlaneID = "plane-b" }, nil, pause.ErrOtherPlane},
		{"a plane id differing in case", func(h *pause.Header) { h.PlaneID = "Plane-a" }, nil, pause.ErrOtherPlane},
		{"no plane", nil, &noPlane, pause.ErrOtherPlane},
	} {
		f := c.f
		if f == nil {
			h := own
			c.change(&h)
			signed := signedHeader(t, "alice", h, global)
			f = &signed
		}
		by, err := j.Judge(t.Context(), *f)
		wantRefused(t, c.name, by, err, c.want)
		if _, err := b.Vouched(p.roster, *f); !errors.Is(err, c.want) {
			t.Errorf("%s: doctor's check = %v, want %v", c.name, err, c.want)
		}
	}
	if n := floorSerial(t, p.floor); n != 0 {
		t.Errorf("the refusals raised the floor to %d", n)
	}
	if subject, err := b.Vouched(p.roster, signedHeader(t, "alice", own, global)); err != nil || subject != "alice" {
		t.Errorf("the control, doctor's check of the plane's own = %q, %v", subject, err)
	}
	if _, err := j.Judge(t.Context(), signedHeader(t, "alice", own, global)); err != nil {
		t.Errorf("the control, the plane's own = %v", err)
	}
	var zero signedpause.Binding
	if err := zero.Check(own); !errors.Is(err, pause.ErrOtherScope) {
		t.Errorf("a binding no one made = %v, want a refusal", err)
	}
	if _, err := signedpause.NewBinding("", "t1", "A", p.file); !errors.Is(err, pause.ErrOptions) {
		t.Errorf("a binding with no plane id = %v, want ErrOptions", err)
	}
}

// TestACopyBetweenTwoPlanesOfOneProjectIsRefused: two planes reading one
// path for the same tenant and project, told apart by their ids alone: what
// alice signed for one is refused by the other, whose floor stays as it
// was, and taken by its own.
func TestACopyBetweenTwoPlanesOfOneProjectIsRefused(t *testing.T) {
	p := newPlane(t)
	floorB := filepath.Join(t.TempDir(), "pausefloor-b")
	if err := policystate.InitPause(t.Context(), floorB, "t1", "A"); err != nil {
		t.Fatal(err)
	}
	b, err := signedpause.New(p.authn, p.authz, "plane-b", "t1", "A", p.file, floorB)
	if err != nil {
		t.Fatal(err)
	}
	forA := p.byAlice(4, global)(t)
	by, err := b.Judge(t.Context(), forA)
	wantRefused(t, "plane-a's document on plane-b", by, err, pause.ErrOtherPlane)
	if n := floorSerial(t, floorB); n != 0 {
		t.Errorf("plane-b's floor = %d after the refusal", n)
	}
	if by, err := p.judge(t).Judge(t.Context(), forA); err != nil || by.Floor != 4 {
		t.Errorf("the control, plane-a's own judge = %+v, %v", by, err)
	}
}

// writeV3 writes a version 3 file of h over d, which names no plane, signed
// by the key called by: the version 4 body with its plane_id cut out.
func writeV3(t *testing.T, path, by string, h pause.Header, d pause.Document) {
	t.Helper()
	const placeholder = "v3-placeholder"
	h.PlaneID = placeholder
	body, err := pause.MarshalSigned(h, d)
	if err != nil {
		t.Fatal(err)
	}
	cut := bytes.Replace(body, []byte(`"plane_id":"`+placeholder+`",`), nil, 1)
	cut = bytes.Replace(cut, []byte(`"schema_version":"4"`), []byte(`"schema_version":"3"`), 1)
	if bytes.Contains(cut, []byte("plane_id")) || !bytes.Contains(cut, []byte(`"schema_version":"3"`)) {
		t.Fatalf("the version 4 body is not spelled as writeV3 expects: %s", body)
	}
	sig, err := bundle.SignBytesAs(pause.PayloadType, cut, key(by))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := policykey.MarshalEnvelope(policy.StatementEnvelope{PayloadType: pause.PayloadType, Payload: cut,
		Signatures: []policy.StatementSignature{{KeyID: h.KeyID, Signature: sig}}}, pause.MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o640); err != nil { //nolint:gosec // G306: the mode a signed write leaves
		t.Fatal(err)
	}
}

// signedPoller is a poller under p's judge of p's pause file, which alice
// signed empty for the plane at serial 1, past its first read, which took
// it and raised the floor to 1.
func signedPoller(t *testing.T, p *plane) *pause.Poller {
	t.Helper()
	if err := pause.InitSigned(t.Context(), p.file, pause.Header{KeyID: keyID("alice"), PlaneID: planeID, Tenant: "t1", Project: "A", Serial: 1}, p.operator()); err != nil {
		t.Fatal(err)
	}
	poller, err := pause.Open(pause.Options{Path: p.file, Interval: time.Minute, Clock: func() time.Time { return now }, Judge: p.judge(t), PlaneOwned: true})
	if err != nil {
		t.Fatal(err)
	}
	if s := poller.Current(); s.State() != pause.Clear || floorSerial(t, p.floor) != 1 {
		t.Fatalf("the first read = %s, %q: %s", s.State(), s.Cause(), s.Detail())
	}
	return poller
}

// TestAVersion3FileBlocksUntilItIsSignedAgain: a plane polling its pause
// file finds a version 3 file at a higher serial: the read is unknown,
// which blocks every call, it names pause sign, and the floor stays where
// the last file the plane took left it. Signed again for the plane, the
// same two entries pause and the floor rises past both.
func TestAVersion3FileBlocksUntilItIsSignedAgain(t *testing.T) {
	p := newPlane(t)
	poller := signedPoller(t, p)
	two := pause.Document{Entries: []pause.Entry{
		{ID: "g", Scope: pause.Scope{Kind: pause.ScopeGlobal}, CreatedAt: now},
		{ID: "a", Scope: pause.Scope{Kind: pause.ScopeAgent, ID: "agent-1"}, CreatedAt: now},
	}}
	writeV3(t, p.file, "alice", pause.Header{KeyID: keyID("alice"), Tenant: "t1", Project: "A", File: p.bound, Serial: 5}, two)
	s := poller.Poll()
	if s.State() != pause.Unknown || s.Cause() != pause.CauseVersion || !strings.Contains(s.Detail(), "pause sign --plane-id") {
		t.Errorf("a version 3 file polled = %s, %q: %s; want unknown, %q, naming pause sign", s.State(), s.Cause(), s.Detail(), pause.CauseVersion)
	}
	if n := floorSerial(t, p.floor); n != 1 {
		t.Errorf("the refused version 3 file moved the floor to %d", n)
	}
	got, err := pause.Resign(t.Context(), p.file, planeID, p.operator())
	if err != nil || got.Serial != 6 {
		t.Fatalf("Resign = %+v, %v", got.Header, err)
	}
	s = poller.Poll()
	if s.State() != pause.Paused || len(s.Entries()) != 2 || floorSerial(t, p.floor) != 6 {
		t.Errorf("the file signed again polled = %s, %q: %s, %d entries, floor %d", s.State(), s.Cause(), s.Detail(), len(s.Entries()), floorSerial(t, p.floor))
	}
}
