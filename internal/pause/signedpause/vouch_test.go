package signedpause_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/pause/signedpause"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

// TestADocumentForAnotherPlanesFileIsRefused: a document alice signed for
// another plane's pause file, of the same tenant and project, is refused by
// this plane's judge; the control, the same one for this plane's file, is
// taken.
func TestADocumentForAnotherPlanesFileIsRefused(t *testing.T) {
	p := newPlane(t)
	other, err := pause.BindingOf(filepath.Join(t.TempDir(), "pause.json"))
	if err != nil {
		t.Fatal(err)
	}
	by, err := p.judge(t).Judge(t.Context(), signedFor(t, "alice", "alice", "t1", "A", other, 1, global))
	wantRefused(t, "a document for another plane's file", by, err, pause.ErrOtherFile)
	if _, err := p.judge(t).Judge(t.Context(), p.byAlice(1, global)(t)); err != nil {
		t.Errorf("the control, a document for this plane's file: %v", err)
	}
}

func TestVouchedTakesOnlyARosterOperatorsGrantedSignature(t *testing.T) {
	p := newPlane(t)
	if subject, err := signedpause.Vouched(p.roster, p.byAlice(1, global)(t)); err != nil || subject != "alice" {
		t.Fatalf("alice's document = %q, %v", subject, err)
	}
	for _, c := range []struct {
		name string
		f    pause.Signed
		want pause.Error
	}{
		{"bob, who only reads A", p.signed(t, "bob", "bob", "t1", "A", 1, global), pause.ErrUnauthorized},
		{"carol, for A, which she does not operate", p.signed(t, "carol", "carol", "t1", "A", 1, global), pause.ErrUnauthorized},
		{"a key the roster does not name", p.signed(t, "mallory", "mallory", "t1", "A", 1, global), pause.ErrUnauthenticated},
		{"mallory under alice's key id", p.signed(t, "mallory", "alice", "t1", "A", 1, global), pause.ErrUnauthenticated},
	} {
		if _, err := signedpause.Vouched(p.roster, c.f); !errors.Is(err, c.want) {
			t.Errorf("%s = %v, want %v", c.name, err, c.want)
		}
	}
	relabelled := p.byAlice(1, global)(t)
	relabelled.Envelope.PayloadType = "application/vnd.agent-approval-answer+json"
	if _, err := signedpause.Vouched(p.roster, relabelled); !errors.Is(err, pause.ErrUnauthenticated) {
		t.Errorf("a relabelled envelope = %v", err)
	}
}

// writeAs writes a document of h over d signed by the key called by into the
// pause file at path, as anyone who may write the file can.
func writeAs(t *testing.T, path, by string, h pause.Header, d pause.Document) {
	t.Helper()
	body, err := pause.MarshalSigned(h, d)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bundle.SignBytesAs(pause.PayloadType, body, key(by))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := policykey.MarshalEnvelope(policy.StatementEnvelope{PayloadType: pause.PayloadType, Payload: body,
		Signatures: []policy.StatementSignature{{KeyID: h.KeyID, Signature: sig}}}, pause.MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o640); err != nil { //nolint:gosec // G306: the mode a signed write leaves
		t.Fatal(err)
	}
}

// operator is alice's signer, judging what a write starts from against the
// plane's roster, as the pause commands do.
func (p *plane) operator() pause.Signer {
	return pause.Signer{KeyID: keyID("alice"), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, key("alice"))
	}, Accept: func(f pause.Signed) error {
		_, err := signedpause.Vouched(p.roster, f)
		return err
	}}
}

// TestAWriterSignsNoEntriesSomeoneWithoutARosterKeyPutThere: a file a writer
// of the pause file signed with no roster key, at any serial, the highest
// but one among them, is refused before anything is signed, and the global
// pause alice signed is never lifted under her signature.
func TestAWriterSignsNoEntriesSomeoneWithoutARosterKeyPutThere(t *testing.T) {
	p := newPlane(t)
	g := pause.Entry{ID: "g", Scope: pause.Scope{Kind: pause.ScopeGlobal}, CreatedAt: now}
	other := pause.Entry{ID: "x", Scope: pause.Scope{Kind: pause.ScopeAgent, ID: "agent-1"}, CreatedAt: now}
	for _, serial := range []int64{3, policy.MaxSerial - 1} {
		if err := os.Remove(p.file); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if err := pause.InitSigned(t.Context(), p.file, pause.Header{KeyID: keyID("alice"), Tenant: "t1", Project: "A", Serial: 1}, p.operator()); err != nil {
			t.Fatal(err)
		}
		if _, err := pause.AddSigned(t.Context(), p.file, g, p.operator()); err != nil {
			t.Fatal(err)
		}
		writeAs(t, p.file, "mallory", pause.Header{KeyID: keyID("mallory"), Tenant: "t1", Project: "A", File: p.bound, Serial: serial}, pause.Document{})
		before, err := os.ReadFile(p.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pause.AddSigned(t.Context(), p.file, other, p.operator()); !errors.Is(err, pause.ErrNotVouched) {
			t.Errorf("serial %d: alice's add over mallory's file = %v, want ErrNotVouched", serial, err)
		}
		if _, err := pause.RemoveSigned(t.Context(), p.file, "x", p.operator()); !errors.Is(err, pause.ErrNotVouched) {
			t.Errorf("serial %d: alice's removal over mallory's file = %v, want ErrNotVouched", serial, err)
		}
		if now, _ := os.ReadFile(p.file); string(now) != string(before) {
			t.Errorf("serial %d: a refused write changed the file", serial)
		}
	}
}

// TestAnOlderFileAWriterSignsAgainNeverPassesTheFloor: an older document
// alice signed, put back, is one the roster vouches for, so a writer signs
// it again at the serial after its own; that serial is at or below the
// floor the plane raised past it, so the plane refuses it.
func TestAnOlderFileAWriterSignsAgainNeverPassesTheFloor(t *testing.T) {
	p := newPlane(t)
	j := p.judge(t)
	if err := pause.InitSigned(t.Context(), p.file, pause.Header{KeyID: keyID("alice"), Tenant: "t1", Project: "A", Serial: 1}, p.operator()); err != nil {
		t.Fatal(err)
	}
	older, err := os.ReadFile(p.file)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"g", "h"} {
		if _, err := pause.AddSigned(t.Context(), p.file, pause.Entry{ID: id, Scope: pause.Scope{Kind: pause.ScopeGlobal}, CreatedAt: now}, p.operator()); err != nil {
			t.Fatal(err)
		}
	}
	signedAt3, err := pause.List(p.file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Judge(t.Context(), p.byAlice(3, signedAt3.Document)(t)); err != nil {
		t.Fatalf("the plane takes serial 3: %v", err)
	}
	if err := os.WriteFile(p.file, older, 0o640); err != nil { //nolint:gosec // G306: the mode a signed write leaves
		t.Fatal(err)
	}
	resigned, err := pause.AddSigned(t.Context(), p.file, pause.Entry{ID: "x", Scope: pause.Scope{Kind: pause.ScopeAgent, ID: "agent-1"}, CreatedAt: now}, p.operator())
	if err != nil || resigned.Serial != 2 {
		t.Fatalf("the writer over serial 1 = %+v, %v; want serial 2", resigned, err)
	}
	l, err := pause.List(p.file)
	if err != nil {
		t.Fatal(err)
	}
	by, err := j.Judge(t.Context(), p.byAlice(l.Signed.Serial, l.Document)(t))
	wantRefused(t, "serial 2 signed again over serial 1 put back", by, err, pause.ErrBelowFloor)
}
