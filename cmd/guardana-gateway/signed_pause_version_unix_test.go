//go:build unix

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/policystate"
)

// pauseV3 is a version 3 pause file, which names no plane, of h over d,
// signed by s: the version 4 body with its plane_id cut out.
func pauseV3(t *testing.T, s pause.Signer, h pause.Header, d pause.Document) []byte {
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
		t.Fatalf("the version 4 body is not spelled as pauseV3 expects: %s", body)
	}
	sig, err := s.Sign(pause.PayloadType, cut)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := policykey.MarshalEnvelope(policy.StatementEnvelope{PayloadType: pause.PayloadType, Payload: cut,
		Signatures: []policy.StatementSignature{{KeyID: s.KeyID, Signature: sig}}}, pause.MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// initAgain replaces the pause file at file with an empty one alice signs
// as h, and returns the bytes it held.
func initAgain(t *testing.T, file string, h pause.Header) []byte {
	t.Helper()
	held, err := os.ReadFile(file) //nolint:gosec // G304: a file under the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := pause.InitSigned(t.Context(), file, h, aliceSigner()); err != nil {
		t.Fatal(err)
	}
	return held
}

// TestASignedPlaneRefusesAnOlderVersionOrAnotherPlanesPause: a version 3
// file, and a version 4 file alice signed for another plane at this path,
// are unknown, which blocks every call, and leave the floor where the
// plane's own file left it; the version 3 refusal names pause sign, and a
// restart over it is refused naming it too.
func TestASignedPlaneRefusesAnOlderVersionOrAnotherPlanesPause(t *testing.T) {
	tr := signedPauseTree(t)
	file := filepath.Join(tr.dir, "pause", "pause.json")
	floor := filepath.Join(tr.dir, "pausefloor")
	p, err := buildOneAccount(t, tr)
	if err != nil {
		t.Fatal(err)
	}
	polled(t, p, "the plane's own file", pause.Clear, "")
	bound, err := pause.BindingOf(file)
	if err != nil {
		t.Fatal(err)
	}
	global := pause.Document{Entries: []pause.Entry{{ID: "g", Scope: pause.Scope{Kind: pause.ScopeGlobal}, CreatedAt: time.Now().UTC().Truncate(time.Second)}}}
	h := pause.Header{KeyID: aliceSigner().KeyID, PlaneID: "plane-b", Tenant: "acme", Project: "orders", File: bound, Serial: 4}
	other := initAgain(t, file, h)
	polled(t, p, "plane-b's file at this path", pause.Unknown, pause.CauseOtherFile)
	writeTestFile(t, file, pauseV3(t, aliceSigner(), pause.Header{KeyID: h.KeyID, Tenant: "acme", Project: "orders", File: bound, Serial: 5}, global))
	s := p.poller.Poll()
	if s.State() != pause.Unknown || s.Cause() != pause.CauseVersion || !strings.Contains(s.Detail(), "pause sign --plane-id") {
		t.Errorf("a version 3 file polled = %s, %q: %s; want unknown, %q, naming pause sign", s.State(), s.Cause(), s.Detail(), pause.CauseVersion)
	}
	if f, err := policystate.ReadPause(floor, "acme", "orders"); err != nil || f.Serial != 1 {
		t.Errorf("the refusals moved the floor to %+v, %v", f, err)
	}
	if err := p.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := buildOneAccount(t, tr); !errors.Is(err, pause.ErrNotServable) || !strings.Contains(err.Error(), "pause sign") {
		t.Errorf("a restart over a version 3 file = %v, want a refusal naming pause sign", err)
	}
	writeTestFile(t, file, other)
	if _, err := buildOneAccount(t, tr); err != nil {
		t.Errorf("the control, a restart over the plane's own file = %v", err)
	}
}
