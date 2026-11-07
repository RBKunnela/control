package console

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/approvals"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

// newSignedPauseFile is a signed pause file holding one global entry, g.
func newSignedPauseFile(t *testing.T) string {
	t.Helper()
	seed := sha256.Sum256([]byte("console-test/operator"))
	key := ed25519.NewKeyFromSeed(seed[:])
	s := pause.Signer{KeyID: policykey.KeyID(key.Public().(ed25519.PublicKey)), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, key)
	}, Accept: func(pause.Signed) error { return nil }}
	dir := filepath.Join(t.TempDir(), "pause")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "pause.json")
	if err := pause.InitSigned(context.Background(), file, pause.Header{KeyID: s.KeyID, Tenant: "t1", Project: "A", Serial: 1}, s); err != nil {
		t.Fatal(err)
	}
	if _, err := pause.AddSigned(context.Background(), file, pause.Entry{ID: "g", Scope: pause.Scope{Kind: pause.ScopeGlobal}, CreatedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}, s); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestASignedPauseFileIsNeverWrittenByThePage: a pause and a lift are each
// refused naming the command that signs them, and the file is byte for byte
// what it was.
func TestASignedPauseFileIsNeverWrittenByThePage(t *testing.T) {
	dir, _ := newPlane(t)
	file := newSignedPauseFile(t)
	before, err := os.ReadFile(file) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	s := serve(t, dir, file)
	for _, c := range []struct{ path, body, command string }{
		{"/api/pause", `{"scope":{"kind":"action","provider":"payments","action":"tool","name":"refund"},"reason":"card fraud"}`,
			brand.CLI + " pause add --key <operator key file> --provider payments --action tool --name refund --reason 'card fraud' -- " + file},
		{"/api/pause", `{"scope":{"kind":"run","id":"run-1"},"reason":""}`, brand.CLI + " pause add --key <operator key file> --run run-1 -- " + file},
		{"/api/unpause", `{"id":"g"}`, brand.CLI + " pause remove --key <operator key file> -- " + file + " g"},
	} {
		a := s.do(t, s.write(c.path, c.body))
		var refused struct{ Error string }
		decode(t, a, &refused)
		if a.status != http.StatusConflict || !strings.Contains(refused.Error, "nothing was written") || !strings.Contains(refused.Error, c.command) {
			t.Errorf("%s %s: %d %q, want 409 naming %q", c.path, c.body, a.status, refused.Error, c.command)
		}
	}
	if after, err := os.ReadFile(file); err != nil || string(after) != string(before) { //nolint:gosec // G304: the test's own temporary directory
		t.Errorf("a refused write changed the file: %v", err)
	}
	var st stateReply
	decode(t, s.do(t, s.readState()), &st)
	if st.Pause == nil || st.Pause.State != "paused" || len(st.Pause.Entries) != 1 {
		t.Errorf("the page shows %+v", st.Pause)
	}
}

// TestAPageUnderTheSignedAuthorityWritesNoPause: a page over the read-only
// handle writes no pause even to an unsigned file, which the control, a page
// over the approver, writes.
func TestAPageUnderTheSignedAuthorityWritesNoPause(t *testing.T) {
	dir, plane := newSignedPlane(t)
	hold(t, plane, "SIGNED1")
	r, err := approvals.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	file := newPauseFile(t)
	if p := (&page{o: Options{Reader: r, PauseFile: file}}); !p.writesNoPause() {
		t.Error("a page over the reader would write an unsigned pause file")
	}
	if p := (&page{o: Options{PauseFile: file}}); p.writesNoPause() {
		t.Error("a page over the approver would not write an unsigned pause file")
	}
	if p := (&page{o: Options{PauseFile: newSignedPauseFile(t)}}); !p.writesNoPause() {
		t.Error("a page over the approver would write a signed pause file")
	}
}
