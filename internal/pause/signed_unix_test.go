//go:build unix

package pause

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
)

func testKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("pause-test/" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func testPublic(name string) ed25519.PublicKey { return testKey(name).Public().(ed25519.PublicKey) }

func testKeyID(name string) string { return policykey.KeyID(testPublic(name)) }

// signer signs as the key called name, under its own id, and accepts every
// signed file a write starts from.
func signer(name string) Signer {
	return Signer{KeyID: testKeyID(name), Sign: func(payloadType string, body []byte) ([]byte, error) {
		return bundle.SignBytesAs(payloadType, body, testKey(name))
	}, Accept: func(Signed) error { return nil }}
}

// judgeFunc is a Judge of the test's making.
type judgeFunc func(Signed) (SignedBy, error)

func (f judgeFunc) Judge(_ context.Context, s Signed) (SignedBy, error) { return f(s) }

// takes is a judge that takes every signed file, as its signer.
var takes = judgeFunc(func(s Signed) (SignedBy, error) {
	return SignedBy{Subject: "alice", KeyID: s.Body.KeyID, Serial: s.Body.Serial, Floor: s.Body.Serial}, nil
})

var signedNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// signedPlane is a pause file in a directory of its own, as an operator
// writes it for a plane under the signed authority.
type signedPlane struct{ path string }

func newSignedPlane(t *testing.T) *signedPlane {
	t.Helper()
	p := &signedPlane{path: filepath.Join(t.TempDir(), "pause", "pause.json")}
	if err := os.Mkdir(filepath.Dir(p.path), 0o750); err != nil {
		t.Fatal(err)
	}
	return p
}

var globalEntry = Entry{ID: "g", Scope: Scope{Kind: ScopeGlobal}, CreatedAt: signedNow, Reason: "stop"}

// write puts a document of h over d, signed by the key called by, in the
// pause file, replacing what stands there.
func (p *signedPlane) write(t *testing.T, by string, h Header, d Document) {
	t.Helper()
	raw, err := signFile(h, d, signer(by))
	if err != nil {
		t.Fatal(err)
	}
	p.writeRaw(t, raw)
}

func (p *signedPlane) writeRaw(t *testing.T, raw []byte) {
	t.Helper()
	if err := os.WriteFile(p.path+".tmp", raw, 0o640); err != nil { //nolint:gosec // G306: the mode a signed write leaves, which the plane reads through the group
		t.Fatal(err)
	}
	if err := os.Rename(p.path+".tmp", p.path); err != nil {
		t.Fatal(err)
	}
}

// header is a header of t1/A at serial signed by the key called by, bound to
// a pause file no test writes; p.header binds it to p's.
func header(by string, serial int64) Header {
	return Header{KeyID: testKeyID(by), Tenant: "t1", Project: "A", File: "/srv/pause/pause.json", Serial: serial}
}

func (p *signedPlane) header(t *testing.T, by string, serial int64) Header {
	t.Helper()
	file, err := BindingOf(p.path)
	if err != nil {
		t.Fatal(err)
	}
	h := header(by, serial)
	h.File = file
	return h
}

var paused = Document{Entries: []Entry{globalEntry}}

// read reads the file as a plane would under j, its account another than the
// one that owns the file.
func (p *signedPlane) read(t *testing.T, j Judge) Snapshot {
	t.Helper()
	actAs(t, os.Geteuid()+1)
	return ReadSigned(t.Context(), p.path, signedNow, time.Second, j)
}

func wantUnknown(t *testing.T, what string, s Snapshot, cause Cause) {
	t.Helper()
	if s.State() != Unknown || s.Cause() != cause {
		t.Errorf("%s = %s, %q: %s; want unknown, %q", what, s.State(), s.Cause(), s.Detail(), cause)
	}
	if _, ok := s.SignedBy(); ok {
		t.Errorf("%s names a signer though unknown", what)
	}
}

func TestASignedFileAJudgeTakesPausesAndNamesItsSigner(t *testing.T) {
	p := newSignedPlane(t)
	p.write(t, "alice", header("alice", 1), paused)
	var judged Signed
	s := p.read(t, judgeFunc(func(f Signed) (SignedBy, error) { judged = f; return takes(f) }))
	if s.State() != Paused || !s.Covers("tool", "u", "x", Vouched{}) {
		t.Fatalf("the read = %s, %q: %s; want paused", s.State(), s.Cause(), s.Detail())
	}
	if by, ok := s.SignedBy(); !ok || by.Subject != "alice" || by.Serial != 1 {
		t.Errorf("SignedBy = %+v, %v", by, ok)
	}
	if judged.Envelope.PayloadType != PayloadType || len(judged.Envelope.Signatures) != 1 || judged.Body.Header != header("alice", 1) {
		t.Errorf("the judge was handed %+v", judged)
	}
	p.write(t, "alice", header("alice", 2), Document{})
	if s := p.read(t, takes); s.State() != Clear {
		t.Errorf("the lift = %s, %q: %s; want clear", s.State(), s.Cause(), s.Detail())
	}
}

// TestEveryRefusalOfTheJudgeIsUnknownWithItsCause: none reads as a file that
// pauses nothing.
func TestEveryRefusalOfTheJudgeIsUnknownWithItsCause(t *testing.T) {
	p := newSignedPlane(t)
	p.write(t, "alice", header("alice", 1), Document{})
	for _, c := range []struct {
		err   Error
		cause Cause
	}{
		{ErrUnauthenticated, CauseUnauthenticated}, {ErrOtherScope, CauseOtherScope}, {ErrUnauthorized, CauseUnauthorized},
		{ErrAuthority, CauseAuthority}, {ErrBelowFloor, CauseBelowFloor}, {ErrForked, CauseForked}, {ErrFloor, CauseFloor},
	} {
		refuses := judgeFunc(func(Signed) (SignedBy, error) { return SignedBy{}, fmt.Errorf("%w: why", c.err) })
		wantUnknown(t, string(c.cause), p.read(t, refuses), c.cause)
	}
	if s := ReadSigned(t.Context(), p.path, signedNow, time.Second, nil); s.State() != Unknown {
		t.Errorf("a signed read with no judge = %s", s.State())
	}
}

func TestAnUnsignedOrTamperedFileUnderSignedIsUnknown(t *testing.T) {
	p := newSignedPlane(t)
	p.writeRaw(t, []byte(`{"schema_version":"2","entries":[]}`))
	wantUnknown(t, "a version 2 file", p.read(t, takes), CauseUnsigned)
	p.writeRaw(t, []byte(`{"schema_version":"1","entries":[]}`))
	wantUnknown(t, "a version 1 file", p.read(t, takes), CauseUnsigned)
	raw, err := signFile(header("alice", 1), paused, signer("alice"))
	if err != nil {
		t.Fatal(err)
	}
	p.writeRaw(t, append([]byte(" "), raw...))
	if s := p.read(t, takes); s.State() != Paused {
		t.Errorf("the control, a file led by white space: %s, %q: %s", s.State(), s.Cause(), s.Detail())
	}
	env, err := parseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	env.PayloadType = "application/vnd.agent-approval-answer+json"
	other, err := marshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	p.writeRaw(t, other)
	wantUnknown(t, "a signed file of another payload type", p.read(t, takes), CauseMalformed)
	env.PayloadType = PayloadType
	env.Signatures = append(env.Signatures, env.Signatures[0])
	twice, err := marshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	p.writeRaw(t, twice)
	wantUnknown(t, "a signed file of two signatures", p.read(t, takes), CauseMalformed)
}

// TestAPollerUnderSignedNeverUnpausesOnARefusal: a refusal after a pause
// leaves the poller Unknown, which blocks, and never Clear.
func TestAPollerUnderSignedNeverUnpausesOnARefusal(t *testing.T) {
	p := newSignedPlane(t)
	p.write(t, "alice", header("alice", 1), paused)
	refuse := false
	j := judgeFunc(func(f Signed) (SignedBy, error) {
		if refuse {
			return SignedBy{}, ErrUnauthorized
		}
		return takes(f)
	})
	actAs(t, os.Geteuid()+1)
	poller, err := Open(Options{Path: p.path, Interval: time.Second, Clock: func() time.Time { return signedNow }, Judge: j})
	if err != nil {
		t.Fatal(err)
	}
	if s := poller.Current(); s.State() != Paused {
		t.Fatalf("the first read = %s", s.State())
	}
	refuse = true
	p.write(t, "bob", header("bob", 2), Document{})
	wantUnknown(t, "a refused lift polled", poller.Poll(), CauseUnauthorized)
	if n := poller.Stats().Failed[CauseUnauthorized]; n != 1 {
		t.Errorf("the failures counted under %q = %d, want 1", CauseUnauthorized, n)
	}
	if _, err := Open(Options{Path: p.path, Interval: time.Second, Clock: func() time.Time { return signedNow }, Judge: j}); !errors.Is(err, ErrNotServable) {
		t.Errorf("a start on a refused file = %v, want ErrNotServable", err)
	}
}

// TestASignedPlaneRefusesAFileItsOwnAccountOwns: the directory, then the
// file, owned by the plane's account are refused at every read, the judge
// never asked; read as another account they pause; a poller of a dev plane,
// whose one account is the operator's too, takes them; a file or directory
// the group may write is refused whoever owns it.
func TestASignedPlaneRefusesAFileItsOwnAccountOwns(t *testing.T) {
	p := newSignedPlane(t)
	p.write(t, "alice", header("alice", 1), paused)
	me, other := os.Geteuid(), os.Geteuid()+1
	asked := false
	j := judgeFunc(func(f Signed) (SignedBy, error) { asked = true; return takes(f) })
	for _, c := range []struct {
		name string
		uids []int
	}{{"the directory", []int{me}}, {"the file", []int{other, me}}} {
		actAs(t, c.uids...)
		s := ReadSigned(t.Context(), p.path, signedNow, time.Second, j)
		wantUnknown(t, c.name+" owned by the plane's account", s, CausePlaneOwned)
		if !strings.Contains(s.Detail(), c.name) {
			t.Errorf("%s: the detail %q does not name it", c.name, s.Detail())
		}
	}
	if asked {
		t.Error("the judge was asked about a file the plane's account owns")
	}
	if s := p.read(t, takes); s.State() != Paused {
		t.Errorf("read as another account: %s, %q: %s", s.State(), s.Cause(), s.Detail())
	}
	actAs(t, me)
	for _, planeOwned := range []bool{false, true} {
		poller, err := Open(Options{Path: p.path, Interval: time.Second, Clock: func() time.Time { return signedNow }, Judge: takes, PlaneOwned: planeOwned})
		if (err == nil) != planeOwned || (planeOwned && poller.Current().State() != Paused) {
			t.Errorf("a poller with PlaneOwned %v over the plane's own file: %v", planeOwned, err)
		}
	}
	actAs(t, other)
	if err := os.Chmod(p.path, 0o660); err != nil { //nolint:gosec // G302: the group-writable file under test
		t.Fatal(err)
	}
	wantUnknown(t, "a file the group may write", p.read(t, takes), CauseFileMode)
	if err := os.Chmod(p.path, 0o640); err != nil { //nolint:gosec // G302: the mode a signed write leaves
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(p.path), 0o770); err != nil { //nolint:gosec // G302: the group-writable directory under test
		t.Fatal(err)
	}
	wantUnknown(t, "a directory the group may write", p.read(t, takes), CauseDirMode)
}

func TestAnUnsignedPlaneReadsNoSignedFile(t *testing.T) {
	p := newSignedPlane(t)
	p.write(t, "alice", header("alice", 1), paused)
	s := Read(p.path, signedNow, time.Second)
	if s.State() != Unknown || s.Cause() != CauseSignedFile {
		t.Errorf("Read of a signed file = %s, %q, want unknown, %q", s.State(), s.Cause(), CauseSignedFile)
	}
}

func TestTheSignedWriterRaisesTheSerialAndKeepsTheScope(t *testing.T) {
	p := newSignedPlane(t)
	ctx := t.Context()
	if err := InitSigned(ctx, p.path, header("alice", 1), signer("alice")); err != nil {
		t.Fatal(err)
	}
	if _, err := AddSigned(ctx, p.path, globalEntry, signer("carol")); err != nil {
		t.Fatal(err)
	}
	wantListed(t, "after the add", p.path, p.header(t, "carol", 2), 1)
	if info, err := os.Stat(p.path); err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("the signed file's mode = %v, %v; want 0640, which the plane's account reads through the group", info.Mode().Perm(), err)
	}
	if _, err := RemoveSigned(ctx, p.path, "g", signer("alice")); err != nil {
		t.Fatal(err)
	}
	wantListed(t, "after the removal", p.path, p.header(t, "alice", 3), 0)
}

// wantListed fails unless the file at path lists under h with n entries.
func wantListed(t *testing.T, what, path string, h Header, n int) {
	t.Helper()
	if l, err := List(path); err != nil || l.Signed == nil || l.Signed.Header != h || len(l.Entries) != n {
		t.Errorf("%s the file lists %+v, %v; want %+v and %d entries", what, l, err, h, n)
	}
}

// TestTheSignedWriterRefusesAWriteOfTheOtherKind: an unsigned write to a
// signed file, a signed one to an unsigned file, and a signer that cannot
// sign.
func TestTheSignedWriterRefusesAWriteOfTheOtherKind(t *testing.T) {
	p := newSignedPlane(t)
	ctx := t.Context()
	if err := InitSigned(ctx, p.path, header("alice", 1), signer("alice")); err != nil {
		t.Fatal(err)
	}
	if err := InitSigned(ctx, p.path, header("alice", 1), signer("alice")); !errors.Is(err, ErrExists) {
		t.Errorf("InitSigned over a file = %v, want ErrExists", err)
	}
	if err := Add(ctx, p.path, globalEntry); !errors.Is(err, ErrSigned) {
		t.Errorf("an unsigned add to a signed file = %v, want ErrSigned", err)
	}
	if err := Remove(ctx, p.path, "g"); !errors.Is(err, ErrSigned) {
		t.Errorf("an unsigned removal from a signed file = %v, want ErrSigned", err)
	}
	if _, err := AddSigned(ctx, p.path, globalEntry, Signer{KeyID: testKeyID("alice")}); !errors.Is(err, ErrSigner) {
		t.Errorf("a signer that cannot sign = %v, want ErrSigner", err)
	}
	unsigned := filepath.Join(filepath.Dir(p.path), "unsigned.json")
	if err := Init(ctx, unsigned); err != nil {
		t.Fatal(err)
	}
	if _, err := AddSigned(ctx, unsigned, globalEntry, signer("alice")); !errors.Is(err, ErrUnsigned) {
		t.Errorf("a signed add to an unsigned file = %v, want ErrUnsigned", err)
	}
}

// TestTheSignedWriterSignsOnlyAFileItsSignerAccepts: a file Accept refuses is
// left as it was and nothing is signed; a signer with no Accept signs
// nothing; the control, a file it accepts, is signed at the next serial.
func TestTheSignedWriterSignsOnlyAFileItsSignerAccepts(t *testing.T) {
	p := newSignedPlane(t)
	if err := InitSigned(t.Context(), p.path, header("alice", 1), signer("alice")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p.path)
	if err != nil {
		t.Fatal(err)
	}
	var judged Signed
	refuses := signer("alice")
	refuses.Accept = func(f Signed) error { judged = f; return errors.New("not the roster's") }
	if _, err := AddSigned(t.Context(), p.path, globalEntry, refuses); !errors.Is(err, ErrNotVouched) {
		t.Errorf("an add over a file the signer refuses = %v, want ErrNotVouched", err)
	}
	if judged.Body.Header != p.header(t, "alice", 1) {
		t.Errorf("Accept was handed %+v, not the file the write starts from", judged.Body.Header)
	}
	none := signer("alice")
	none.Accept = nil
	if _, err := RemoveSigned(t.Context(), p.path, "g", none); !errors.Is(err, ErrSigner) {
		t.Errorf("a signer that judges nothing = %v, want ErrSigner", err)
	}
	if now, _ := os.ReadFile(p.path); string(now) != string(before) {
		t.Error("a refused write changed the file")
	}
	got, err := AddSigned(t.Context(), p.path, globalEntry, signer("alice"))
	if err != nil || got.Header != p.header(t, "alice", 2) || len(got.Entries) != 1 {
		t.Errorf("the control = %+v, %v", got, err)
	}
}

// TestASignedFileIsBoundToItsOwnPath: a signed file copied from one path to
// another is refused by the writer at the second.
func TestASignedFileIsBoundToItsOwnPath(t *testing.T) {
	a, b := newSignedPlane(t), newSignedPlane(t)
	if err := InitSigned(t.Context(), a.path, header("alice", 1), signer("alice")); err != nil {
		t.Fatal(err)
	}
	if l, err := List(a.path); err != nil || l.Signed.File != a.header(t, "alice", 1).File {
		t.Fatalf("the file names %+v, %v; want its own path", l.Signed, err)
	}
	raw, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	b.writeRaw(t, raw)
	if _, err := AddSigned(t.Context(), b.path, globalEntry, signer("alice")); !errors.Is(err, ErrOtherFile) {
		t.Errorf("an add to a copy of another path's file = %v, want ErrOtherFile", err)
	}
	if _, err := AddSigned(t.Context(), a.path, globalEntry, signer("alice")); err != nil {
		t.Errorf("the control, an add at the file's own path = %v", err)
	}
}

// TestTheSignedWriterRefusesAFileThatChangedUnderIt: a writer that skipped
// the lock replaced the file between this writer's read and its replace.
func TestTheSignedWriterRefusesAFileThatChangedUnderIt(t *testing.T) {
	p := newSignedPlane(t)
	if err := InitSigned(t.Context(), p.path, header("alice", 1), signer("alice")); err != nil {
		t.Fatal(err)
	}
	theirs, err := signFile(p.header(t, "alice", 2), paused, signer("alice"))
	if err != nil {
		t.Fatal(err)
	}
	beforeReplace = func() { p.writeRaw(t, theirs) }
	t.Cleanup(func() { beforeReplace = nil })
	if _, err := RemoveSigned(t.Context(), p.path, "none", signer("alice")); !errors.Is(err, ErrNoEntry) {
		t.Fatalf("a removal of no entry = %v", err)
	}
	_, err = AddSigned(t.Context(), p.path, Entry{ID: "h", Scope: Scope{Kind: ScopeGlobal}, CreatedAt: signedNow}, signer("alice"))
	if !errors.Is(err, ErrChanged) {
		t.Errorf("an add over a file that changed = %v, want ErrChanged", err)
	}
	if now, _ := os.ReadFile(p.path); string(now) != string(theirs) {
		t.Error("the writer replaced a file that changed under it")
	}
	beforeReplace = nil
	if _, err := AddSigned(t.Context(), p.path, Entry{ID: "h", Scope: Scope{Kind: ScopeGlobal}, CreatedAt: signedNow}, signer("alice")); err != nil {
		t.Errorf("the same add over a file that stood still = %v", err)
	}
}

func TestParseSignedHoldsTheFormat(t *testing.T) {
	good := map[string]any{
		"schema_version": "3", "alg": "ed25519", "keyId": testKeyID("alice"), "tenant": "t1", "project": "A",
		"file": "/srv/pause/pause.json", "serial": int64(1), "entries": []any{},
	}
	body := func(change func(map[string]any)) []byte {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		change(m)
		b, err := canon.Canonicalize(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := ParseSigned(body(func(map[string]any) {})); err != nil {
		t.Fatalf("the control body: %v", err)
	}
	for _, c := range []struct {
		name   string
		change func(map[string]any)
		want   Error
	}{
		{"serial 0", func(m map[string]any) { m["serial"] = int64(0) }, ErrMalformed},
		{"a serial as text", func(m map[string]any) { m["serial"] = "1" }, ErrMalformed},
		{"another alg", func(m map[string]any) { m["alg"] = "rsa" }, ErrMalformed},
		{"version 2", func(m map[string]any) { m["schema_version"] = "2" }, ErrVersion},
		{"an unknown member", func(m map[string]any) { m["extra"] = "x" }, ErrMalformed},
		{"no tenant", func(m map[string]any) { delete(m, "tenant") }, ErrMalformed},
		{"an empty project", func(m map[string]any) { m["project"] = "" }, ErrMalformed},
		{"a tenant past its bound", func(m map[string]any) { m["tenant"] = strings.Repeat("t", MaxNameBytes+1) }, ErrMalformed},
		{"no file", func(m map[string]any) { delete(m, "file") }, ErrMalformed},
		{"a relative file", func(m map[string]any) { m["file"] = "pause/pause.json" }, ErrMalformed},
		{"a file not in its clean form", func(m map[string]any) { m["file"] = "/srv/pause/../pause/pause.json" }, ErrMalformed},
		{"a file with a control character", func(m map[string]any) { m["file"] = "/srv/pause/p\u0007.json" }, ErrMalformed},
		{"a file past its bound", func(m map[string]any) { m["file"] = "/" + strings.Repeat("p", MaxFilePathBytes) }, ErrMalformed},
	} {
		if _, err := ParseSigned(body(c.change)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := ParseSigned(body(func(m map[string]any) { m["tenant"] = strings.Repeat("t", MaxNameBytes) })); err != nil {
		t.Errorf("a tenant at its bound: %v", err)
	}
	if _, err := ParseSigned(body(func(m map[string]any) { m["file"] = "/" + strings.Repeat("p", MaxFilePathBytes-1) })); err != nil {
		t.Errorf("a file at its bound: %v", err)
	}
	if _, err := MarshalSigned(header("alice", policy.MaxSerial), Document{}); err != nil {
		t.Errorf("the highest serial: %v", err)
	}
	if _, err := MarshalSigned(header("alice", policy.MaxSerial+1), Document{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("a serial past the highest: %v", err)
	}
	spaced := append([]byte(" "), body(func(map[string]any) {})...)
	if _, err := ParseSigned(spaced); !errors.Is(err, ErrMalformed) {
		t.Errorf("a body that is not its canonical form: %v", err)
	}
	if _, err := ParseSigned(make([]byte, MaxSignedBodyBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a body over the bound: %v", err)
	}
}

// TestASignedFileWhoseBodyNamesAnotherKeyIsMalformed: the key the body names
// is the one the signature names.
func TestASignedFileWhoseBodyNamesAnotherKeyIsMalformed(t *testing.T) {
	raw, err := signFile(header("alice", 1), Document{}, signer("alice"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := parseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	env.Signatures[0].KeyID = testKeyID("bob")
	other, err := marshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeFile(other); !errors.Is(err, ErrMalformed) {
		t.Errorf("decodeFile = %v, want ErrMalformed", err)
	}
	if _, err := decodeFile(raw); err != nil {
		t.Errorf("the control: %v", err)
	}
}
