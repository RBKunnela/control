//go:build unix

package pause

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/policy"
	"github.com/guardana/control/pkg/contract"
)

// v3Placeholder is the plane id signV3 writes a version 4 body under before
// it cuts the member out.
const v3Placeholder = "v3-placeholder"

// signV3 is a version 3 file, which names no plane, of h over d signed by
// the key called by: the version 4 body of h with its plane_id cut out and
// its version set back.
func signV3(t *testing.T, by string, h Header, d Document) []byte {
	t.Helper()
	h.PlaneID = v3Placeholder
	body, err := MarshalSigned(h, d)
	if err != nil {
		t.Fatal(err)
	}
	cut := bytes.Replace(body, []byte(`"plane_id":"`+v3Placeholder+`",`), nil, 1)
	cut = bytes.Replace(cut, []byte(`"schema_version":"4"`), []byte(`"schema_version":"3"`), 1)
	if bytes.Equal(cut, body) || bytes.Contains(cut, []byte("plane_id")) {
		t.Fatalf("the version 4 body is not spelled as signV3 expects: %s", body)
	}
	sig, err := signer(by).Sign(PayloadType, cut)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := marshalEnvelope(policy.StatementEnvelope{PayloadType: PayloadType, Payload: cut,
		Signatures: []policy.StatementSignature{{KeyID: testKeyID(by), Signature: sig}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// twoEntries is a document of two entries, which a test compares field by
// field after a Resign.
var twoEntries = Document{Entries: []Entry{
	{ID: "g", Scope: Scope{Kind: ScopeGlobal}, CreatedAt: signedNow, Reason: "stop"},
	{ID: "p", Scope: Scope{Kind: ScopeProvider, Provider: "orders"}, CreatedAt: signedNow.Add(time.Minute), Reason: "orders down"},
}}

// TestAVersion3FileIsRefusedNamingTheCommand: a plane's read of a version 3
// file is unknown, which blocks every call, names pause sign and never asks
// the judge, so no floor is raised; the writer's read and doctor's refuse it
// alike.
func TestAVersion3FileIsRefusedNamingTheCommand(t *testing.T) {
	p := newSignedPlane(t)
	p.writeRaw(t, signV3(t, "alice", p.header(t, "alice", 5), Document{}))
	asked := false
	s := p.read(t, judgeFunc(func(f Signed) (SignedBy, error) { asked = true; return takes(f) }))
	wantUnknown(t, "a version 3 file read by a plane", s, CauseVersion)
	if !strings.Contains(s.Detail(), "pause sign --plane-id") {
		t.Errorf("the refusal %q does not name the command that signs the file again", s.Detail())
	}
	if asked {
		t.Error("the judge, which raises the floor, was asked about a version 3 file")
	}
	if _, err := Inspect(p.path); !errors.Is(err, ErrVersion) || !strings.Contains(err.Error(), "pause sign") {
		t.Errorf("Inspect, which doctor reads with, = %v; want ErrVersion naming pause sign", err)
	}
	actAs(t, os.Geteuid())
	if _, err := List(p.path); !errors.Is(err, ErrVersion) {
		t.Errorf("List = %v, want ErrVersion", err)
	}
	if _, err := AddSigned(t.Context(), p.path, globalEntry, signer("alice")); !errors.Is(err, ErrVersion) {
		t.Errorf("an add to a version 3 file = %v, want ErrVersion", err)
	}
	p.write(t, "alice", p.header(t, "alice", 6), Document{})
	if s := p.read(t, takes); s.State() != Clear {
		t.Errorf("the control, a version 4 file = %s, %q: %s", s.State(), s.Cause(), s.Detail())
	}
}

// TestResignCarriesEveryEntryToTheCurrentVersion: a version 3 file of two
// entries becomes a version 4 file of plane-a with the same two entries at
// the next serial, which a plane takes; run again it signs at the serial
// after that.
func TestResignCarriesEveryEntryToTheCurrentVersion(t *testing.T) {
	p := newSignedPlane(t)
	from := p.header(t, "alice", 5)
	p.writeRaw(t, signV3(t, "alice", from, twoEntries))
	want := Header{KeyID: testKeyID("carol"), PlaneID: "plane-a", Tenant: "t1", Project: "A", File: from.File, Serial: 6}
	wantResigned(t, "Resign", p.path, signer("carol"), want)
	if s := p.read(t, takes); s.State() != Paused || len(s.Entries()) != 2 {
		t.Errorf("a plane's read of the signed file = %s, %q: %s", s.State(), s.Cause(), s.Detail())
	}
	actAs(t, os.Geteuid())
	want.KeyID, want.Serial = testKeyID("alice"), 7
	wantResigned(t, "Resign run again", p.path, signer("alice"), want)
}

// wantResigned runs Resign of the file at path for plane-a with s, and fails
// t unless it signed want over twoEntries and the file lists the same.
func wantResigned(t *testing.T, what, path string, s Signer, want Header) {
	t.Helper()
	got, err := Resign(t.Context(), path, "plane-a", s)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if got.Header != want || !slices.EqualFunc(got.Entries, twoEntries.Entries, sameEntry) {
		t.Errorf("%s signed %+v over %d entries, want %+v over the two", what, got.Header, len(got.Entries), want)
	}
	l, err := List(path)
	if err != nil || l.Signed == nil || l.Signed.Header != want || !slices.EqualFunc(l.Entries, twoEntries.Entries, sameEntry) {
		t.Fatalf("%s: the file lists %+v, %v; want %+v over the two entries", what, l, err, want)
	}
}

// fillV3 is a document whose version 3 body under h is exactly size bytes:
// entries of the longest reason, the last ones cut until it fits.
func fillV3(t *testing.T, h Header, size int) Document {
	t.Helper()
	h.PlaneID = v3Placeholder
	member := len(`"plane_id":"` + v3Placeholder + `",`)
	bodyOf := func(d Document) int {
		body, err := MarshalSigned(h, d)
		if err != nil {
			t.Fatal(err)
		}
		return len(body) - member
	}
	var d Document
	for bodyOf(d) < size {
		d.Entries = append(d.Entries, Entry{ID: fmt.Sprintf("e%02d", len(d.Entries)), Scope: Scope{Kind: ScopeGlobal},
			CreatedAt: signedNow, Reason: strings.Repeat("r", MaxReasonBytes)})
	}
	for i, over := len(d.Entries)-1, bodyOf(d)-size; over > 0; i-- {
		cut := min(over, len(d.Entries[i].Reason)-1)
		d.Entries[i].Reason = d.Entries[i].Reason[cut:]
		over -= cut
	}
	if n := bodyOf(d); n != size {
		t.Fatalf("fillV3 made a body of %d bytes, want %d", n, size)
	}
	return d
}

// TestResignCarriesAFullVersion3File: a version 3 body at its 16 KiB bound is
// signed again for the longest plane id, every byte of which the canonical
// form escapes, with every entry kept; a version 3 body one byte past that
// bound is refused.
func TestResignCarriesAFullVersion3File(t *testing.T) {
	p := newSignedPlane(t)
	from := p.header(t, "alice", 5)
	full := fillV3(t, from, maxUpgradeBodyBytes)
	p.writeRaw(t, signV3(t, "alice", from, full))
	plane := strings.Repeat(`"`, contract.MaxStringBytes)
	got, err := Resign(t.Context(), p.path, plane, signer("alice"))
	if err != nil || got.PlaneID != plane || got.Serial != 6 || !slices.EqualFunc(got.Entries, full.Entries, sameEntry) {
		t.Fatalf("Resign of a full version 3 file = serial %d, %d of %d entries, %v", got.Serial, len(got.Entries), len(full.Entries), err)
	}
	over := fillV3(t, from, maxUpgradeBodyBytes+1)
	if _, err := ReadSignedV3(signV3(t, "alice", from, over)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a version 3 body one byte past its bound = %v, want ErrTooLarge", err)
	}
}

// TestResignRefusesWhatItCannotCarry: an unsigned file, a version 4 file of
// another plane, a file the signer does not accept, a file bound to another
// path, a version no build signed and an empty plane id are each refused
// and the file left as it was.
func TestResignRefusesWhatItCannotCarry(t *testing.T) {
	p := newSignedPlane(t)
	other := newSignedPlane(t)
	notVouched := signer("alice")
	notVouched.Accept = func(Signed) error { return errors.New("not the roster's") }
	planeB := p.header(t, "alice", 3)
	planeB.PlaneID = "plane-b"
	for _, c := range []struct {
		name  string
		raw   func(*testing.T) []byte
		plane string
		s     Signer
		want  Error
	}{
		{"an unsigned file", func(*testing.T) []byte { return []byte(`{"schema_version":"2","entries":[]}`) }, "plane-a", signer("alice"), ErrUnsigned},
		{"an unsigned file of version 3", func(*testing.T) []byte { return []byte(`{"schema_version":"3","entries":[]}`) }, "plane-a", signer("alice"), ErrUnsigned},
		{"a version 4 file of plane-b", func(t *testing.T) []byte {
			raw, err := signFile(planeB, paused, signer("alice"))
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}, "plane-a", signer("alice"), ErrOtherPlane},
		{"a version 3 file the roster does not vouch for", func(t *testing.T) []byte { return signV3(t, "mallory", p.header(t, "mallory", 3), paused) }, "plane-a", notVouched, ErrNotVouched},
		{"a version 3 file of another path", func(t *testing.T) []byte { return signV3(t, "alice", other.header(t, "alice", 3), paused) }, "plane-a", signer("alice"), ErrOtherFile},
		{"a version 3 file with no plane asked for", func(t *testing.T) []byte { return signV3(t, "alice", p.header(t, "alice", 3), paused) }, "", signer("alice"), ErrMalformed},
		{"a version 5 file", func(t *testing.T) []byte {
			raw := signV3(t, "alice", p.header(t, "alice", 3), paused)
			env, err := parseEnvelope(raw)
			if err != nil {
				t.Fatal(err)
			}
			env.Payload = bytes.Replace(env.Payload, []byte(`"schema_version":"3"`), []byte(`"schema_version":"5"`), 1)
			out, err := marshalEnvelope(env)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}, "plane-a", signer("alice"), ErrVersion},
	} {
		raw := c.raw(t)
		p.writeRaw(t, raw)
		if _, err := Resign(t.Context(), p.path, c.plane, c.s); !errors.Is(err, c.want) {
			t.Errorf("%s: Resign = %v, want %v", c.name, err, c.want)
		}
		if now, err := os.ReadFile(p.path); err != nil || !bytes.Equal(now, raw) {
			t.Errorf("%s: a refused Resign changed the file: %v", c.name, err)
		}
	}
	p.writeRaw(t, signV3(t, "alice", p.header(t, "alice", 3), paused))
	if _, err := Resign(t.Context(), p.path, "plane-a", signer("alice")); err != nil {
		t.Errorf("the control, a version 3 file of this path the signer accepts: %v", err)
	}
	planeA := planeB
	planeA.PlaneID = "plane-a"
	planeA.Serial = 9
	raw, err := signFile(planeA, paused, signer("alice"))
	if err != nil {
		t.Fatal(err)
	}
	p.writeRaw(t, raw)
	if got, err := Resign(t.Context(), p.path, "plane-a", signer("alice")); err != nil || got.Serial != 10 {
		t.Errorf("the control, a version 4 file of plane-a = %+v, %v", got.Header, err)
	}
}

// TestReadSignedV3ReadsOnlyVersion3: it reads what signV3 writes, its plane
// id empty, and refuses a version 4 file and an unsigned one.
func TestReadSignedV3ReadsOnlyVersion3(t *testing.T) {
	h := header("alice", 4)
	f, err := ReadSignedV3(signV3(t, "alice", h, twoEntries))
	want := h
	want.PlaneID = ""
	if err != nil || f.Body.Header != want || !slices.EqualFunc(f.Body.Entries, twoEntries.Entries, sameEntry) {
		t.Fatalf("ReadSignedV3 = %+v, %v; want %+v over the two entries", f.Body, err, want)
	}
	v4, err := signFile(h, twoEntries, signer("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSignedV3(v4); !errors.Is(err, ErrVersion) {
		t.Errorf("a version 4 file = %v, want ErrVersion", err)
	}
	if _, err := ReadSignedV3([]byte(`{"schema_version":"2","entries":[]}`)); !errors.Is(err, ErrUnsigned) {
		t.Errorf("an unsigned file = %v, want ErrUnsigned", err)
	}
	if _, err := decodeFile(signV3(t, "alice", h, twoEntries)); !errors.Is(err, ErrVersion) {
		t.Errorf("a plane's decode of a version 3 file = %v, want ErrVersion", err)
	}
}
