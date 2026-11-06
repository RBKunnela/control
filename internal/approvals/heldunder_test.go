package approvals_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/approvals"
)

// TestASignedHoldTakesNoClaim: a record a plane under the signed authority
// holds refuses an approver's claim, writing nothing; the same hold under the
// default authority takes it.
func TestASignedHoldTakesNoClaim(t *testing.T) {
	for _, c := range []struct {
		name string
		opts []approvals.Option
		want error
	}{
		{"signed", []approvals.Option{approvals.WithAuthority(approvals.HeldUnderSigned)}, approvals.ErrSignedHold},
		{"directory", nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, dir := openPlane(t, c.opts...)
			if err := p.Hold(t.Context(), held(t, "APPROVAL1", "req-1"), minted); err != nil {
				t.Fatal(err)
			}
			before := recordNames(t, dir)
			_, err := openApprover(t, dir).Answer(t.Context(), "APPROVAL1", controlv1.ApprovalState_APPROVAL_STATE_APPROVED, "duty-officer", "", minted.Add(time.Minute))
			if !errors.Is(err, c.want) && (c.want != nil || err != nil) {
				t.Fatalf("Answer = %v, want %v", err, c.want)
			}
			if c.want != nil && !equalNames(before, recordNames(t, dir)) {
				t.Error("a refused claim changed the directory")
			}
		})
	}
}

func equalNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestARecordSaysWhoHoldsIt: a 2.1 record names its authority, the held
// request's tenant and project; one without an authority, or under one this
// build does not name, is refused; a 2.0 record without the three members is
// read as held under the directory, and one carrying them is refused.
func TestARecordSaysWhoHoldsIt(t *testing.T) {
	p, dir := openPlane(t, approvals.WithAuthority(approvals.HeldUnderSigned))
	if err := p.Hold(t.Context(), held(t, "APPROVAL1", "req-1"), minted); err != nil {
		t.Fatal(err)
	}
	framed := readFile(t, dir, "APPROVAL1.0-held.rec")
	for _, member := range []string{`"schema_version":"2.1"`, `"authority":"signed"`, `"tenant":"tenant-1"`, `"project":"proj-1"`} {
		if !bytes.Contains(bodyOf(t, framed), []byte(member)) {
			t.Errorf("the record holds no %s", member)
		}
	}
	legacy := func(tb testing.TB, f []byte) []byte {
		body := replaceInBody(tb, f, `"schema_version":"2.1"`, `"schema_version":"2.0"`)
		return bytes.Replace(body, []byte(`,"authority":"signed","tenant":"tenant-1","project":"proj-1"`), nil, 1)
	}
	for name, c := range map[string]struct {
		body func(testing.TB, []byte) []byte
		want error
		held string
	}{
		"as written":   {func(tb testing.TB, f []byte) []byte { return bodyOf(tb, f) }, nil, approvals.HeldUnderSigned},
		"no authority": {func(tb testing.TB, f []byte) []byte { return replaceInBody(tb, f, `,"authority":"signed"`, ``) }, approvals.ErrInvalidHold, ""},
		"an unnamed authority": {func(tb testing.TB, f []byte) []byte {
			return replaceInBody(tb, f, `"authority":"signed"`, `"authority":"anyone"`)
		}, approvals.ErrInvalidHold, ""},
		"no tenant": {func(tb testing.TB, f []byte) []byte {
			return replaceInBody(tb, f, `"tenant":"tenant-1"`, `"tenant":""`)
		}, approvals.ErrInvalidHold, ""},
		"2.0": {legacy, nil, approvals.HeldUnderDirectory},
		"2.0 naming an authority": {func(tb testing.TB, f []byte) []byte {
			return replaceInBody(tb, f, `"schema_version":"2.1"`, `"schema_version":"2.0"`)
		}, approvals.ErrUnknownField, ""},
	} {
		t.Run(name, func(t *testing.T) {
			writeFile(t, dir, "APPROVAL1.0-held.rec", reframe(t, c.body(t, framed)))
			rec, err := openReader(t, dir).Held(t.Context(), "APPROVAL1")
			if c.want != nil {
				if !errors.Is(err, c.want) {
					t.Fatalf("Held = %v, want %v", err, c.want)
				}
				return
			}
			if err != nil || rec.HeldUnder() != c.held {
				t.Fatalf("Held = %v held under %q, want %q", err, rec.HeldUnder(), c.held)
			}
		})
	}
}

func openReader(t *testing.T, dir string) *approvals.Reader {
	t.Helper()
	r, err := approvals.OpenReader(dir)
	if err != nil {
		t.Fatalf("opening the reader: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// TestAnAnswerIsTheRecordsAnswer: AnswerFor takes every member the plane
// compares from the record, and refuses a record held under the directory,
// one past its expiry and a zero time.
func TestAnAnswerIsTheRecordsAnswer(t *testing.T) {
	p, dir := openPlane(t, approvals.WithAuthority(approvals.HeldUnderSigned))
	h := held(t, "APPROVAL1", "req-1")
	if err := p.Hold(t.Context(), h, minted); err != nil {
		t.Fatal(err)
	}
	rec, err := openReader(t, dir).Held(t.Context(), "APPROVAL1")
	if err != nil {
		t.Fatal(err)
	}
	at := minted.Add(time.Minute)
	a, err := approvals.AnswerFor(rec, approvals.DecisionReject, "no", at, "ed25519-0011223344556677")
	if err != nil {
		t.Fatal(err)
	}
	want := approvals.Answer{Alg: "ed25519", KeyID: "ed25519-0011223344556677", Tenant: "tenant-1", Project: "proj-1",
		RequestID: "req-1", ApprovalID: "APPROVAL1", ActionDigest: h.Approval.GetActionDigest(), BundleDigest: string(bundle),
		Decision: "reject", DecidedAt: at, Reason: "no"}
	if a != want {
		t.Errorf("AnswerFor = %+v\nwant %+v", a, want)
	}
	if approvals.AnswerLabel(a) != "ed25519-0011223344556677-reject" {
		t.Errorf("AnswerLabel = %q", approvals.AnswerLabel(a))
	}
	for name, c := range map[string]struct {
		rec  func(approvals.Record) approvals.Record
		at   time.Time
		want error
	}{
		"held under the directory": {func(r approvals.Record) approvals.Record { r.Authority = approvals.HeldUnderDirectory; return r }, at, approvals.ErrNotSigned},
		"at its expiry":            {func(r approvals.Record) approvals.Record { return r }, expires, approvals.ErrApprovalExpired},
		"a zero time":              {func(r approvals.Record) approvals.Record { return r }, time.Time{}, approvals.ErrZeroTime},
	} {
		if _, err := approvals.AnswerFor(c.rec(rec), approvals.DecisionApprove, "", c.at, "ed25519-0011223344556677"); !errors.Is(err, c.want) {
			t.Errorf("%s: AnswerFor = %v, want %v", name, err, c.want)
		}
	}
	if _, err := approvals.AnswerFor(rec, approvals.DecisionApprove, "", expires.Add(-time.Nanosecond), "ed25519-0011223344556677"); err != nil {
		t.Errorf("an instant before the expiry: %v", err)
	}
}

func TestWithAuthorityTakesTheTwoKinds(t *testing.T) {
	if _, err := approvals.OpenPlane(t.TempDir(), approvals.WithAuthority("memory")); !errors.Is(err, approvals.ErrInvalidOption) {
		t.Errorf("OpenPlane under memory = %v, want ErrInvalidOption", err)
	}
}

// TestOnlyASignedHoldIsHeldToTheAnswersIDBound: a tenant past the 256 bytes
// a signed answer may name is refused under signed and held under the
// directory authority, which no signed answer names.
func TestOnlyASignedHoldIsHeldToTheAnswersIDBound(t *testing.T) {
	long := strings.Repeat("t", approvals.MaxAnswerIDBytes+1)
	for _, c := range []struct {
		name string
		opts []approvals.Option
		want error
	}{
		{"signed", []approvals.Option{approvals.WithAuthority(approvals.HeldUnderSigned)}, approvals.ErrInvalidHold},
		{"directory", nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _ := openPlane(t, c.opts...)
			h := held(t, "APPROVAL1", "req-1")
			h.Envelope.TenantId = long
			if err := p.Hold(t.Context(), h, minted); !errors.Is(err, c.want) && (c.want != nil || err != nil) {
				t.Fatalf("Hold with a %d-byte tenant = %v, want %v", len(long), err, c.want)
			}
			h = held(t, "APPROVAL2", "req-2")
			h.Envelope.TenantId = long[:approvals.MaxAnswerIDBytes]
			if err := p.Hold(t.Context(), h, minted); err != nil {
				t.Errorf("Hold with a %d-byte tenant: %v", approvals.MaxAnswerIDBytes, err)
			}
		})
	}
}
