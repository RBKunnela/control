package reaction_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
)

const bareDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// The four lines as a writer spells them, written out by hand.
const (
	headerGolden = `{"kind":"header","list_id":"list-1","route_digest":"sha256:` + bareDigest +
		`","route_id":"refunds","route_serial":3,"version":"1.0"}`
	stopGolden = `{"created_at":"2026-10-06T12:00:00Z","entry_id":"stp-18d65886e405ee7044097d29ec8a59c2",` +
		`"expires_at":"2026-10-06T13:00:00Z","finding_id":"fnd-0001","kind":"stop","procedure_digest":"` + bareDigest +
		`","procedure_id":"refund","procedure_version":"1","rule_id":"STEP_OUTSIDE_PROCEDURE","rule_version":"1",` +
		`"run_id":"run-a","tenant_id":"acme","version":"1.0"}`
	coveredGolden = `{"created_at":"2026-10-06T12:05:00Z","finding_id":"fnd-0002","kind":"covered","run_id":"run-a",` +
		`"tenant_id":"acme","version":"1.0"}`
)

func goldenStop() reaction.Stop {
	return reaction.Stop{
		EntryID: "stp-18d65886e405ee7044097d29ec8a59c2", TenantID: "acme", RunID: "run-a", FindingID: "fnd-0001",
		ProcedureID: "refund", ProcedureVersion: "1", ProcedureDigest: bareDigest,
		RuleID: "STEP_OUTSIDE_PROCEDURE", RuleVersion: "1",
		CreatedAt: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 10, 6, 13, 0, 0, 0, time.UTC),
	}
}

func TestEntryIDIsTheFindingsUnderItsOwnDomain(t *testing.T) {
	if got := reaction.EntryID("fnd-0001"); got != "stp-18d65886e405ee7044097d29ec8a59c2" {
		t.Fatalf("EntryID = %q", got)
	}
	plain := sha256.Sum256([]byte("fnd-0001"))
	if reaction.EntryID("fnd-0001") == "stp-"+hex.EncodeToString(plain[:16]) {
		t.Fatal("the entry id is the finding id's hash with no domain")
	}
	if reaction.EntryID("fnd-0001") == reaction.EntryID("fnd-0002") {
		t.Fatal("two findings share an entry id")
	}
}

func TestLinesMarshalAsWritten(t *testing.T) {
	h := reaction.Header{ListID: "list-1", RouteID: "refunds", RouteSerial: 3, RouteDigest: "sha256:" + bareDigest}
	c := reaction.Covered{FindingID: "fnd-0002", TenantID: "acme", RunID: "run-a", CreatedAt: time.Date(2026, 10, 6, 12, 5, 0, 0, time.UTC)}
	for _, tc := range []struct {
		name string
		got  func() ([]byte, error)
		want string
	}{
		{"header", h.Marshal, headerGolden},
		{"stop", goldenStop().Marshal, stopGolden},
		{"covered", c.Marshal, coveredGolden},
	} {
		got, err := tc.got()
		if err != nil || string(got) != tc.want {
			t.Errorf("%s: Marshal = %s, %v\nwant %s", tc.name, got, err, tc.want)
		}
		l, err := reaction.ParseLine([]byte(tc.want))
		if err != nil {
			t.Errorf("%s: ParseLine of the golden: %v", tc.name, err)
		}
		if tc.name == "stop" && (l.Kind != reaction.KindStop || l.Stop.ExpiresAt.Sub(l.Stop.CreatedAt) != time.Hour || l.Stop.EntryID != goldenStop().EntryID) {
			t.Errorf("stop read back as %+v", l)
		}
	}
}

func TestLiftLineCarriesItsEnvelope(t *testing.T) {
	line := liftLineOf(t, liftKey(), "list-1", "sha256:"+bareDigest, "run-a", 4, 4)
	raw, err := line.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	checkLiftShape(t, raw)
	l, err := reaction.ParseLine(raw)
	if err != nil || l.Kind != reaction.KindLift || l.Lift.RunID != "run-a" || l.Lift.ThroughLine != 4 {
		t.Fatalf("ParseLine = %+v, %v", l, err)
	}
	signed, err := reaction.VerifyLift(l.Lift.Envelope, pubOf(liftKey()))
	if err != nil || signed.RunID != "run-a" || signed.ThroughLine != 4 {
		t.Fatalf("the carried lift: %+v, %v", signed, err)
	}
}

// checkLiftShape reads a lift line with a decoder of its own.
func checkLiftShape(t *testing.T, raw []byte) {
	t.Helper()
	var shape struct {
		Kind, Version, RunID string
		Through              int64 `json:"through_line"`
		Envelope             struct {
			PayloadType string `json:"payloadType"`
			Signatures  []struct {
				KeyID string `json:"keyid"`
			} `json:"signatures"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if shape.Kind != "lift" || shape.Version != "1.0" || shape.Through != 4 ||
		shape.Envelope.PayloadType != "application/vnd.agent-reaction-lift+json" ||
		len(shape.Envelope.Signatures) != 1 || shape.Envelope.Signatures[0].KeyID != keyIDOf(liftKey()) {
		t.Fatalf("lift line %s", raw)
	}
	if strings.ContainsRune(string(raw), '\n') {
		t.Fatal("a lift line holds a newline")
	}
}

func lineRefusals() []error {
	return []error{
		reaction.ErrLineTooLong, reaction.ErrLineJSON, reaction.ErrLineRepeat, reaction.ErrLineKind,
		reaction.ErrLineMember, reaction.ErrLineVersion, reaction.ErrLineValue, reaction.ErrLineTime, reaction.ErrEntryID,
		reaction.ErrLineCanonical,
	}
}

func TestParseLineRefusesEachKindMalformed(t *testing.T) {
	r := strings.Replace
	cases := []struct {
		name, line string
		want       error
	}{
		{"not JSON", `{"kind":"stop"`, reaction.ErrLineJSON},
		{"an array", `[1]`, reaction.ErrLineJSON},
		{"two objects", headerGolden + headerGolden, reaction.ErrLineJSON},
		{"a member twice", r(headerGolden, `"kind":"header",`, `"kind":"header","kind":"header",`, 1), reaction.ErrLineRepeat},
		{"no kind", r(headerGolden, `"kind":"header",`, ``, 1), reaction.ErrLineKind},
		{"an unknown kind", r(headerGolden, `"kind":"header"`, `"kind":"pause"`, 1), reaction.ErrLineKind},
		{"a kind in capitals", r(headerGolden, `"kind":"header"`, `"kind":"HEADER"`, 1), reaction.ErrLineKind},
		{"version 2.0", r(headerGolden, `"1.0"`, `"2.0"`, 1), reaction.ErrLineVersion},
		{"version 1.1", r(headerGolden, `"1.0"`, `"1.1"`, 1), reaction.ErrLineVersion},
		{"version 1", r(headerGolden, `"1.0"`, `"1"`, 1), reaction.ErrLineVersion},
		{"version 01.0", r(headerGolden, `"1.0"`, `"01.0"`, 1), reaction.ErrLineVersion},
		{"a stop of version 1.1", r(stopGolden, `"version":"1.0"`, `"version":"1.1"`, 1), reaction.ErrLineVersion},
		{"version as a number", r(headerGolden, `"1.0"`, `1.0`, 1), reaction.ErrLineVersion},
		{"no version", r(headerGolden, `,"version":"1.0"`, ``, 1), reaction.ErrLineMember},
		{"header: an unknown member", r(headerGolden, `"kind"`, `"extra":1,"kind"`, 1), reaction.ErrLineMember},
		{"header: no list id", r(headerGolden, `"list_id":"list-1",`, ``, 1), reaction.ErrLineMember},
		{"header: an empty list id", r(headerGolden, `"list-1"`, `""`, 1), reaction.ErrLineValue},
		{"header: serial 0", r(headerGolden, `"route_serial":3`, `"route_serial":0`, 1), reaction.ErrLineValue},
		{"header: serial 3.0", r(headerGolden, `"route_serial":3`, `"route_serial":3.0`, 1), reaction.ErrLineValue},
		{"header: a bare route digest", r(headerGolden, `"sha256:`, `"`, 1), reaction.ErrLineValue},
		{"stop: no expires_at", r(stopGolden, `"expires_at":"2026-10-06T13:00:00Z",`, ``, 1), reaction.ErrLineMember},
		{"stop: a covered member", r(stopGolden, `"kind"`, `"through_line":2,"kind"`, 1), reaction.ErrLineMember},
		{"stop: another entry id", r(stopGolden, `stp-18d6`, `stp-28d6`, 1), reaction.ErrEntryID},
		{"stop: the entry id in capitals", r(stopGolden, `stp-18d65886e405ee`, `stp-18D65886E405EE`, 1), reaction.ErrEntryID},
		{"stop: a prefixed procedure digest", r(stopGolden, `"procedure_digest":"`, `"procedure_digest":"sha256:`, 1), reaction.ErrLineValue},
		{"stop: a procedure digest in capitals", r(stopGolden, `"0123456789abcdef`, `"0123456789ABCDEF`, 1), reaction.ErrLineValue},
		{"stop: a short procedure digest", r(stopGolden, `cdef","procedure_id"`, `cde","procedure_id"`, 1), reaction.ErrLineValue},
		{"stop: an empty run id", r(stopGolden, `"run-a"`, `""`, 1), reaction.ErrLineValue},
		{"stop: a run id of 65 bytes", r(stopGolden, `"run-a"`, `"`+strings.Repeat("r", 65)+`"`, 1), reaction.ErrLineValue},
		{"stop: a tenant with a control character", r(stopGolden, `"acme"`, `"ac\u0007me"`, 1), reaction.ErrLineValue},
		{"covered: a finding id with an unpaired surrogate", r(coveredGolden, `"fnd-0002"`, `"fnd-\ud800"`, 1), reaction.ErrLineJSON},
		{"covered: a finding id of invalid UTF-8", r(coveredGolden, `"fnd-0002"`, "\"fnd-\xff\"", 1), reaction.ErrLineJSON},
		{"stop: a fraction of a second", r(stopGolden, `12:00:00Z`, `12:00:00.5Z`, 1), reaction.ErrLineTime},
		{"stop: an offset", r(stopGolden, `12:00:00Z`, `12:00:00+00:00`, 1), reaction.ErrLineTime},
		{"stop: a lower-case z", r(stopGolden, `12:00:00Z`, `12:00:00z`, 1), reaction.ErrLineTime},
		{"stop: no seconds", r(stopGolden, `12:00:00Z`, `12:00Z`, 1), reaction.ErrLineTime},
		{"stop: a time as a number", r(stopGolden, `"2026-10-06T12:00:00Z"`, `1791288000`, 1), reaction.ErrLineTime},
		{"stop: before 1970", r(stopGolden, `2026-10-06T12:00:00Z`, `1969-12-31T23:59:59Z`, 1), reaction.ErrLineTime},
		{"covered: an entry id", r(coveredGolden, `"kind"`, `"entry_id":"stp-1","kind"`, 1), reaction.ErrLineMember},
		{"covered: no run", r(coveredGolden, `"run_id":"run-a",`, ``, 1), reaction.ErrLineMember},
		{"covered: an empty finding id", r(coveredGolden, `"fnd-0002"`, `""`, 1), reaction.ErrLineValue},
		{"covered: a finding id of 129 bytes", r(coveredGolden, `"fnd-0002"`, `"`+strings.Repeat("f", 129)+`"`, 1), reaction.ErrLineValue},
		{"covered: a time in another zone", r(coveredGolden, `12:05:00Z`, `14:05:00+02:00`, 1), reaction.ErrLineTime},
	}
	cases = append(cases, liftLineRefusals(t)...)
	for _, c := range cases {
		_, err := reaction.ParseLine([]byte(c.line))
		expectOnly(t, c.name, err, c.want, lineRefusals())
	}
}

func liftLineRefusals(t *testing.T) []struct {
	name, line string
	want       error
} {
	raw, err := liftLineOf(t, liftKey(), "list-1", "sha256:"+bareDigest, "run-a", 4, 4).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	lift, r := string(raw), strings.Replace
	return []struct {
		name, line string
		want       error
	}{
		{"lift: no envelope", r(lift, lift[strings.Index(lift, `"envelope"`):strings.Index(lift, `"kind"`)], ``, 1), reaction.ErrLineMember},
		{"lift: an envelope as a string", `{"envelope":"e","kind":"lift","run_id":"run-a","through_line":4,"version":"1.0"}`, reaction.ErrLineValue},
		{"lift: an envelope with a member DSSE lacks", r(lift, `"envelope":{`, `"envelope":{"extra":1,`, 1), reaction.ErrLineValue},
		{"lift: a payload not base64", r(lift, `"payload":"`, `"payload":"*`, 1), reaction.ErrLineValue},
		{"lift: through_line 0", r(lift, `"through_line":4`, `"through_line":0`, 1), reaction.ErrLineValue},
		{"lift: through_line negative", r(lift, `"through_line":4`, `"through_line":-4`, 1), reaction.ErrLineValue},
		{"lift: through_line past 2^53-1", r(lift, `"through_line":4`, `"through_line":9007199254740992`, 1), reaction.ErrLineValue},
		{"lift: a tenant", r(lift, `"kind"`, `"tenant_id":"acme","kind"`, 1), reaction.ErrLineMember},
	}
}

// TestLineBound: a stop line padded with white space to exactly
// MaxLineBytes is read, and refused only for its spelling; one byte more is
// refused for its length.
func TestLineBound(t *testing.T) {
	if reaction.MaxLineBytes != 65536 {
		t.Fatalf("MaxLineBytes = %d", reaction.MaxLineBytes)
	}
	pad := func(n int) []byte {
		return []byte(stopGolden[:1] + strings.Repeat(" ", n-len(stopGolden)) + stopGolden[1:])
	}
	_, err := reaction.ParseLine(pad(65536))
	expectOnly(t, "a line of 65536 bytes", err, reaction.ErrLineCanonical, lineRefusals())
	_, err = reaction.ParseLine(pad(65537))
	expectOnly(t, "a line of 65537 bytes", err, reaction.ErrLineTooLong, lineRefusals())
}

func TestMarshalRefusesWhatItWouldNotReadBack(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*reaction.Stop)
	}{
		{"an entry id of another finding", func(s *reaction.Stop) { s.EntryID = reaction.EntryID("fnd-0002") }},
		{"a fraction of a second", func(s *reaction.Stop) { s.CreatedAt = s.CreatedAt.Add(time.Millisecond) }},
		{"the zero expiry", func(s *reaction.Stop) { s.ExpiresAt = time.Time{} }},
		{"a prefixed digest", func(s *reaction.Stop) { s.ProcedureDigest = "sha256:" + bareDigest }},
	} {
		s := goldenStop()
		tc.edit(&s)
		if raw, err := s.Marshal(); !errors.Is(err, reaction.ErrLineMarshal) {
			t.Errorf("%s: Marshal = %s, %v; want ErrLineMarshal", tc.name, raw, err)
		}
	}
	other := liftLineOf(t, routeKey(), "list-1", "sha256:"+bareDigest, "run-a", 2, 2)
	if raw, err := other.Marshal(); err != nil {
		t.Errorf("a lift under another key is the judge's to refuse, not Marshal's: %v", err)
	} else if _, err := reaction.ParseLine(raw); err != nil {
		t.Errorf("a lift line under another key does not read back: %v", err)
	}
}

// TestAStopCarriesTheFindingRecordsDigest: the digest supervise gives the
// refund procedure is read as a stop line writes it, and no other spelling.
func TestAStopCarriesTheFindingRecordsDigest(t *testing.T) {
	raw, err := stopOf(t, "fnd-1", "run-a", clock0, time.Hour).Marshal()
	if err != nil {
		t.Fatalf("a stop of the refund procedure: %v", err)
	}
	if l, err := reaction.ParseLine(raw); err != nil || l.Stop.ProcedureDigest != refundDigest(t) {
		t.Fatalf("ParseLine = %+v, %v", l.Stop, err)
	}
	for _, d := range []string{"sha256:" + refundDigest(t), strings.ToUpper(refundDigest(t)), refundDigest(t)[1:], refundDigest(t) + "0"} {
		edited := strings.Replace(string(raw), `"procedure_digest":"`+refundDigest(t)+`"`, `"procedure_digest":"`+d+`"`, 1)
		_, err := reaction.ParseLine([]byte(edited))
		expectOnly(t, "procedure digest "+d, err, reaction.ErrLineValue, lineRefusals())
	}
}
