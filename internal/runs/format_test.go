package runs

import (
	"errors"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

const (
	literalID     = "run-0123456789abcdef0123456789abcdef"
	literalParent = "run-fedcba9876543210fedcba9876543210"
	literalHash   = "abababababababababababababababababababababababababababababababab"
)

// literalRecord is a closed child run as a file holds it, written out by hand
// so that the decoder and the encoder are each held to the format rather than
// to each other.
const literalRecord = `{"schema_version":"2.0","run_id":"` + literalID + `","project_id":"project-a",` +
	`"tenant_id":"tenant-a","principal_type":"user","principal_id":"alice","agent_id":"agent-1","root":"` + literalParent + `",` +
	`"parent":"` + literalParent + `","opened_at":"2026-03-01T12:00:00Z","expires_at":"2026-03-01T13:00:00.5Z",` +
	`"closed_at":"2026-03-01T12:30:00Z","secret_sha256":"` + literalHash + `"}` + "\n"

// literalRecordV1 is the same run as a record of major 1 holds it, with no
// project.
const literalRecordV1 = `{"schema_version":"1.0","run_id":"` + literalID + `","tenant_id":"tenant-a",` +
	`"principal_type":"user","principal_id":"alice","agent_id":"agent-1","root":"` + literalParent + `",` +
	`"parent":"` + literalParent + `","opened_at":"2026-03-01T12:00:00Z","expires_at":"2026-03-01T13:00:00.5Z",` +
	`"closed_at":"2026-03-01T12:30:00Z","secret_sha256":"` + literalHash + `"}` + "\n"

func literalValue() Record {
	return Record{
		ID:           literalID,
		Who:          Identity{ProjectID: "project-a", TenantID: "tenant-a", PrincipalType: "user", PrincipalID: "alice", AgentID: "agent-1"},
		Root:         literalParent,
		Parent:       literalParent,
		OpenedAt:     time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC),
		ExpiresAt:    time.Date(2026, time.March, 1, 13, 0, 0, 500000000, time.UTC),
		ClosedAt:     time.Date(2026, time.March, 1, 12, 30, 0, 0, time.UTC),
		SecretSHA256: literalHash,
	}
}

func TestTheRecordFormatReadsAndWritesAsDocumented(t *testing.T) {
	got, err := decodeRecord([]byte(literalRecord))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != literalValue() {
		t.Fatalf("decode = %+v\nwant %+v", got, literalValue())
	}
	raw, err := new(Admin).encodeRecord(literalValue())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if string(raw) != literalRecord {
		t.Fatalf("encode =\n%s\nwant\n%s", raw, literalRecord)
	}
}

func TestTheRecordDecoderRefusesWhatItCannotReadOneWay(t *testing.T) {
	swap := func(old, with string) string { return strings.Replace(literalRecord, old, with, 1) }
	cases := map[string]struct {
		raw  string
		want error
	}{
		"absent key":              {swap(`"closed_at":"2026-03-01T12:30:00Z",`, ""), ErrMissingField},
		"unknown key":             {swap(`{`, `{"note":"",`), ErrUnknownField},
		"key in another case":     {swap(`"agent_id"`, `"Agent_ID"`), ErrUnknownField},
		"duplicate key":           {swap(`{`, `{"agent_id":"agent-2",`), ErrDuplicateField},
		"null":                    {swap(`"closed_at":"2026-03-01T12:30:00Z"`, `"closed_at":null`), ErrMalformed},
		"number":                  {swap(`"tenant_id":"tenant-a"`, `"tenant_id":7`), ErrMalformed},
		"major 1, no project":     {literalRecordV1, ErrSchemaVersion},
		"major 1, with a project": {swap(`"2.0"`, `"1.0"`), ErrSchemaVersion},
		"major 3":                 {swap(`"2.0"`, `"3.0"`), ErrSchemaVersion},
		"no minor":                {swap(`"2.0"`, `"2"`), ErrSchemaVersion},
		"minor past 32 bits":      {swap(`"2.0"`, `"2.4294967296"`), ErrSchemaVersion},
		"no project key":          {swap(`"project_id":"project-a",`, ""), ErrMissingField},
		"empty project":           {swap(`"project_id":"project-a"`, `"project_id":""`), ErrIdentity},
		"project not an id":       {swap(`"project_id":"project-a"`, `"project_id":"project\u0000"`), ErrIdentity},
		"project over the bound":  {swap(`"project-a"`, `"`+strings.Repeat("p", MaxIdentityBytes+1)+`"`), ErrIdentity},
		"trailing object":         {literalRecord + "{}", ErrMalformed},
		"an array":                {"[" + literalRecord + "]", ErrMalformed},
		"offset time":             {swap(`"2026-03-01T12:00:00Z"`, `"2026-03-01T14:00:00+02:00"`), ErrMalformed},
		"padded fraction":         {swap(`13:00:00.5Z`, `13:00:00.50Z`), ErrMalformed},
		"ttl over the bound":      {swap(`"2026-03-01T13:00:00.5Z"`, `"2026-04-01T12:00:00.000000001Z"`), ErrTTL},
		"ttl under the bound":     {swap(`"2026-03-01T13:00:00.5Z"`, `"2026-03-01T12:00:59Z"`), ErrTTL},
		"upper-case hash":         {swap(literalHash, strings.ToUpper(literalHash)), ErrMalformed},
		"a root of its own":       {swap(`"root":"`+literalParent, `"root":"`+literalID), ErrMalformed},
		"no parent, a root":       {swap(`"parent":"`+literalParent+`"`, `"parent":""`), ErrMalformed},
		"empty agent":             {swap(`"agent_id":"agent-1"`, `"agent_id":""`), ErrIdentity},
		"zero opening":            {swap(`"2026-03-01T12:00:00Z"`, `"0001-01-01T00:00:00Z"`), ErrMalformed},
	}
	for name, c := range cases {
		if _, err := decodeRecord([]byte(c.raw)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	at := literalRecord
	at = strings.Replace(at, `"2026-03-01T13:00:00.5Z"`, `"2026-03-31T12:00:00Z"`, 1)
	if _, err := decodeRecord([]byte(at)); err != nil {
		t.Fatalf("a lifetime of exactly MaxTTL: %v", err)
	}
	if _, err := decodeRecord([]byte(swap(`"2.0"`, `"2.4294967295"`))); err != nil {
		t.Fatalf("the last minor within 32 bits: %v", err)
	}
	if got, err := decodeRecord([]byte(swap(`"project-a"`, `"`+strings.Repeat("p", MaxIdentityBytes)+`"`))); err != nil || len(got.Who.ProjectID) != MaxIdentityBytes {
		t.Fatalf("a project at the bound: %v", err)
	}
}

// A record of major 1 names no project. It is refused by its version, with
// the reason said, and never read as a record of whatever project asks.
func TestARecordOfMajorOneIsRefusedAsHavingNoProject(t *testing.T) {
	for name, raw := range map[string]string{
		"as major 1 wrote it":    literalRecordV1,
		"with a project grafted": strings.Replace(literalRecord, `"2.0"`, `"1.0"`, 1),
		"a later minor of 1":     strings.Replace(literalRecordV1, `"1.0"`, `"1.7"`, 1),
	} {
		rec, err := decodeRecord([]byte(raw))
		if !errors.Is(err, ErrSchemaVersion) || !strings.Contains(err.Error(), "names no project") || rec != (Record{}) {
			t.Errorf("%s: %+v, %v; want ErrSchemaVersion saying it names no project", name, rec, err)
		}
	}
}

// The encoder refuses a record with no project, so none is ever written.
func TestTheRecordEncoderRefusesARecordWithNoProject(t *testing.T) {
	for name, project := range map[string]string{"empty": "", "not an id": "a/b\n"} {
		rec := literalValue()
		rec.Who.ProjectID = project
		if raw, err := new(Admin).encodeRecord(rec); !errors.Is(err, ErrIdentity) || raw != nil {
			t.Errorf("%s: %q, %v; want ErrIdentity and nothing", name, raw, err)
		}
	}
}

// A string the decoder would turn into U+FFFD is refused, so a file holding
// one never reads as the file holding U+FFFD itself; that file, and a
// surrogate pair, still read.
func TestTheReadersRefuseAStringThatIsNotUnicode(t *testing.T) {
	tenant := func(v string) string { return strings.Replace(literalRecord, `"tenant-a"`, `"tenant-`+v+`"`, 1) }
	state := func(root, maxRead string) string {
		return `{"schema_version":"1.0","root":"` + root + `","untrusted":false,"max_read":"` + maxRead + `"}`
	}
	refused := map[string]string{
		"a lone high surrogate":         tenant(`\ud800`),
		"a lone low surrogate":          tenant(`\udc00`),
		"a high surrogate, then a char": tenant(`\ud800A`),
		"two high surrogates":           tenant(`\ud800\ud800`),
		"a byte that is not UTF-8":      tenant("\xff"),
		"a truncated sequence":          tenant("\xe2\x82"),
	}
	for name, raw := range refused {
		if _, err := decodeRecord([]byte(raw)); !errors.Is(err, ErrEncoding) {
			t.Errorf("record, %s: %v, want ErrEncoding", name, err)
		}
	}
	for name, raw := range map[string]string{
		"a lone surrogate in max_read": state(literalID, `PUBLIC\ud800`),
		"a byte that is not UTF-8":     state(literalID+"\xff", "PUBLIC"),
	} {
		if _, _, err := decodeState([]byte(raw)); !errors.Is(err, ErrEncoding) {
			t.Errorf("state, %s: %v, want ErrEncoding", name, err)
		}
	}
	for raw, want := range map[string]string{
		tenant("�"):          "tenant-�",
		tenant(`�`):          "tenant-�",
		tenant(`😀`):          "tenant-\U0001F600",
		tenant("\U0001F600"): "tenant-\U0001F600",
	} {
		got, err := decodeRecord([]byte(raw))
		if err != nil || got.Who.TenantID != want {
			t.Errorf("%q: tenant %q, %v; want %q", raw, got.Who.TenantID, err, want)
		}
	}
}

func TestTheStateFormatReadsAndWritesAsDocumented(t *testing.T) {
	cases := []struct {
		text  string
		state State
	}{
		{`{"schema_version":"1.0","root":"` + literalID + `","untrusted":false,"max_read":"PUBLIC"}`, State{MaxRead: controlv1.Sensitivity_SENSITIVITY_PUBLIC}},
		{`{"schema_version":"1.0","root":"` + literalID + `","untrusted":true,"max_read":"UNKNOWN"}`, State{Untrusted: true}},
		{`{"schema_version":"1.0","root":"` + literalID + `","untrusted":false,"max_read":"SECRET"}`, State{MaxRead: controlv1.Sensitivity_SENSITIVITY_SECRET}},
	}
	for _, c := range cases {
		root, got, err := decodeState([]byte(c.text))
		if err != nil || root != literalID || got != c.state {
			t.Errorf("decode %s = %s %+v, %v", c.text, root, got, err)
		}
		raw, err := encodeState(literalID, c.state)
		if err != nil || string(raw) != c.text+"\n" {
			t.Errorf("encode %+v = %s, %v", c.state, raw, err)
		}
	}
	names := map[string]controlv1.Sensitivity{
		"UNKNOWN": 0, "PUBLIC": 1, "INTERNAL": 2, "CONFIDENTIAL": 3, "RESTRICTED": 4, "SECRET": 5,
	}
	for name, want := range names {
		if got, ok := parseSensitivity(name); !ok || got != want {
			t.Errorf("parseSensitivity(%s) = %v, %t", name, got, ok)
		}
	}
	for _, name := range []string{"UNSPECIFIED", "public", "SENSITIVITY_PUBLIC", ""} {
		if _, ok := parseSensitivity(name); ok {
			t.Errorf("parseSensitivity(%q) read a level", name)
		}
	}
}
