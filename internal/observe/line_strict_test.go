package observe_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestUnmarshalLineIsStrict(t *testing.T) {
	lines := fixtureLines(t)
	obs := strings.TrimSuffix(string(lines[0]), "\n")
	rep := strings.TrimSuffix(string(lines[1]), "\n")
	obsBody := obs[len(`{"observation":`) : len(obs)-1]
	repBody := rep[len(`{"importReport":`) : len(rep)-1]
	replace := func(s, old, with string) string {
		if !strings.Contains(s, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(s, old, with, 1)
	}
	cases := map[string]struct{ line, want string }{
		"empty":                     {"", "blank"},
		"blank":                     {"\n", "blank"},
		"whitespace":                {" \t\r\n", "blank"},
		"not JSON":                  {"observation\n", ""},
		"an array":                  {"[" + obs + "]", ""},
		"two objects":               {obs + obs, ""},
		"no member":                 {"{}", "no member"},
		"a null member":             {`{"observation":null}`, "null"},
		"two members":               {`{"observation":` + obsBody + `,"importReport":` + repBody + `}`, "importReport"},
		"a null beside a member":    {`{"observation":null,"importReport":` + repBody + `}`, "null"},
		"an unknown member":         {replace(obs, `{"observation":`, `{"verdict":"ALLOW","observation":`), "verdict"},
		"an unknown nested member":  {replace(obs, `"subject":{`, `"subject":{"content":"x",`), "content"},
		"a null nested member":      {replace(obs, `"stage":"STAGE_COMPLETED"`, `"stage":null`), "null"},
		"a null timestamp":          {replace(obs, `"eventTime":"2026-10-04T10:00:00.250Z"`, `"eventTime":null`), "null"},
		"a duplicate member":        {replace(obs, `"tenantId":"tenant-a"`, `"tenantId":"tenant-a","tenantId":"tenant-b"`), "duplicate"},
		"a duplicate, two spelling": {replace(obs, `"tenantId":"tenant-a"`, `"tenantId":"tenant-a","tenant_id":"tenant-b"`), "duplicate"},
		"a duplicate map key":       {replace(rep, `{"unmapped_operation":"1"}`, `{"a":"1","a":"2"}`), "duplicate"},
		"version of a later minor":  {replace(obs, `"schemaVersion":"0.1"`, `"schemaVersion":"0.3"`), "minor"},
		"version absent":            {replace(rep, `"schemaVersion":"0.1",`, ``), "absent"},
		"invalid UTF-8":             {replace(obs, "read_file", "read\xfffile"), "UTF-8"},
		"a trailing comma":          {replace(obs, `"contentAttributesDropped":2}`, `"contentAttributesDropped":2,}`), ""},
	}
	for name, c := range cases {
		r, err := observe.UnmarshalLine([]byte(c.line))
		if !errors.Is(err, observe.ErrLine) || !strings.Contains(err.Error(), c.want) || r != nil {
			t.Errorf("%s: UnmarshalLine = %v, %v, want ErrLine saying %q", name, r, err, c.want)
		}
	}
	if _, err := observe.UnmarshalLine([]byte(replace(obs, `"schemaVersion":"0.1"`, `"schemaVersion":"1.0"`))); !errors.Is(err, observe.ErrVersion) {
		t.Errorf("another major: %v, want ErrVersion", err)
	}
}

// The bound counts the line without its newline, in both directions.
func TestTheLineBound(t *testing.T) {
	obs := bytes.TrimSuffix(fixtureLines(t)[0], []byte("\n"))
	padded := func(n int) []byte {
		return append(bytes.Repeat([]byte(" "), n-len(obs)), obs...)
	}
	for _, c := range []struct {
		line []byte
		ok   bool
	}{
		{padded(65536), true},
		{append(padded(65536), '\n'), true},
		{padded(65537), false},
		{append(padded(65537), '\n'), false},
		{append(padded(65535), '\r', '\n'), true},
		{append(padded(65536), '\r', '\n'), false},
	} {
		_, err := observe.UnmarshalLine(c.line)
		if c.ok && err != nil {
			t.Errorf("UnmarshalLine of %d bytes: %v", len(c.line), err)
		}
		if !c.ok && !errors.Is(err, observe.ErrLineTooLong) {
			t.Errorf("UnmarshalLine of %d bytes = %v, want ErrLineTooLong", len(c.line), err)
		}
	}

}

// The writer's longest line is the reader's longest.
func TestTheWritersLongestLineReads(t *testing.T) {
	short, err := observe.MarshalLine(obsRecord(withName("n")))
	if err != nil {
		t.Fatal(err)
	}
	fill := 65536 - (len(short) - 1) + 1
	atLimit, err := observe.MarshalLine(obsRecord(withName(strings.Repeat("n", fill))))
	if err != nil || len(atLimit) != 65537 {
		t.Fatalf("a record whose line is 65536 bytes: %d bytes, %v", len(atLimit), err)
	}
	if _, err := observe.UnmarshalLine(atLimit); err != nil {
		t.Fatalf("the writer's longest line does not read: %v", err)
	}
	over, err := observe.MarshalLine(obsRecord(withName(strings.Repeat("n", fill+1))))
	if !errors.Is(err, observe.ErrLineTooLong) || over != nil {
		t.Fatalf("a record whose line is 65537 bytes: %d bytes, %v, want ErrLineTooLong", len(over), err)
	}
	// Escaping is measured: six bytes for each U+2028 where the raw rune is three.
	escaped, err := observe.MarshalLine(obsRecord(withName(strings.Repeat("n", fill-5) + "\u2028")))
	if !errors.Is(err, observe.ErrLineTooLong) {
		t.Fatalf("a line over the bound only once escaped: %d bytes, %v, want ErrLineTooLong", len(escaped), err)
	}
}

// The reader takes every minor in its table, the writer only the one it
// writes.
func TestTheWriterWritesOnlyItsOwnVersion(t *testing.T) {
	defer observe.AcceptMinor("3")()
	o := fixtureObservation()
	o.SchemaVersion = "0.3"
	raw, err := protojson.Marshal(obsRecord(o))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observe.UnmarshalLine(raw); err != nil {
		t.Fatalf("a minor in the table does not read: %v", err)
	}
	_, err = observe.MarshalLine(obsRecord(o))
	if !errors.Is(err, observe.ErrLine) || !strings.Contains(err.Error(), "this writer writes") {
		t.Fatalf("MarshalLine of 0.3 = %v, want a refusal naming the writer's version", err)
	}
}

// The writer looks for unknown fields only through singular messages, so a
// list or map of messages added to the contract would go unexamined.
func TestTheRecordHoldsNoRepeatedMessage(t *testing.T) {
	seen := map[protoreflect.FullName]bool{}
	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		for i := range md.Fields().Len() {
			fd := md.Fields().Get(i)
			switch {
			case fd.IsMap() && fd.MapValue().Message() != nil, fd.IsList() && fd.Message() != nil:
				t.Errorf("%s is a list or map of messages", fd.FullName())
			case fd.Message() != nil && !fd.IsMap():
				walk(fd.Message())
			}
		}
	}
	walk((&observev1.Record{}).ProtoReflect().Descriptor())
	if len(seen) < 8 {
		t.Fatalf("the walk reached %d messages, want the whole record", len(seen))
	}
}
