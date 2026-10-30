package egresslog_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/ingest/egresslog"
	"github.com/guardana/control/internal/observe"
	"google.golang.org/protobuf/proto"
)

// neutral is the Envoy descriptor through the neutral checks alone, so a
// test can change one member and hand it to Check.
func neutral(t *testing.T) *observev1.SourceDescriptor {
	t.Helper()
	d, err := observe.ReadNeutral(readTestdata(t, "envoy.descriptor.json"))
	if err != nil {
		t.Fatalf("ReadNeutral: %v", err)
	}
	return d
}

func TestCheckAcceptsTheFixtures(t *testing.T) {
	for _, name := range []string{"envoy.descriptor.json", "squid.descriptor.json"} {
		loadDescriptor(t, name)
	}
}

func TestCheckRefuses(t *testing.T) {
	cases := []struct {
		name   string
		change func(d *observev1.SourceDescriptor)
		member string
	}{
		{"no mapping", func(d *observev1.SourceDescriptor) { d.EgressAccessLog = nil }, "egress_access_log"},
		{"another kind", func(d *observev1.SourceDescriptor) { d.Kind = observe.KindOTelGenAI }, "kind"},
		{"no format", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Format = "" }, "format"},
		{"another format", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Format = "json" }, "format"},
		{"no fields", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields = nil }, "fields.time"},
		{"no time", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields.Time = "" }, "fields.time"},
		{"no destination", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields.Destination = "" }, "fields.destination"},
		{"no time format", func(d *observev1.SourceDescriptor) {
			d.EgressAccessLog.Fields.TimeFormat = observev1.TimeFormat_TIME_FORMAT_UNSPECIFIED
		}, "fields.time_format"},
		{"an undeclared time format", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields.TimeFormat = 9 }, "fields.time_format"},
		{"no destination form", func(d *observev1.SourceDescriptor) {
			d.EgressAccessLog.Fields.DestinationForm = observev1.DestinationForm_DESTINATION_FORM_UNSPECIFIED
		}, "fields.destination_form"},
		{"an undeclared destination form", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields.DestinationForm = 3 }, "fields.destination_form"},
		{"two fields, one member", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields.Port = "start_time" }, "fields.port"},
		{"a name of 129 bytes", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields.Method = strings.Repeat("m", 129) }, "fields.method"},
		{"a control character", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields.Status = "status\n" }, "fields.status"},
		{"a format character", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields.BytesSent = "sent\u200b" }, "fields.bytes_sent"},
		{"whitespace only", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields.BytesReceived = "  " }, "fields.bytes_received"},
		{"a caller with no basis", func(d *observev1.SourceDescriptor) {
			d.EgressAccessLog.CallerBasis = observev1.CallerBasis_CALLER_BASIS_UNSPECIFIED
		}, "caller_basis"},
		{"a caller with an undeclared basis", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.CallerBasis = 7 }, "caller_basis"},
		{"a basis with no caller", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields.Caller = "" }, "caller_basis"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := neutral(t)
			tc.change(d)
			err := egresslog.Check(d)
			if !errors.Is(err, egresslog.ErrDescriptor) || !strings.Contains(err.Error(), tc.member+":") {
				t.Fatalf("Check = %v, want ErrDescriptor naming %s", err, tc.member)
			}
			if _, err := egresslog.Import(strings.NewReader(envoyLine("", "")), d, descSHA, received); !errors.Is(err, egresslog.ErrDescriptor) {
				t.Fatalf("Import = %v, want ErrDescriptor", err)
			}
		})
	}
	if err := egresslog.Check(nil); !errors.Is(err, egresslog.ErrDescriptor) {
		t.Fatalf("Check(nil) = %v", err)
	}
}

// The bounds and the optional members, at the input where each changes the
// result.
func TestCheckAccepts(t *testing.T) {
	cases := []struct {
		name   string
		change func(d *observev1.SourceDescriptor)
	}{
		{"a name of 128 bytes", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields.Method = strings.Repeat("m", 128) }},
		{"only time and destination", func(d *observev1.SourceDescriptor) {
			d.EgressAccessLog.Fields = &observev1.EgressFields{
				Time: "t", TimeFormat: observev1.TimeFormat_TIME_FORMAT_UNIX_MILLISECONDS, Destination: "d",
				DestinationForm: observev1.DestinationForm_DESTINATION_FORM_AUTHORITY,
			}
			d.EgressAccessLog.CallerBasis = observev1.CallerBasis_CALLER_BASIS_UNSPECIFIED
		}},
		{"a caller named none", func(d *observev1.SourceDescriptor) {
			d.EgressAccessLog.CallerBasis = observev1.CallerBasis_CALLER_BASIS_NONE
		}},
		{"a name with a dot and a space", func(d *observev1.SourceDescriptor) { d.EgressAccessLog.Fields.Caller = "client ip.v4" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := neutral(t)
			tc.change(d)
			if err := egresslog.Check(d); err != nil {
				t.Fatalf("Check = %v", err)
			}
		})
	}
}

func TestImportRefusesWhatItCannotServe(t *testing.T) {
	d := envoy(t)
	in := envoyLine("", "")
	if _, err := egresslog.Import(nil, d, descSHA, received); err == nil {
		t.Fatal("a nil reader imported")
	}
	if _, err := egresslog.Import(strings.NewReader(in), nil, descSHA, received); !errors.Is(err, egresslog.ErrDescriptor) {
		t.Fatalf("nil descriptor: %v", err)
	}
	for _, sha := range []string{"", strings.ToUpper(descSHA), descSHA[:63], descSHA + "0", strings.Repeat("g", 64)} {
		if _, err := egresslog.Import(strings.NewReader(in), d, sha, received); !errors.Is(err, egresslog.ErrDescriptor) {
			t.Fatalf("digest %q: %v", sha, err)
		}
	}
	// A descriptor the neutral checks refuse is refused here too, so a
	// caller cannot skip them by calling Import alone.
	otel, ok := proto.Clone(d).(*observev1.SourceDescriptor)
	if !ok {
		t.Fatal("clone")
	}
	otel.HeartbeatSeconds = 0
	if _, err := egresslog.Import(strings.NewReader(in), otel, descSHA, received); !errors.Is(err, egresslog.ErrDescriptor) {
		t.Fatalf("heartbeat 0: %v", err)
	}
	for _, at := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, err := egresslog.Import(strings.NewReader(in), d, descSHA, at); !errors.Is(err, egresslog.ErrReceived) {
			t.Fatalf("received %v: %v", at, err)
		}
	}
}

// An input declared independent is one the agent cannot write, so the
// command refuses one that group or others can: InputForbidden names those
// bits, and the file reader the command uses refuses them.
func TestInputForbidden(t *testing.T) {
	d := envoy(t)
	if got := egresslog.InputForbidden(d); got != 0o022 {
		t.Fatalf("independent: %v, want 0o022", got)
	}
	for _, trust := range []observev1.Trust{observev1.Trust_TRUST_PLATFORM, observev1.Trust_TRUST_SELF_REPORTED} {
		other, ok := proto.Clone(d).(*observev1.SourceDescriptor)
		if !ok {
			t.Fatal("clone")
		}
		other.Trust = trust
		if got := egresslog.InputForbidden(other); got != 0 {
			t.Fatalf("%s: %v, want 0", trust, got)
		}
	}
	in := []byte(envoyLine("", ""))
	for _, tc := range []struct {
		mode fs.FileMode
		ok   bool
	}{{0o600, true}, {0o644, true}, {0o620, false}, {0o602, false}, {0o666, false}} {
		path := writeMode(t, in, tc.mode)
		raw, err := files.ReadRegular(path, 1<<20, egresslog.InputForbidden(d))
		switch {
		case tc.ok && (err != nil || !bytes.Equal(raw, in)):
			t.Fatalf("%v: %v", tc.mode, err)
		case !tc.ok && err == nil:
			t.Fatalf("%v: an input others can write was read under independent trust", tc.mode)
		}
	}
}

// writeMode writes b to a fresh file whose permission bits are exactly mode,
// whatever the umask.
func writeMode(t *testing.T, b []byte, mode fs.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "egress.jsonl")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
