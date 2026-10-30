package egresslog_test

import (
	"strings"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/ingest/egresslog"
	"google.golang.org/protobuf/proto"
)

// base is the connection envoyLine("", "") holds.
func base() conn {
	return conn{host: "api.example.com", port: 443, method: "CONNECT", status: 200, sent: 52011, received: 1834,
		caller: "10.0.0.7", basis: address, at: "2026-10-04T10:00:00.25Z"}
}

func TestKept(t *testing.T) {
	cases := []struct {
		name, member, raw string
		change            func(c *conn)
		dropped           uint64
	}{
		{"a host in capitals", "server_name", `"API.Example.COM"`, func(c *conn) { c.host = "api.example.com" }, 0},
		{"an A-label", "server_name", `"xn--bcher-kva.example"`, func(c *conn) { c.host = "xn--bcher-kva.example" }, 0},
		{"a label of 63 bytes", "server_name", `"` + strings.Repeat("a", 63) + `.example"`,
			func(c *conn) { c.host = strings.Repeat("a", 63) + ".example" }, 0},
		{"a digit-led label", "server_name", `"3com.example"`, func(c *conn) { c.host = "3com.example" }, 0},
		{"an IPv4 address", "server_name", `"10.0.0.1"`, func(c *conn) { c.host = "10.0.0.1" }, 0},
		{"an IPv6 literal", "server_name", `"2001:DB8:0:0::1"`, func(c *conn) { c.host = "2001:db8::1" }, 0},
		{"an escaped host", "server_name", `"api\u002eexample.com"`, func(c *conn) { c.host = "api.example.com" }, 0},
		{"port 1", "upstream_remote_port", "1", func(c *conn) { c.port = 1 }, 0},
		{"port 65535", "upstream_remote_port", "65535", func(c *conn) { c.port = 65535 }, 0},
		{"port as a string", "upstream_remote_port", `"8443"`, func(c *conn) { c.port = 8443 }, 0},
		{"port null", "upstream_remote_port", "null", func(c *conn) { c.port = 0 }, 0},
		{"port dash", "upstream_remote_port", `"-"`, func(c *conn) { c.port = 0 }, 0},
		{"port absent", "upstream_remote_port", "", func(c *conn) { c.port = 0 }, 0},
		{"port empty", "upstream_remote_port", `""`, func(c *conn) { c.port = 0 }, 0},
		{"a method in lower case", "method", `"get"`, func(c *conn) { c.method = "" }, 1},
		{"an unlisted method", "method", `"BREW"`, func(c *conn) { c.method = "" }, 1},
		{"a method that is a number", "method", "7", func(c *conn) { c.method = "" }, 1},
		{"each listed method", "method", `"TRACE"`, func(c *conn) { c.method = "TRACE" }, 0},
		{"method dash", "method", `"-"`, func(c *conn) { c.method = "" }, 0},
		{"status 0, the proxy saying nothing", "response_code", "0", func(c *conn) { c.status = 0 }, 0},
		{"status 100", "response_code", "100", func(c *conn) { c.status = 100 }, 0},
		{"status 599", "response_code", `"599"`, func(c *conn) { c.status = 599 }, 0},
		{"status 99", "response_code", "99", func(c *conn) { c.status = 0 }, 1},
		{"status 600", "response_code", "600", func(c *conn) { c.status = 0 }, 1},
		{"status a word", "response_code", `"ok"`, func(c *conn) { c.status = 0 }, 1},
		{"bytes negative", "bytes_sent", "-1", func(c *conn) { c.sent = 0 }, 1},
		{"bytes past uint64", "bytes_sent", "18446744073709551616", func(c *conn) { c.sent = 0 }, 1},
		{"bytes at uint64", "bytes_received", "18446744073709551615", func(c *conn) { c.received = 18446744073709551615 }, 0},
		{"bytes an object", "bytes_received", `{"n":1}`, func(c *conn) { c.received = 0 }, 1},
		{"bytes an exponent", "bytes_received", "1e3", func(c *conn) { c.received = 0 }, 1},
		{"an address with a port", "downstream_remote_address", `"10.0.0.7:50123"`, func(c *conn) { c.caller = "10.0.0.7:50123" }, 0},
		{"an IPv6 address", "downstream_remote_address", `"2001:DB8::7"`, func(c *conn) { c.caller = "2001:db8::7" }, 0},
		{"an IPv6 address with a port", "downstream_remote_address", `"[2001:db8:0::7]:50123"`, func(c *conn) { c.caller = "[2001:db8::7]:50123" }, 0},
		{"a mapped IPv4 address", "downstream_remote_address", `"::ffff:10.0.0.7"`, func(c *conn) { c.caller = "10.0.0.7" }, 0},
		{"caller dash", "downstream_remote_address", `"-"`, noCaller, 0},
		{"caller absent", "downstream_remote_address", "", noCaller, 0},
		{"a future time, kept as read", "start_time", `"2099-01-01T00:00:00Z"`, func(c *conn) { c.at = "2099-01-01T00:00:00Z" }, 0},
		{"a time with an offset", "start_time", `"2026-10-04T12:00:00.5+02:00"`, func(c *conn) { c.at = "2026-10-04T10:00:00.5Z" }, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := one(t, envoyLine(tc.member, tc.raw))
			want := base()
			tc.change(&want)
			if got := only(t, b); got != want {
				t.Fatalf("\n got %+v\nwant %+v", got, want)
			}
			if got := b.Report.GetCounts().GetStringsDropped(); got != tc.dropped {
				t.Fatalf("strings_dropped %d, want %d", got, tc.dropped)
			}
			if got := b.Report.GetCounts().GetCallersDropped(); got != 0 {
				t.Fatalf("callers_dropped %d, want 0", got)
			}
		})
	}
}

// Under an address basis a caller is an IP address or nothing: anything else
// is dropped and counted as a caller dropped, and the connection kept, so a
// mapping that names a content member copies no content.
func TestAnAddressCallerIsAnAddress(t *testing.T) {
	for _, raw := range []string{
		`"path?token=x"`, `"/v2/private-repo/manifests/latest?token=not-a-real-token"`, `"alice"`, `"workload.example"`,
		`"10.0.0.7:0"`, `"[2001:db8::7]"`, `"fe80::1%eth0"`, `"010.0.0.7"`, `"10.0.0.7/32"`, `"10.0.0.7\u202e"`, "7", "true",
	} {
		b := one(t, envoyLine("downstream_remote_address", raw))
		want := base()
		noCaller(&want)
		if got := only(t, b); got != want {
			t.Fatalf("%s:\n got %+v\nwant %+v", raw, got, want)
		}
		c := b.Report.GetCounts()
		if c.GetCallersDropped() != 1 || c.GetStringsDropped() != 0 {
			t.Fatalf("%s: callers_dropped %d, strings_dropped %d; want 1 and 0", raw, c.GetCallersDropped(), c.GetStringsDropped())
		}
		if b.Report.GetSchemaVersion() != "0.3" {
			t.Fatalf("%s: report schema %q", raw, b.Report.GetSchemaVersion())
		}
	}
}

// Under any other basis a caller is opaque text within the text rules.
func TestAnAuthenticatedCallerIsText(t *testing.T) {
	d, ok := proto.Clone(envoy(t)).(*observev1.SourceDescriptor)
	if !ok {
		t.Fatal("clone")
	}
	d.EgressAccessLog.CallerBasis = authenticated
	cases := []struct {
		name, member, raw string
		change            func(c *conn)
		dropped           uint64
	}{
		{"a caller of 256 bytes", "downstream_remote_address", `"` + strings.Repeat("c", 256) + `"`,
			func(c *conn) { c.caller, c.basis = strings.Repeat("c", 256), authenticated }, 0},
		{"a caller of 257 bytes", "downstream_remote_address", `"` + strings.Repeat("c", 257) + `"`, noCaller, 1},
		{"a caller of 300 bytes with a control character", "downstream_remote_address",
			`"` + strings.Repeat("c", 150) + `\u0007` + strings.Repeat("c", 149) + `"`, noCaller, 1},
		{"a caller with a control character", "downstream_remote_address", `"10.0.0.7\n"`, noCaller, 1},
		{"a caller with a format character", "downstream_remote_address", `"10.0.0.7\u202e"`, noCaller, 1},
		{"a caller of whitespace", "downstream_remote_address", `"   "`, noCaller, 1},
		{"a caller with private use", "downstream_remote_address", `"a\ue000"`, noCaller, 1},
		{"a caller with a line separator", "downstream_remote_address", `"a\u2028b"`, noCaller, 1},
		{"a caller with a paragraph separator", "downstream_remote_address", `"a\u2029b"`, noCaller, 1},
		{"a caller with a lone surrogate", "downstream_remote_address", `"a\ud800"`, noCaller, 1},
		{"a caller with a noncharacter", "downstream_remote_address", `"a\ufdd0"`, noCaller, 1},
		{"a caller with U+FFFF", "downstream_remote_address", `"a\uffff"`, noCaller, 1},
		{"a caller beyond ASCII", "downstream_remote_address", `"zoë"`, func(c *conn) { c.caller, c.basis = "zoë", authenticated }, 0},
		{"a caller that is a number", "downstream_remote_address", "7", noCaller, 1},
		{"caller dash", "downstream_remote_address", `"-"`, noCaller, 0},
		{"caller absent", "downstream_remote_address", "", noCaller, 0},
		{"a path", "downstream_remote_address", `"path?token=x"`, func(c *conn) { c.caller, c.basis = "path?token=x", authenticated }, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := importBytes(t, []byte(envoyLine(tc.member, tc.raw)), d)
			want := base()
			tc.change(&want)
			if got := only(t, b); got != want {
				t.Fatalf("\n got %+v\nwant %+v", got, want)
			}
			c := b.Report.GetCounts()
			if c.GetStringsDropped() != tc.dropped || c.GetCallersDropped() != 0 {
				t.Fatalf("strings_dropped %d, callers_dropped %d; want %d and 0", c.GetStringsDropped(), c.GetCallersDropped(), tc.dropped)
			}
		})
	}
}

// noCaller is a connection whose caller was dropped or never given: its
// basis is then none, since a basis needs a caller.
func noCaller(c *conn) { c.caller, c.basis = "", none }

func TestListedMethods(t *testing.T) {
	for _, m := range []string{"CONNECT", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"} {
		if got := only(t, one(t, envoyLine("method", `"`+m+`"`))).method; got != m {
			t.Fatalf("%s read as %q", m, got)
		}
	}
}

func TestTimeFormats(t *testing.T) {
	cases := []struct {
		format observev1.TimeFormat
		raw    string
		at     string
	}{
		{observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS, "1791108000", "2026-10-04T10:00:00Z"},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS, "1791108000.250", "2026-10-04T10:00:00.25Z"},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS, `"1791108000.000000001"`, "2026-10-04T10:00:00.000000001Z"},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS, "0", "1970-01-01T00:00:00Z"},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_MILLISECONDS, "1791108000250", "2026-10-04T10:00:00.25Z"},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_MILLISECONDS, `"1791108000250"`, "2026-10-04T10:00:00.25Z"},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS, "253402300799", "9999-12-31T23:59:59Z"},
	}
	for _, tc := range cases {
		b := timed(t, tc.format, tc.raw)
		if got := only(t, b).at; got != tc.at {
			t.Fatalf("%s %s read as %s, want %s", tc.format, tc.raw, got, tc.at)
		}
	}
	refused := []struct {
		format observev1.TimeFormat
		raw    string
	}{
		{observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS, "1791108000.0000000001"},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS, `"1791108000."`},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS, "-1"},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS, "1e9"},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS, "253402300800"},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS, `"-"`},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_SECONDS, `"2026-10-04T10:00:00Z"`},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_MILLISECONDS, "1791108000250.5"},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_MILLISECONDS, "99999999999999999999"},
		{observev1.TimeFormat_TIME_FORMAT_UNIX_MILLISECONDS, "null"},
	}
	for _, tc := range refused {
		b := timed(t, tc.format, tc.raw)
		if got := refusedFor(t, b); got != "time" {
			t.Fatalf("%s %s refused for %q, want time", tc.format, tc.raw, got)
		}
	}
}

// timed imports an Envoy line whose time is raw under a descriptor reading
// format.
func timed(t *testing.T, format observev1.TimeFormat, raw string) egresslog.Batch {
	t.Helper()
	d, ok := proto.Clone(envoy(t)).(*observev1.SourceDescriptor)
	if !ok {
		t.Fatal("clone")
	}
	d.EgressAccessLog.Fields.TimeFormat = format
	return importBytes(t, []byte(envoyLine("start_time", raw)), d)
}
