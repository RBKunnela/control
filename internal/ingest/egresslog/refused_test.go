package egresslog_test

import (
	"strings"
	"testing"

	"github.com/guardana/control/internal/ingest/egresslog"
)

func TestRefusals(t *testing.T) {
	cases := []struct {
		name, line, reason string
	}{
		{"an array", "[1]\n", "not_an_object"},
		{"a string", "\"x\"\n", "not_an_object"},
		{"null", "null\n", "not_an_object"},
		{"a blank line", "\n", "not_an_object"},
		{"a cut object", `{"start_time":` + "\n", "not_an_object"},
		{"two objects", `{} {}` + "\n", "not_an_object"},
		{"not UTF-8", "{\"start_time\":\"2026-10-04T10:00:00Z\",\"server_name\":\"a.example\",\"x\":\"\xff\"}\n", "not_an_object"},
		{"a mapped member twice", `{"start_time":"2026-10-04T10:00:00Z","server_name":"a.example","server_name":"b.example"}` + "\n", "duplicate_member"},
		{"an unmapped member twice", `{"start_time":"2026-10-04T10:00:00Z","server_name":"a.example","path":"/a","path":"/b"}` + "\n", "duplicate_member"},
		{"a member twice, once escaped", `{"start_time":"2026-10-04T10:00:00Z","\u0073tart_time":"2027-10-04T10:00:00Z","server_name":"a.example"}` + "\n", "duplicate_member"},
		{"time null", envoyLine("start_time", "null"), "time"},
		{"time dash", envoyLine("start_time", `"-"`), "time"},
		{"time absent", envoyLine("start_time", ""), "time"},
		{"time empty", envoyLine("start_time", `""`), "time"},
		{"time a word", envoyLine("start_time", `"yesterday"`), "time"},
		{"time with no zone", envoyLine("start_time", `"2026-10-04T10:00:00"`), "time"},
		{"time with a space", envoyLine("start_time", `"2026-10-04 10:00:00Z"`), "time"},
		{"time a number under rfc3339", envoyLine("start_time", `1791108000`), "time"},
		{"time an object", envoyLine("start_time", `{"s":1}`), "time"},
		{"a URL", envoyLine("server_name", `"https://api.example.com/v1?q=1"`), "destination"},
		{"a scheme alone", envoyLine("server_name", `"https://api.example.com"`), "destination"},
		{"a path", envoyLine("server_name", `"api.example.com/v1"`), "destination"},
		{"a query", envoyLine("server_name", `"api.example.com?q=1"`), "destination"},
		{"a fragment", envoyLine("server_name", `"api.example.com#top"`), "destination"},
		{"user@host", envoyLine("server_name", `"user@api.example.com"`), "destination"},
		{"a space", envoyLine("server_name", `"api .example.com"`), "destination"},
		{"a tab", envoyLine("server_name", `"api.example.com\t"`), "destination"},
		{"a host and port", envoyLine("server_name", `"api.example.com:443"`), "destination"},
		{"an IPv4 address and port", envoyLine("server_name", `"10.0.0.1:443"`), "destination"},
		{"a bracketed IPv6 literal", envoyLine("server_name", `"[2001:db8::1]"`), "destination"},
		{"an IPv6 zone", envoyLine("server_name", `"fe80::1%eth0"`), "destination"},
		{"an IDN in U-labels", envoyLine("server_name", `"bücher.example"`), "destination"},
		{"a Kelvin sign, which lowercases to k", envoyLine("server_name", `"\u212aube.example"`), "destination"},
		{"a fullwidth stop", envoyLine("server_name", `"api\uff0eexample.com"`), "destination"},
		{"a trailing dot", envoyLine("server_name", `"api.example.com."`), "destination"},
		{"an empty label", envoyLine("server_name", `"api..example.com"`), "destination"},
		{"a leading hyphen", envoyLine("server_name", `"-api.example.com"`), "destination"},
		{"a trailing hyphen", envoyLine("server_name", `"api-.example.com"`), "destination"},
		{"an underscore", envoyLine("server_name", `"_dmarc.example.com"`), "destination"},
		{"a label of 64 bytes", envoyLine("server_name", `"`+strings.Repeat("a", 64)+`.example"`), "destination"},
		{"a host of 254 bytes", envoyLine("server_name", `"`+host(254)+`"`), "destination"},
		{"a zero-padded IPv4 address", envoyLine("server_name", `"010.0.0.1"`), "destination"},
		{"an IPv4 octet over 255", envoyLine("server_name", `"256.0.0.1"`), "destination"},
		{"three octets", envoyLine("server_name", `"10.0.1"`), "destination"},
		{"destination dash", envoyLine("server_name", `"-"`), "destination"},
		{"destination null", envoyLine("server_name", "null"), "destination"},
		{"destination absent", envoyLine("server_name", ""), "destination"},
		{"destination a number", envoyLine("server_name", "7"), "destination"},
		{"destination a number with an exponent", envoyLine("server_name", "1e5"), "destination"},
		{"destination an object", envoyLine("server_name", `{"host":"api.example.com"}`), "destination"},
		{"port 0", envoyLine("upstream_remote_port", "0"), "port"},
		{"port 65536", envoyLine("upstream_remote_port", "65536"), "port"},
		{"port 0 as a string", envoyLine("upstream_remote_port", `"0"`), "port"},
		{"port negative", envoyLine("upstream_remote_port", "-1"), "port"},
		{"port a fraction", envoyLine("upstream_remote_port", "443.5"), "port"},
		{"port a word", envoyLine("upstream_remote_port", `"https"`), "port"},
		{"port a bool", envoyLine("upstream_remote_port", "true"), "port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := one(t, tc.line)
			if got := refusedFor(t, b); got != tc.reason || len(b.Observations) != 0 {
				t.Fatalf("refused for %q with %d observations, want %q", got, len(b.Observations), tc.reason)
			}
			if !b.Report.GetEveryRunDoubted() {
				t.Fatal("a refused line names no run, so it puts every run in doubt")
			}
		})
	}
}

// host is a name of n bytes, n at least 2, of labels at most 63 bytes.
func host(n int) string {
	var b strings.Builder
	for b.Len() < n {
		label := min(63, n-b.Len())
		if b.Len() > 0 {
			b.WriteByte('.')
			label = min(63, n-b.Len())
		}
		b.WriteString(strings.Repeat("h", label))
	}
	return b.String()
}

// padded is a valid Envoy line of exactly n bytes before its newline.
func padded(t *testing.T, n int) string {
	t.Helper()
	rest := strings.TrimPrefix(envoyLine("", ""), "{")
	fixed := len(`{"pad":"`) + len(`",`) + len(rest) - 1
	line := `{"pad":"` + strings.Repeat("x", n-fixed) + `",` + rest
	if len(line) != n+1 {
		t.Fatalf("padded line of %d bytes, want %d", len(line)-1, n)
	}
	return line
}

func TestLineBound(t *testing.T) {
	if b := one(t, padded(t, egresslog.MaxLineBytes)); len(b.Observations) != 1 {
		t.Fatalf("a line of exactly %d bytes: %v", egresslog.MaxLineBytes, b.Report.GetCounts())
	}
	b := one(t, padded(t, egresslog.MaxLineBytes+1))
	if got := refusedFor(t, b); got != "line_too_long" {
		t.Fatalf("a line of %d bytes refused for %q", egresslog.MaxLineBytes+1, got)
	}
	// The line after a long one is read whole, so a long line cannot hide
	// the start of the next.
	in := padded(t, 10*egresslog.MaxLineBytes) + envoyLine("server_name", `"next.example"`)
	b = importBytes(t, []byte(in), envoy(t))
	if c := b.Report.GetCounts(); c.GetRefusedBy()["line_too_long"] != 1 || len(b.Observations) != 1 ||
		b.Observations[0].GetSubject().GetName() != "next.example" {
		t.Fatalf("after a long line: %v", c)
	}
}

func TestHostHasExactlyTheBound(t *testing.T) {
	if n := len(host(253)); n != 253 {
		t.Fatalf("host(253) is %d bytes", n)
	}
	if got := only(t, one(t, envoyLine("server_name", `"`+host(253)+`"`))).host; got != host(253) {
		t.Fatalf("a host of 253 bytes read as %q", got)
	}
}
