package egresslog_test

import (
	"strings"
	"testing"
)

// proxyLine is a forward proxy's line: envoyLine with the authority in place
// of the SNI host, and the port member given as port, or left out when "".
func proxyLine(authority, port string) string {
	line := envoyLine("server_name", "")
	line = strings.Replace(line, `{`, `{"authority":`+authority+`,`, 1)
	if port == "" {
		return strings.Replace(line, `"upstream_remote_port":443,`, ``, 1)
	}
	return strings.Replace(line, `"upstream_remote_port":443`, `"upstream_remote_port":`+port, 1)
}

func TestAnAuthorityIsSplit(t *testing.T) {
	cases := []struct {
		name, authority, port, host string
		want                        uint32
	}{
		{"both ways, agreeing", `"api.example.com:443"`, "443", "api.example.com", 443},
		{"the port member null", `"api.example.com:8443"`, "null", "api.example.com", 8443},
		{"the port member a dash", `"api.example.com:8443"`, `"-"`, "api.example.com", 8443},
		{"the port member absent", `"api.example.com:8443"`, "", "api.example.com", 8443},
		{"the port member as a string, agreeing", `"api.example.com:8443"`, `"8443"`, "api.example.com", 8443},
		{"a host in capitals", `"API.Example.COM:443"`, "443", "api.example.com", 443},
		{"an IPv4 address", `"203.0.113.7:443"`, "443", "203.0.113.7", 443},
		{"an IPv6 address", `"[2001:DB8:0::1]:443"`, "443", "2001:db8::1", 443},
		{"a mapped IPv4 address", `"[::ffff:203.0.113.7]:443"`, "443", "203.0.113.7", 443},
		{"port 65535", `"api.example.com:65535"`, "null", "api.example.com", 65535},
		{"a host alone, the port member giving the port", `"registry.example.org"`, "80", "registry.example.org", 80},
		{"a host alone, and no port member", `"registry.example.org"`, "", "registry.example.org", 0},
		{"a host alone, the port member null", `"Registry.Example.ORG"`, "null", "registry.example.org", 0},
		{"an IPv6 address in brackets alone", `"[2001:db8::1]"`, "", "2001:db8::1", 0},
		{"an IPv6 address in brackets alone, the port member giving the port", `"[2001:db8::1]"`, "8443", "2001:db8::1", 8443},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := only(t, importBytes(t, []byte(proxyLine(tc.authority, tc.port)), forwardProxy(t)))
			if got.host != tc.host || got.port != tc.want {
				t.Fatalf("host %q port %d, want %q %d", got.host, got.port, tc.host, tc.want)
			}
		})
	}
}

func TestAnAuthorityIsRefusedWhole(t *testing.T) {
	cases := []struct{ name, authority, port, reason string }{
		{"an IPv6 address with no brackets", `"2001:db8::1"`, "443", "destination"},
		{"an IPv6 address and a port with no brackets", `"2001:db8::1:443"`, "443", "destination"},
		{"a colon with no port", `"registry.example.org:"`, "80", "destination"},
		{"brackets with a colon and no port", `"[2001:db8::1]:"`, "443", "destination"},
		{"an IPv4 address in brackets", `"[203.0.113.7]:443"`, "443", "destination"},
		{"an IPv4 address in brackets alone", `"[203.0.113.7]"`, "443", "destination"},
		{"a zone", `"[fe80::1%eth0]:443"`, "443", "destination"},
		{"a zone with no brackets", `"fe80::1%eth0"`, "443", "destination"},
		{"a trailing dot", `"exfil.example.net.:443"`, "443", "destination"},
		{"an underscore", `"my_host.exfil.example.net:443"`, "443", "destination"},
		{"a URL", `"https://api.example.com:443/v1"`, "443", "destination"},
		{"a path after the port", `"api.example.com:443/v1"`, "443", "destination"},
		{"user information", `"user@api.example.com:443"`, "443", "destination"},
		{"port 0", `"api.example.com:0"`, "null", "destination"},
		{"port 65536", `"api.example.com:65536"`, "null", "destination"},
		{"a signed port", `"api.example.com:+443"`, "null", "destination"},
		{"dash", `"-"`, "443", "destination"},
		{"null", "null", "443", "destination"},
		{"the port given both ways, disagreeing", `"api.example.com:443"`, "8443", "port"},
		{"the port member out of range", `"api.example.com:443"`, "70000", "port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := importBytes(t, []byte(proxyLine(tc.authority, tc.port)), forwardProxy(t))
			if got := refusedFor(t, b); got != tc.reason {
				t.Fatalf("refused for %q, want %q", got, tc.reason)
			}
		})
	}
}

// Under the host form an authority is not a host, and an IPv4-mapped IPv6
// address is the IPv4 address it maps.
func TestTheHostFormTakesAHostAlone(t *testing.T) {
	if got := refusedFor(t, one(t, envoyLine("server_name", `"api.example.com:443"`))); got != "destination" {
		t.Fatalf("an authority under the host form refused for %q", got)
	}
	if got := only(t, one(t, envoyLine("server_name", `"::ffff:203.0.113.7"`))).host; got != "203.0.113.7" {
		t.Fatalf("a mapped address read as %q", got)
	}
}
