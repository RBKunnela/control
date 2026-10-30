package netname_test

import (
	"strings"
	"testing"

	"github.com/guardana/control/internal/netname"
	"github.com/guardana/control/pkg/contract"
	"pgregory.net/rapid"
)

func TestHost(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"api.example.com", "api.example.com"},
		{"Registry.Example.ORG", "registry.example.org"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"203.0.113.7", "203.0.113.7"},
		{"2001:0DB8:0000::1", "2001:db8::1"},
		{"::ffff:203.0.113.7", "203.0.113.7"},
		{"::ffff:cb00:7107", "203.0.113.7"},
		{"a." + strings.Repeat("b", 63), "a." + strings.Repeat("b", 63)},
		{strings.Repeat("a.", 126) + "a", strings.Repeat("a.", 126) + "a"},
	} {
		got, ok := netname.Host(c.in)
		if !ok || got != c.want {
			t.Errorf("Host(%q) = %q, %v; want %q", c.in, got, ok, c.want)
		}
	}
}

func TestHostRefuses(t *testing.T) {
	for _, in := range []string{
		"", "-", "evil.example.", ".evil.example", "my_host.example", "[2001:db8::1]", "fe80::1%eth0",
		"api.example.com:443", "https://api.example.com/", "user@api.example.com", "api.example.com/x",
		"a b.example", "-a.example", "a-.example", "a..example", "0x7f.1", "001.2.3.4", "1.2.3.4.5", "123",
		"a.123", "Kelvin.example", "bücher.example", "a." + strings.Repeat("b", 64),
		strings.Repeat("a.", 126) + "ab",
	} {
		if got, ok := netname.Host(in); ok {
			t.Errorf("Host(%q) = %q, want refused", in, got)
		}
	}
}

func TestAuthority(t *testing.T) {
	for _, c := range []struct {
		in, host string
		port     uint32
	}{
		{"api.example.com:443", "api.example.com", 443},
		{"Registry.Example.ORG:8443", "registry.example.org", 8443},
		{"203.0.113.7:1", "203.0.113.7", 1},
		{"[2001:DB8::1]:65535", "2001:db8::1", 65535},
		{"[::ffff:203.0.113.7]:80", "203.0.113.7", 80},
		{"registry.example.org", "registry.example.org", 0},
		{"Registry.Example.ORG", "registry.example.org", 0},
		{"203.0.113.7", "203.0.113.7", 0},
		{"[2001:db8::1]", "2001:db8::1", 0},
		{"[::ffff:203.0.113.7]", "203.0.113.7", 0},
	} {
		host, port, ok := netname.Authority(c.in)
		if !ok || host != c.host || port != c.port {
			t.Errorf("Authority(%q) = %q, %d, %v; want %q, %d", c.in, host, port, ok, c.host, c.port)
		}
	}
}

func TestAuthorityRefuses(t *testing.T) {
	for _, in := range []string{
		"", "-", ":", "api.example.com:", "api.example.com:0", "api.example.com:65536",
		"api.example.com:+443", "api.example.com:44 3", "api.example.com:443/x", ":443",
		"2001:db8::1", "2001:db8::1:443", "::1", "[2001:db8::1]:", "[2001:db8::1]443", "[2001:db8::1]]",
		"[2001:db8::1", "[]", "[203.0.113.7]", "[203.0.113.7]:443", "[fe80::1%eth0]", "[fe80::1%eth0]:443",
		"fe80::1%eth0", "[api.example.com]:443", "evil.example.", "evil.example.:443",
		"https://api.example.com:443", "user@api.example.com:443", "a:b:443", "api.example.com/x",
	} {
		if host, port, ok := netname.Authority(in); ok {
			t.Errorf("Authority(%q) = %q, %d, want refused", in, host, port)
		}
	}
}

func TestAddress(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"10.0.0.7", "10.0.0.7"},
		{"10.0.0.7:50123", "10.0.0.7:50123"},
		{"2001:DB8::7", "2001:db8::7"},
		{"[2001:db8:0::7]:50123", "[2001:db8::7]:50123"},
		{"::ffff:10.0.0.7", "10.0.0.7"},
		{"[::ffff:10.0.0.7]:50123", "10.0.0.7:50123"},
	} {
		got, ok := netname.Address(c.in)
		if !ok || got != c.want {
			t.Errorf("Address(%q) = %q, %v; want %q", c.in, got, ok, c.want)
		}
	}
}

func TestAddressRefuses(t *testing.T) {
	for _, in := range []string{
		"", "-", "alice", "path?token=x", "/v2/private-repo/manifests/latest?token=x", "workload.example",
		"10.0.0.7:0", "10.0.0.7:65536", "[2001:db8::7]", "fe80::1%eth0", "[fe80::1%eth0]:1", "010.0.0.7",
		"10.0.0.7/32", " 10.0.0.7",
	} {
		if got, ok := netname.Address(in); ok {
			t.Errorf("Address(%q) = %q, want refused", in, got)
		}
	}
}

// A spelling Host gives is one Host keeps, and one the destination host
// rule of the contract accepts.
func TestHostIsAFixedPoint(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := rapid.OneOf(
			rapid.StringMatching(`[A-Za-z0-9-]{1,10}(\.[A-Za-z0-9-]{1,10}){0,3}`),
			rapid.StringMatching(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`),
			rapid.StringMatching(`[0-9a-fA-F:.]{2,40}`),
		).Draw(t, "in")
		h, ok := netname.Host(in)
		if !ok {
			return
		}
		again, ok := netname.Host(h)
		if !ok || again != h {
			t.Fatalf("Host(%q) = %q, and Host of that = %q, %v", in, h, again, ok)
		}
		if err := contract.CheckHost(h); err != nil {
			t.Fatalf("Host(%q) = %q, which the contract refuses: %v", in, h, err)
		}
	})
}

func TestAddressIsAFixedPoint(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := rapid.StringMatching(`\[?[0-9a-fA-F:.]{2,40}\]?(:[0-9]{1,5})?`).Draw(t, "in")
		a, ok := netname.Address(in)
		if !ok {
			return
		}
		if again, ok := netname.Address(a); !ok || again != a {
			t.Fatalf("Address(%q) = %q, and Address of that = %q, %v", in, a, again, ok)
		}
	})
}
