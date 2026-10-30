package netname_test

import (
	"testing"

	"github.com/guardana/control/internal/netname"
)

// Whatever the input, a spelling any reader gives is one Host or Address
// keeps as it is.
func FuzzNames(f *testing.F) {
	for _, s := range []string{
		"api.example.com", "Registry.Example.ORG:443", "[2001:db8::1]:443", "::ffff:203.0.113.7",
		"10.0.0.7:50123", "path?token=x", "evil.example.", "fe80::1%eth0",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if h, ok := netname.Host(s); ok {
			if again, ok := netname.Host(h); !ok || again != h {
				t.Fatalf("Host(%q) = %q, not kept", s, h)
			}
		}
		if h, _, ok := netname.Authority(s); ok {
			if again, ok := netname.Host(h); !ok || again != h {
				t.Fatalf("Authority(%q) host %q, not kept by Host", s, h)
			}
		}
		if a, ok := netname.Address(s); ok {
			if again, ok := netname.Address(a); !ok || again != a {
				t.Fatalf("Address(%q) = %q, not kept", s, a)
			}
		}
	})
}
