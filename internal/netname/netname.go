package netname

import (
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/guardana/control/internal/observe"
)

// maxLabelBytes bounds one label of a name, as DNS does.
const maxLabelBytes = 63

// Host reads s as a host in its one spelling, or reports false. A name is
// lowercased and held to LDH labels and observe.MaxHostBytes; an IPv4 address
// is a dotted quad; an IPv6 address is written as net/netip writes it, with no
// zone and no brackets, and one that maps an IPv4 address is that address.
// None of these admits a scheme, a path, a query, a fragment, user
// information, a port or whitespace, so a URL is refused whole, never parsed
// down to the host inside it. A name in U-labels is refused: mapping it to
// A-labels needs IDNA tables this build does not carry, and an A-label is
// taken as written.
func Host(s string) (string, bool) {
	// Checked before lowercasing, which maps some non-ASCII letters, the
	// Kelvin sign among them, to ASCII ones.
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return "", false
		}
	}
	if strings.Contains(s, ":") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return "", false
		}
		return a.Unmap().String(), true
	}
	s = strings.ToLower(s)
	if len(s) > observe.MaxHostBytes {
		return "", false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if !ldh(l) {
			return "", false
		}
	}
	// A top-level label is never all digits, so a name ending in one is an
	// IPv4 address, which has no colon, or nothing: never a second spelling
	// of one.
	if digits(labels[len(labels)-1]) {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return "", false
		}
		return a.String(), true
	}
	return s, true
}

// Authority reads s as host, host:port, [v6] or [v6]:port, as a forward
// proxy's request names its target, and returns the host as Host spells it
// and the port, 1 to 65535, or 0 when s names none. An IPv6 address without
// brackets, a dotted IPv4 address inside them and a colon with no port after
// it are refused; an IPv6 address inside them that maps an IPv4 address is
// that IPv4 address, as Host writes it.
func Authority(s string) (string, uint32, bool) {
	host, port, hasPort, ok := splitAuthority(s)
	if !ok {
		return "", 0, false
	}
	var n uint32
	if hasPort {
		if n, ok = portNumber(port); !ok {
			return "", 0, false
		}
	}
	h, ok := Host(host)
	if !ok {
		return "", 0, false
	}
	return h, n, true
}

// splitAuthority splits s into its host and the port text after its colon,
// if it has one. A bracketed host must be an IPv6 address with no zone, and
// an unbracketed one holds no colon.
func splitAuthority(s string) (string, string, bool, bool) {
	rest, bracketed := strings.CutPrefix(s, "[")
	if !bracketed {
		i := strings.LastIndexByte(s, ':')
		if i < 0 {
			return s, "", false, true
		}
		if strings.Contains(s[:i], ":") {
			return "", "", false, false
		}
		return s[:i], s[i+1:], true, true
	}
	inner, after, ok := strings.Cut(rest, "]")
	if !ok {
		return "", "", false, false
	}
	a, err := netip.ParseAddr(inner)
	if err != nil || !a.Is6() || a.Zone() != "" {
		return "", "", false, false
	}
	if after == "" {
		return inner, "", false, true
	}
	port, hasPort := strings.CutPrefix(after, ":")
	return inner, port, hasPort, hasPort
}

// Address reads s as an IP address, alone or with a port of 1 to 65535 as
// address:port or [v6]:port, and returns it as net/netip writes it, an
// address that maps an IPv4 address written as that address. Anything else,
// a name or a path among them, is refused.
func Address(s string) (string, bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			return "", false
		}
		return a.Unmap().String(), true
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil || ap.Addr().Zone() != "" || ap.Port() == 0 {
		return "", false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String(), true
}

func portNumber(s string) (uint32, bool) {
	if !digits(s) {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

// ldh reports a label of 1 to 63 letters, digits and hyphens that neither
// starts nor ends with a hyphen. s is lowercase.
func ldh(s string) bool {
	if s == "" || len(s) > maxLabelBytes || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func digits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}
