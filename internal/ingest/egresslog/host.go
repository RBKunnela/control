package egresslog

import (
	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/netname"
	"github.com/guardana/control/internal/observe"
)

// destination reads the host a connection was made to under the mapping's
// form, in netname's one spelling, and the port an authority names, or 0. A
// value that is not a host alone, or not an authority, is refused whole,
// never parsed down to the host inside it.
func destination(v value, form observev1.DestinationForm) (string, uint32, bool) {
	if v.kind != kindString {
		return "", 0, false
	}
	switch form {
	case observev1.DestinationForm_DESTINATION_FORM_HOST:
		h, ok := netname.Host(v.text)
		return h, 0, ok
	case observev1.DestinationForm_DESTINATION_FORM_AUTHORITY:
		return netname.Authority(v.text)
	}
	return "", 0, false
}

// connectionPort is the line's port: the port member's, the authority's
// when the member is unset or unmapped, and 0 when neither gives one. A port
// member outside 1 to 65535, or one the authority contradicts, is refused.
func connectionPort(member value, authority uint32) (uint32, bool) {
	port, ok := portOf(member)
	switch {
	case !ok:
		return 0, false
	case port == 0:
		return authority, true
	case authority != 0 && authority != port:
		return 0, false
	}
	return port, true
}

// portOf reads a port of 1 to 65535, or 0 when the line says nothing.
func portOf(v value) (uint32, bool) {
	if v.unset() {
		return 0, true
	}
	n, ok := v.unsigned()
	if !ok || n < 1 || n > 65535 {
		return 0, false
	}
	return uint32(n), true
}

// caller reads the caller under the descriptor's basis: under
// CALLER_BASIS_ADDRESS an IP address, with a port or without one, in
// netname's one spelling, and under any other basis text a record keeps,
// copied as the proxy wrote it.
func caller(v value, basis observev1.CallerBasis) (string, bool) {
	if v.kind != kindString {
		return "", false
	}
	if basis == observev1.CallerBasis_CALLER_BASIS_ADDRESS {
		return netname.Address(v.text)
	}
	return v.text, observe.CopyableText(v.text)
}
