package egresslog

import (
	"strconv"
	"strings"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
)

// field is one value a connection is read from.
type field int

const (
	fieldTime field = iota
	fieldDestination
	fieldPort
	fieldMethod
	fieldStatus
	fieldBytesSent
	fieldBytesReceived
	fieldCaller
	fieldCount
)

var fieldNames = [fieldCount]string{"time", "destination", "port", "method", "status", "bytes_sent", "bytes_received", "caller"}

func (f field) String() string { return fieldNames[f] }

type fieldMember struct {
	field field
	name  string
}

// fieldMembers lists the member each field is mapped to, "" for none, in
// field order.
func fieldMembers(f *observev1.EgressFields) []fieldMember {
	return []fieldMember{
		{fieldTime, f.GetTime()},
		{fieldDestination, f.GetDestination()},
		{fieldPort, f.GetPort()},
		{fieldMethod, f.GetMethod()},
		{fieldStatus, f.GetStatus()},
		{fieldBytesSent, f.GetBytesSent()},
		{fieldBytesReceived, f.GetBytesReceived()},
		{fieldCaller, f.GetCaller()},
	}
}

// valueKind is what a mapped member's JSON value is.
type valueKind int

const (
	kindAbsent valueKind = iota
	kindNull
	kindString
	kindNumber
	kindOther
)

// value is a mapped member's value: a string decoded, a number as written,
// and no text for any other kind.
type value struct {
	kind valueKind
	text string
}

// unset reports a value that says nothing: absent, null, empty, or the dash
// both Envoy and Squid write for a value they do not have.
func (v value) unset() bool {
	return v.kind == kindAbsent || v.kind == kindNull || (v.kind == kindString && (v.text == "" || v.text == "-"))
}

// unsigned reads a count written as a JSON number or a decimal string, and
// reports false for any other value: a sign, a fraction or an exponent among
// them, and the empty text of every other kind.
func (v value) unsigned() (uint64, bool) {
	n, err := strconv.ParseUint(v.text, 10, 64)
	return n, err == nil
}

func digits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}
