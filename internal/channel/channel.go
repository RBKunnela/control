package channel

// The kinds of call an envelope's action kind names, spelled exactly.
const (
	KindTool     = "tool"
	KindPrompt   = "prompt"
	KindResource = "resource"
)

// The protocols the plane's adapters speak, as an envelope's action protocol
// and an adapter's name spell them.
const (
	ProtocolMCP     = "mcp"
	ProtocolEnforce = "enforce"
)

// Strength is how far an adapter can keep a call from its effect. The values
// are ordered: each one can do what the one before it does. The zero value is
// StrengthNone, so a strength nobody stated enforces nothing.
type Strength uint8

const (
	// StrengthNone is an adapter that cannot keep a call from its effect.
	StrengthNone Strength = iota
	// StrengthCooperative is an adapter that hands each decision to a caller
	// that enforces it: the plane decides, holds and records, and nothing it
	// holds proves the caller obeyed.
	StrengthCooperative
	// StrengthInline is an adapter that holds the path to the effect and
	// sends only what the plane authorized.
	StrengthInline
)

// KnownKind reports whether kind is one of the kinds above, byte for byte.
func KnownKind(kind string) bool {
	switch kind {
	case KindTool, KindPrompt, KindResource:
		return true
	}
	return false
}

// StrengthOf is the strength of the protocol named, byte for byte. The empty
// name and any protocol this build does not know are StrengthNone.
func StrengthOf(protocol string) Strength {
	s, _ := protocolOf(protocol)
	return s
}

// KnownProtocol reports whether protocol is one of the protocols above, byte
// for byte.
func KnownProtocol(protocol string) bool {
	_, known := protocolOf(protocol)
	return known
}

// protocolOf is the one table of protocols and their strengths.
func protocolOf(protocol string) (Strength, bool) {
	switch protocol {
	case ProtocolMCP:
		return StrengthInline, true
	case ProtocolEnforce:
		return StrengthCooperative, true
	}
	return StrengthNone, false
}
