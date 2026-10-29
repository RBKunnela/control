package channel_test

import (
	"testing"

	"github.com/guardana/control/internal/channel"
)

func TestKnownKindIsTheClosedListByteForByte(t *testing.T) {
	for kind, want := range map[string]bool{
		"tool":      true,
		"prompt":    true,
		"resource":  true,
		"":          false,
		"Tool":      false,
		"tool ":     false,
		" tool":     false,
		"function":  false,
		"resources": false,
		"TOOL":      false,
	} {
		if got := channel.KnownKind(kind); got != want {
			t.Errorf("KnownKind(%q) = %v, want %v", kind, got, want)
		}
	}
}

func TestStrengthOfAnUnknownProtocolIsNone(t *testing.T) {
	for protocol, want := range map[string]channel.Strength{
		"mcp":      channel.StrengthInline,
		"enforce":  channel.StrengthCooperative,
		"":         channel.StrengthNone,
		"MCP":      channel.StrengthNone,
		"mcp ":     channel.StrengthNone,
		"Enforce":  channel.StrengthNone,
		"a2a":      channel.StrengthNone,
		"fake":     channel.StrengthNone,
		"enforce/": channel.StrengthNone,
	} {
		if got := channel.StrengthOf(protocol); got != want {
			t.Errorf("StrengthOf(%q) = %d, want %d", protocol, got, want)
		}
	}
}

func TestTheZeroStrengthIsNone(t *testing.T) {
	var zero channel.Strength
	if zero != channel.StrengthNone {
		t.Errorf("the zero Strength is %d, want StrengthNone", zero)
	}
	if channel.StrengthNone >= channel.StrengthCooperative || channel.StrengthCooperative >= channel.StrengthInline {
		t.Error("the strengths are not ordered None < Cooperative < Inline")
	}
}

func TestKnownProtocolIsTheTableByteForByte(t *testing.T) {
	for protocol, want := range map[string]bool{
		"mcp":      true,
		"enforce":  true,
		"":         false,
		"MCP":      false,
		"mcp ":     false,
		"Enforce":  false,
		"a2a":      false,
		"fake":     false,
		"enforce/": false,
	} {
		if got := channel.KnownProtocol(protocol); got != want {
			t.Errorf("KnownProtocol(%q) = %v, want %v", protocol, got, want)
		}
	}
}
