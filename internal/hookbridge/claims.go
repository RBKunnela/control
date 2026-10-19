package hookbridge

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/guardana/control/internal/policy/strictjson"
)

// PendingDenyWithReason is the one way a profile of this format can answer a
// call held for approval: a deny whose reason names the approval.
const PendingDenyWithReason = "deny-with-reason"

const (
	maxClaimText  = 1024
	maxClaimItems = 64
)

// Claims are what a profile says of its runtime, each with the ids of the
// qualification cases that back it. No claim changes what the bridge does.
type Claims struct {
	Runtime    RuntimeClaim
	FailClosed FailClosedClaim
	Pending    TextClaim
	CallID     FlagClaim
	ToolsSeen  ListClaim
	Bypasses   []TextClaim
	Page       string
}

// RuntimeClaim names the runtime and the versions the cases ran against.
type RuntimeClaim struct {
	Name           string
	TestedVersions []string
	BackedBy       []string
}

// FailClosedClaim names the runtime's setting that blocks a call whose hook
// failed, and the first version that has it; empty when there is none.
type FailClosedClaim struct {
	Setting    string
	MinVersion string
	BackedBy   []string
}

// TextClaim is a claim stated as one text.
type TextClaim struct {
	Text     string
	BackedBy []string
}

// FlagClaim is a claim that holds or does not.
type FlagClaim struct {
	Holds    bool
	BackedBy []string
}

// ListClaim is a claim stated as a list of names.
type ListClaim struct {
	Items    []string
	BackedBy []string
}

func readClaims(raw json.RawMessage) (Claims, error) {
	o, err := strictObject(raw, "runtime", "fail_closed", "pending", "call_id", "tools_seen", "bypasses", "page")
	if err != nil {
		return Claims{}, fmt.Errorf("%w: claims %w", ErrProfile, err)
	}
	var c Claims
	var errs []error
	c.Runtime, err = readRuntime(o["runtime"])
	errs = append(errs, err)
	c.FailClosed, err = readFailClosed(o["fail_closed"])
	errs = append(errs, err)
	c.Pending, err = readText(o["pending"], "value")
	errs = append(errs, err)
	if err == nil && c.Pending.Text != PendingDenyWithReason {
		errs = append(errs, errors.New("pending names a way this format does not have"))
	}
	c.CallID, err = readFlag(o["call_id"])
	errs = append(errs, err)
	c.ToolsSeen, err = readList(o["tools_seen"])
	errs = append(errs, err)
	c.Bypasses, err = readBypasses(o["bypasses"])
	errs = append(errs, err)
	var ok bool
	if c.Page, ok = strictjson.String(o["page"]); !ok || len(c.Page) > maxClaimText {
		errs = append(errs, errors.New("page"))
	}
	if err := errors.Join(errs...); err != nil {
		return Claims{}, fmt.Errorf("%w: claims: %w", ErrProfile, err)
	}
	return c, nil
}

func readRuntime(raw json.RawMessage) (RuntimeClaim, error) {
	o, err := strictObject(raw, "name", "tested_versions", "backed_by")
	if err != nil {
		return RuntimeClaim{}, fmt.Errorf("runtime %w", err)
	}
	var c RuntimeClaim
	name, ok := strictjson.String(o["name"])
	if !ok || name == "" || len(name) > maxClaimText {
		return RuntimeClaim{}, errors.New("runtime.name")
	}
	c.Name = name
	if c.TestedVersions, err = stringList(o["tested_versions"]); err != nil {
		return RuntimeClaim{}, fmt.Errorf("runtime.tested_versions %w", err)
	}
	if c.BackedBy, err = stringList(o["backed_by"]); err != nil {
		return RuntimeClaim{}, fmt.Errorf("runtime.backed_by %w", err)
	}
	return c, nil
}

func readFailClosed(raw json.RawMessage) (FailClosedClaim, error) {
	o, err := strictObject(raw, "setting", "min_version", "backed_by")
	if err != nil {
		return FailClosedClaim{}, fmt.Errorf("fail_closed %w", err)
	}
	setting, ok1 := strictjson.String(o["setting"])
	minVersion, ok2 := strictjson.String(o["min_version"])
	if !ok1 || !ok2 || len(setting) > maxClaimText || len(minVersion) > maxClaimText {
		return FailClosedClaim{}, errors.New("fail_closed")
	}
	backed, err := stringList(o["backed_by"])
	if err != nil {
		return FailClosedClaim{}, fmt.Errorf("fail_closed.backed_by %w", err)
	}
	return FailClosedClaim{Setting: setting, MinVersion: minVersion, BackedBy: backed}, nil
}

func readText(raw json.RawMessage, member string) (TextClaim, error) {
	o, err := strictObject(raw, member, "backed_by")
	if err != nil {
		return TextClaim{}, err
	}
	text, ok := strictjson.String(o[member])
	if !ok || text == "" || len(text) > maxClaimText {
		return TextClaim{}, errors.New(member)
	}
	backed, err := stringList(o["backed_by"])
	if err != nil {
		return TextClaim{}, fmt.Errorf("backed_by %w", err)
	}
	return TextClaim{Text: text, BackedBy: backed}, nil
}

func readFlag(raw json.RawMessage) (FlagClaim, error) {
	o, err := strictObject(raw, "value", "backed_by")
	if err != nil {
		return FlagClaim{}, fmt.Errorf("call_id %w", err)
	}
	var c FlagClaim
	switch string(o["value"]) {
	case "true":
		c.Holds = true
	case "false":
	default:
		return FlagClaim{}, errors.New("call_id.value is not a boolean")
	}
	if c.BackedBy, err = stringList(o["backed_by"]); err != nil {
		return FlagClaim{}, fmt.Errorf("call_id.backed_by %w", err)
	}
	return c, nil
}

func readList(raw json.RawMessage) (ListClaim, error) {
	o, err := strictObject(raw, "value", "backed_by")
	if err != nil {
		return ListClaim{}, fmt.Errorf("tools_seen %w", err)
	}
	var c ListClaim
	if c.Items, err = stringList(o["value"]); err != nil {
		return ListClaim{}, fmt.Errorf("tools_seen.value %w", err)
	}
	if c.BackedBy, err = stringList(o["backed_by"]); err != nil {
		return ListClaim{}, fmt.Errorf("tools_seen.backed_by %w", err)
	}
	return c, nil
}

func readBypasses(raw json.RawMessage) ([]TextClaim, error) {
	items, err := array(raw)
	if err != nil {
		return nil, fmt.Errorf("bypasses %w", err)
	}
	out := make([]TextClaim, 0, len(items))
	for _, item := range items {
		c, err := readText(item, "text")
		if err != nil {
			return nil, fmt.Errorf("bypasses %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}

// strictObject reads raw as an object holding exactly names.
func strictObject(raw json.RawMessage, names ...string) (strictjson.Object, error) {
	o, err := strictjson.ReadObject(raw)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(o.Only(names...), o.Require(names...)); err != nil {
		return nil, err
	}
	return o, nil
}

// stringList reads raw as an array of non-empty strings: not null, which a
// decoder reads into a slice as nil.
func stringList(raw json.RawMessage) ([]string, error) {
	items, err := array(raw)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := strictjson.String(item)
		if !ok || s == "" || len(s) > maxClaimText {
			return nil, errors.New("holds an item that is not a non-empty string")
		}
		out = append(out, s)
	}
	return out, nil
}

func array(raw json.RawMessage) ([]json.RawMessage, error) {
	var items []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &items) != nil {
		return nil, errors.New("is not an array")
	}
	if len(items) > maxClaimItems {
		return nil, fmt.Errorf("holds more than %d items", maxClaimItems)
	}
	return items, nil
}
