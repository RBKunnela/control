package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"google.golang.org/protobuf/reflect/protoreflect"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/pkg/contract"
)

// testCase is one file of a policy test directory: what the kernel is handed
// and what it is expected to answer.
type testCase struct {
	document       []byte
	envelope       []byte
	authorizedArgs []byte
	flow           contract.FlowState
	options        core.Options
	loadedAt       time.Time
	decidedAt      time.Time
	external       core.External
	// externalName is the external member as the case spells it.
	externalName string
	expect       outcome
	hasExpect    bool
}

// outcome is what a case expects, and what a decision gave.
type outcome struct {
	verdict controlv1.Verdict
	action  core.EnforcementAction
	codes   []string
}

// actions names the enforcement actions the way a case spells them.
var actions = map[string]core.EnforcementAction{
	"Block":                  core.Block,
	"Execute":                core.Execute,
	"ExecuteWithObligations": core.ExecuteWithObligations,
	"AwaitApproval":          core.AwaitApproval,
}

// readCase reads one case strictly: every member but external present, each
// spelled exactly, none the format does not have, none twice, nothing after
// the object. A refusal names the member it is about.
func readCase(raw []byte) (*testCase, error) { return readCaseExpecting(raw, true) }

// readCaseExpecting is readCase with expect optional when expectRequired is
// false, as `policy explain` reads a case.
func readCaseExpecting(raw []byte, expectRequired bool) (*testCase, error) {
	required := []string{"document", "envelope", "authorized_args", "flow", "options", "loaded_at", "decided_at"}
	optional := []string{"external"}
	if expectRequired {
		required = append(required, "expect")
	} else {
		optional = append(optional, "expect")
	}
	m, err := object(raw, "", optional, required...)
	if err != nil {
		return nil, err
	}
	c := &testCase{}
	var r reader
	c.document = r.object(m, "", "document")
	c.envelope = r.object(m, "", "envelope")
	c.authorizedArgs = []byte(r.exactString(m, "", "authorized_args"))
	c.flow = r.flow(m["flow"])
	c.options = r.options(m["options"])
	c.loadedAt = r.time(m, "", "loaded_at")
	c.decidedAt = r.time(m, "", "decided_at")
	c.external, c.externalName = r.external(m, "external")
	if _, stated := m["expect"]; stated {
		c.expect, c.hasExpect = r.expect(m["expect"]), true
	}
	if r.err != nil {
		return nil, r.err
	}
	if len(c.authorizedArgs) == 0 {
		c.authorizedArgs = nil
	}
	return c, nil
}

// object reads a JSON object whose members are keys, each once, and any of
// optional, and returns them unparsed. It walks the tokens itself because
// encoding/json keeps the last of two members with one name and matches a
// name in any case.
func object(raw []byte, at string, optional []string, keys ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("%s: want a JSON object", orCase(at))
	}
	members, err := readMembers(dec, at, append(slices.Clone(keys), optional...))
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("%s: %w", orCase(at), err)
	}
	if at == "" {
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return nil, errors.New("the case: data after the object")
		}
	}
	for _, key := range keys {
		if _, ok := members[key]; !ok {
			return nil, fmt.Errorf("%s: missing", label(at, key))
		}
	}
	return members, nil
}

// readMembers reads the members up to the closing brace, each once and each
// one of keys.
func readMembers(dec *json.Decoder, at string, keys []string) (map[string]json.RawMessage, error) {
	members := make(map[string]json.RawMessage, len(keys))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", orCase(at), err)
		}
		key, _ := tok.(string)
		if !contains(keys, key) {
			return nil, fmt.Errorf("%s: a member the case format does not have", label(at, key))
		}
		if _, seen := members[key]; seen {
			return nil, fmt.Errorf("%s: given twice", label(at, key))
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("%s: %w", label(at, key), err)
		}
		members[key] = value
	}
	return members, nil
}

// label names a member for a refusal: "flow.floor", or "floor" at the top.
func label(at, key string) string {
	if at == "" {
		return key
	}
	return at + "." + key
}

func orCase(at string) string {
	if at == "" {
		return "the case"
	}
	return at
}

func contains(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

// reader keeps the first refusal, so the members read in one pass and the
// refusal is the first in the format's order.
type reader struct{ err error }

func (r *reader) refuse(at, key string, err error) {
	if r.err == nil {
		r.err = fmt.Errorf("%s: %w", label(at, key), err)
	}
}

func (r *reader) object(m map[string]json.RawMessage, at, key string) []byte {
	raw := bytes.TrimSpace(m[key])
	if len(raw) == 0 || raw[0] != '{' {
		r.refuse(at, key, errors.New("want a JSON object"))
		return nil
	}
	return raw
}

func (r *reader) string(m map[string]json.RawMessage, at, key string) string {
	var s string
	if isNull(m[key]) || json.Unmarshal(m[key], &s) != nil {
		r.refuse(at, key, errors.New("want a string"))
	}
	return s
}

// exactString is string for a member whose bytes the kernel judges: the
// decoder reads an invalid UTF-8 byte, and an escaped surrogate that is not
// half of a pair, as U+FFFD, so such a member is refused rather than decided
// on other bytes than the case wrote.
func (r *reader) exactString(m map[string]json.RawMessage, at, key string) string {
	s := r.string(m, at, key)
	if !exact(m[key]) {
		r.refuse(at, key, errors.New("want valid UTF-8 and no unpaired surrogate escape"))
		return ""
	}
	return s
}

// exactStrings is strings for a list whose members' bytes are compared, each
// held as exactString holds a member.
func (r *reader) exactStrings(m map[string]json.RawMessage, at, key string) []string {
	list := r.strings(m, at, key)
	var raws []json.RawMessage
	if list == nil || json.Unmarshal(m[key], &raws) != nil {
		return list
	}
	for _, raw := range raws {
		if !exact(raw) {
			r.refuse(at, key, errors.New("want valid UTF-8 and no unpaired surrogate escape"))
			return nil
		}
	}
	return list
}

// exact reports whether a JSON string the decoder accepted decodes to the
// text it spells, with no U+FFFD put in for what it could not carry.
func exact(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if i++; raw[i] != 'u' {
			continue
		}
		r := escaped(raw[i+1:])
		if i += 4; !utf16.IsSurrogate(r) {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' || utf16.DecodeRune(r, escaped(raw[i+3:])) == unicode.ReplacementChar {
			return false
		}
		i += 6
	}
	return true
}

// escaped reads the four hex digits of a \u escape.
func escaped(hex []byte) rune {
	n, err := strconv.ParseUint(string(hex[:4]), 16, 16)
	if err != nil {
		return unicode.ReplacementChar
	}
	return rune(n)
}

func (r *reader) bool(m map[string]json.RawMessage, at, key string) bool {
	var b bool
	if isNull(m[key]) || json.Unmarshal(m[key], &b) != nil {
		r.refuse(at, key, errors.New("want true or false"))
	}
	return b
}

func (r *reader) strings(m map[string]json.RawMessage, at, key string) []string {
	var list []*string
	if isNull(m[key]) || json.Unmarshal(m[key], &list) != nil || slices.Contains(list, nil) {
		r.refuse(at, key, errors.New("want a list of strings"))
		return nil
	}
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = *s
	}
	return out
}

// isNull reports a JSON null, which the decoder reads into any Go value as
// its zero value without an error: a case that wrote null would be read as
// false, "" or no list, and pass without testing what it names.
func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// time reads an RFC 3339 time and holds it to UTC, so a case decides the
// same way on every machine and a zone nobody wrote down never enters a
// decision.
func (r *reader) time(m map[string]json.RawMessage, at, key string) time.Time {
	s := r.string(m, at, key)
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		r.refuse(at, key, errors.New("want an RFC 3339 time"))
		return time.Time{}
	}
	if _, offset := t.Zone(); offset != 0 {
		r.refuse(at, key, errors.New("want a UTC time, written with Z"))
		return time.Time{}
	}
	return t.UTC()
}

func (r *reader) flow(raw json.RawMessage) contract.FlowState {
	m, err := object(raw, "flow", nil, "untrusted", "floor")
	if err != nil {
		r.refuse("", "flow", err)
		return contract.FlowState{}
	}
	untrusted := r.bool(m, "flow", "untrusted")
	n, ok := enumNumber(controlv1.Sensitivity(0).Descriptor(), "SENSITIVITY_", r.string(m, "flow", "floor"))
	if !ok {
		r.refuse("flow", "floor", errors.New("want a sensitivity name without its prefix"))
	}
	return contract.NewFlowState(untrusted, controlv1.Sensitivity(n))
}

func (r *reader) options(raw json.RawMessage) core.Options {
	m, err := object(raw, "options", nil, "fail_open_read", "max_stale_seconds", "applicable")
	if err != nil {
		r.refuse("", "options", err)
		return core.Options{}
	}
	return core.Options{
		Mode:         controlv1.EnforcementMode_ENFORCEMENT_MODE_ENFORCE,
		FailOpenRead: r.bool(m, "options", "fail_open_read"),
		MaxStale:     r.seconds(m, "options", "max_stale_seconds"),
		Applicable:   r.strings(m, "options", "applicable"),
	}
}

// seconds reads a whole number of seconds a Duration can hold. New refuses
// one that is not positive.
func (r *reader) seconds(m map[string]json.RawMessage, at, key string) time.Duration {
	var n json.Number
	// json.Number also reads a quoted number; a case writes a number.
	if raw := bytes.TrimSpace(m[key]); len(raw) == 0 || raw[0] == '"' {
		r.refuse(at, key, errors.New("want an integer"))
		return 0
	} else if err := json.Unmarshal(raw, &n); err != nil {
		r.refuse(at, key, errors.New("want an integer"))
		return 0
	}
	i, err := n.Int64()
	if err != nil || i > math.MaxInt64/int64(time.Second) || i < math.MinInt64/int64(time.Second) {
		r.refuse(at, key, errors.New("want an integer number of seconds a duration holds"))
		return 0
	}
	return time.Duration(i) * time.Second
}

func (r *reader) expect(raw json.RawMessage) outcome {
	m, err := object(raw, "expect", nil, "verdict", "action", "reason_codes")
	if err != nil {
		r.refuse("", "expect", err)
		return outcome{}
	}
	var o outcome
	n, ok := enumNumber(controlv1.Verdict(0).Descriptor(), "VERDICT_", r.string(m, "expect", "verdict"))
	if !ok || n == 0 {
		r.refuse("expect", "verdict", errors.New("want one of the five verdicts, without the prefix"))
	}
	o.verdict = controlv1.Verdict(n)
	if o.action, ok = actions[r.string(m, "expect", "action")]; !ok {
		r.refuse("expect", "action", errors.New("want Block, Execute, ExecuteWithObligations or AwaitApproval"))
	}
	o.codes = r.strings(m, "expect", "reason_codes")
	return o
}

// externals are the external answers a case may hand the kernel, as a case
// spells them. A case without the member asks nothing.
var externals = map[string]core.External{
	"allowed":                 core.ExternalAllowed(),
	"denied":                  core.ExternalDenied(),
	"denied_with_obligations": core.ExternalDeniedObligations(),
	"timeout":                 core.ExternalTimeout(),
	"unavailable":             core.ExternalUnavailable(),
	"answer_refused":          core.ExternalAnswerRefused(),
}

// external reads the answer and its name, "not asked" when the case states
// none. A name outside externals is refused, so the name is never the case's
// free text.
func (r *reader) external(m map[string]json.RawMessage, key string) (core.External, string) {
	if _, stated := m[key]; !stated {
		return core.External{}, "not asked"
	}
	var name string
	if err := json.Unmarshal(m[key], &name); err != nil {
		r.refuse("", key, errors.New("want a string"))
		return core.External{}, ""
	}
	e, known := externals[name]
	if !known {
		r.refuse("", key, errors.New("want allowed, denied, denied_with_obligations, timeout, unavailable or answer_refused"))
		return core.External{}, ""
	}
	return e, name
}

// enumNumber finds a value by its name without the prefix, spelled exactly.
func enumNumber(d protoreflect.EnumDescriptor, prefix, name string) (protoreflect.EnumNumber, bool) {
	if name == "" || strings.HasPrefix(name, prefix) {
		return 0, false
	}
	value := d.Values().ByName(protoreflect.Name(prefix + name))
	if value == nil {
		return 0, false
	}
	return value.Number(), true
}
