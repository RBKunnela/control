package contract_test

import (
	"bytes"
	"errors"
	"math"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/pkg/contract"
)

// The inputs here are written by hand: the runtime's encoder never sends a
// field twice or an enum outside int32, so proto.Marshal cannot produce them.
// Field order means nothing to a parser, so a message is its marshalled fields
// with the fields under test appended. Numbers from action_envelope.proto.
const (
	fieldPrincipal  protowire.Number = 9
	fieldDelegation protowire.Number = 11
	fieldAction     protowire.Number = 12
	fieldData       protowire.Number = 15
	fieldContext    protowire.Number = 17

	// The attributes map inside Principal and the budgets map inside
	// RunContext.
	fieldAttributes protowire.Number = 5
	fieldBudgets    protowire.Number = 5
)

// Ten-byte varints of negative numbers, as a producer sends them: the int64
// sign-extended, which is 2^64 plus the number.
const (
	varintMinusOne      = 1<<64 - 1
	varintMinInt32      = 1<<64 - 1<<31
	varintBelowMinInt32 = 1<<64 - 1<<31 - 1
)

func marshalled(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func lenField(num protowire.Number, body []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, num, protowire.BytesType), body)
}

func varintField(num protowire.Number, v uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, num, protowire.VarintType), v)
}

func concat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// assertRefusedBeforeTheParse: the JSON path refuses the same input in its
// codec, so this one carries no sentinel either, names the field, and returns
// no message, there being none yet.
func assertRefusedBeforeTheParse(t *testing.T, env *controlv1.ActionEnvelope, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want a refusal naming %q, got no error", field)
	}
	var ve *contract.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("got %v, which is not a *ValidationError", err)
	}
	if ve.Field != field {
		t.Errorf("refusal names %q, want %q", ve.Field, field)
	}
	for _, s := range sentinels() {
		if errors.Is(err, s) {
			t.Errorf("%v matches %v; the JSON path refuses the same input with none", err, s)
		}
	}
	if env != nil {
		t.Error("a message came back with a refusal made before the parse")
	}
}

// TestDecodeRefusesAFieldThatIsNotRepeatedSentTwice is ADR-0011's rule. The
// runtime keeps the last scalar and merges a second message into the first, so
// every vector parses into an envelope Validate accepts, and a reader of the
// bytes that kept the first occurrence would see a different one.
func TestDecodeRefusesAFieldThatIsNotRepeatedSentTwice(t *testing.T) {
	without := func(drop func(*controlv1.ActionEnvelope)) []byte {
		env := withDelegation(1)
		drop(env)
		return marshalled(t, env)
	}
	base := withDelegation(1)
	deletion := withDelegation(1)
	deletion.Action = &controlv1.Action{Name: "orders.delete", Effect: controlv1.EffectClass_EFFECT_CLASS_DELETE}

	for _, tc := range []struct {
		name, field string
		wire        []byte
	}{
		{"schema_version, a refused major first", "schema_version", concat(lenField(1, []byte("9.0")), marshalled(t, base))},
		{"request_id", "request_id", concat(marshalled(t, base), lenField(2, []byte("req-2")))},
		{"a message, merged: a DELETE with no provider reads as a READ", "action",
			concat(marshalled(t, deletion), lenField(fieldAction, varintField(4, 1)))},
		{"a field inside a message", "action.name", concat(without(func(e *controlv1.ActionEnvelope) { e.Action = nil }),
			lenField(fieldAction, concat(marshalled(t, base.Action), lenField(2, []byte("orders.write")))))},
		{"a timestamp's seconds", "occurred_at.seconds", concat(without(func(e *controlv1.ActionEnvelope) { e.OccurredAt = nil }),
			lenField(5, concat(marshalled(t, base.OccurredAt), varintField(1, 1_800_000_000))))},
		{"a hop's end, twice the same", "delegation[0].to", concat(without(func(e *controlv1.ActionEnvelope) { e.Delegation = nil }),
			lenField(fieldDelegation, concat(marshalled(t, base.Delegation[0]), lenField(2, []byte("agent-1")))))},
		{"a map entry's key", "principal.attributes", concat(without(func(e *controlv1.ActionEnvelope) { e.Principal = nil }),
			lenField(fieldPrincipal, concat(marshalled(t, base.Principal),
				lenField(5, concat(lenField(1, []byte("team")), lenField(1, []byte("role")), lenField(2, []byte("ops")))))))},
		{"a map entry's value", "principal.attributes", concat(without(func(e *controlv1.ActionEnvelope) { e.Principal = nil }),
			lenField(fieldPrincipal, concat(marshalled(t, base.Principal),
				lenField(5, concat(lenField(1, []byte("team")), lenField(2, []byte("ops")), lenField(2, []byte("dev")))))))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed := &controlv1.ActionEnvelope{}
			if err := proto.Unmarshal(tc.wire, parsed); err != nil || contract.Validate(parsed) != nil {
				t.Fatalf("the runtime does not turn this into an accepted envelope (%v, %v), so it proves nothing",
					err, contract.Validate(parsed))
			}
			env, err := contract.Decode(tc.wire)
			assertRefusedBeforeTheParse(t, env, err, tc.field)
		})
	}
}

// TestDecodeRefusesAnEnumNumberOutsideInt32: the runtime truncates the varint to
// 32 bits, so 2^32+1 arrives as EFFECT_CLASS_READ. Read as a two's-complement
// int64 and outside int32 is refused before the parse. A number inside int32,
// a negative one sent sign-extended included, is the declared-value check's.
func TestDecodeRefusesAnEnumNumberOutsideInt32(t *testing.T) {
	withEffect := func(v uint64) []byte {
		env := valid()
		env.Action = nil
		action := concat(lenField(2, []byte("orders.read")), lenField(5, []byte("orders-mcp")), varintField(4, v))
		return concat(marshalled(t, env), lenField(fieldAction, action))
	}
	for _, v := range []uint64{1<<32 + 1, 1<<63 + 1} {
		parsed := &controlv1.ActionEnvelope{}
		if err := proto.Unmarshal(withEffect(v), parsed); err != nil || parsed.GetAction().GetEffect() != controlv1.EffectClass_EFFECT_CLASS_READ {
			t.Fatalf("the runtime reads %d as %v (%v), not as READ, so the case proves less than it says", v, parsed.GetAction().GetEffect(), err)
		}
	}
	for _, v := range []uint64{1<<32 + 1, 1<<63 + 1, 1 << 31, varintBelowMinInt32} {
		env, err := contract.Decode(withEffect(v))
		assertRefusedBeforeTheParse(t, env, err, "action.effect")
	}
	for _, v := range []uint64{math.MaxInt32, varintMinInt32, varintMinusOne, 99} {
		_, err := contract.Decode(withEffect(v))
		assertRefused(t, err, contract.ErrInvalidEnum, "action.effect")
	}

	base := marshalled(t, valid())
	for name, labels := range map[string][]byte{
		"packed":   lenField(1, concat(protowire.AppendVarint(nil, 1), protowire.AppendVarint(nil, 1<<32+1))),
		"unpacked": concat(varintField(1, 1), varintField(1, 1<<32+1)),
	} {
		env, err := contract.Decode(concat(base, lenField(fieldData, labels)))
		t.Run(name, func(t *testing.T) { assertRefusedBeforeTheParse(t, env, err, "data.sensitivities[1]") })
	}
}

// TestDecodeRefusesAnInt32MemberOutsideInt32: the runtime truncates a
// timestamp's nanos to 32 bits as it does an enum's number, so 2^32+1 arrives
// as one nanosecond and a hop's expiry passes the timestamp check. Read as a
// two's-complement int64 and outside int32 is refused before the parse; the
// same expiry with nanos sent as 1 decodes.
func TestDecodeRefusesAnInt32MemberOutsideInt32(t *testing.T) {
	withNanos := func(v uint64) []byte {
		env := withDelegation(1)
		hop := env.Delegation[0]
		seconds := hop.GetExpiresAt()
		seconds.Nanos = 0
		env.Delegation, hop.ExpiresAt = nil, nil
		expiry := concat(marshalled(t, seconds), varintField(2, v))
		return concat(marshalled(t, env), lenField(fieldDelegation, concat(marshalled(t, hop), lenField(6, expiry))))
	}
	if _, err := contract.Decode(withNanos(1)); err != nil {
		t.Fatalf("the expiry with nanos sent as 1: %v; want it decoded, so the cases below prove nothing", err)
	}
	for _, v := range []uint64{1<<32 + 1, 1<<63 + 1} {
		parsed := &controlv1.ActionEnvelope{}
		if err := proto.Unmarshal(withNanos(v), parsed); err != nil || parsed.GetDelegation()[0].GetExpiresAt().GetNanos() != 1 ||
			contract.Validate(parsed) != nil {
			t.Fatalf("the runtime does not turn nanos %d into an accepted envelope with one nanosecond (%v, %v), so it proves nothing",
				v, err, contract.Validate(parsed))
		}
	}
	for _, v := range []uint64{1<<32 + 1, 1<<63 + 1, 1 << 31, varintBelowMinInt32} {
		env, err := contract.Decode(withNanos(v))
		assertRefusedBeforeTheParse(t, env, err, "delegation[0].expires_at.nanos")
	}
}

// TestDecodeRefusesAFloodBeforeTheParseBuildsIt: the runtime builds every
// element it reads, so 262144 bytes of empty delegation hops would cost
// megabytes before Validate refused the ninth. Counted on the wire, the
// refusal comes at the ninth, before anything is built.
//
// The costliest shape is a field sent as many packed runs of one element: the
// runtime copies a packed field once per run, so the parse is quadratic, and
// the runs below cost gigabytes when the pre-scan counts each run on its own.
// The ceiling holds every shape to one number.
func TestDecodeRefusesAFloodBeforeTheParseBuildsIt(t *testing.T) {
	const allocCeiling = 64 << 10
	// A pre-scan that stops counting runs together lets the same shape at the
	// bound through the parse for a few kilobytes. Checked first, so that such
	// a regression fails here rather than making the flood cost 15 GB.
	if env, err := contract.Decode(lenField(fieldData, oneElementRuns(contract.MaxLabels+1))); env != nil || !errors.Is(err, contract.ErrTooLarge) {
		t.Fatalf("%d one-element packed runs: %v, message returned %t; the pre-scan does not count runs together, so the flood is not sent",
			contract.MaxLabels+1, err, env != nil)
	}
	for _, tc := range []struct {
		name, field string
		wire        []byte
	}{
		{"empty delegation hops", "delegation", bytes.Repeat([]byte{0x5a, 0x00}, contract.MaxEnvelopeBytes/2)},
		{"empty data sources", "data.sources",
			lenField(fieldData, bytes.Repeat([]byte{0x12, 0x00}, contract.MaxEnvelopeBytes/2-4))},
		{"packed sensitivity labels", "data.sensitivities",
			lenField(fieldData, lenField(1, bytes.Repeat([]byte{0x01}, contract.MaxEnvelopeBytes-8)))},
		{"sensitivity labels as 86016 one-element packed runs", "data.sensitivities",
			lenField(fieldData, oneElementRuns(86016))},
		{"principal attributes, every key distinct", "principal.attributes", attributeFlood()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.wire) > contract.MaxEnvelopeBytes {
				t.Fatalf("%d bytes is over MaxEnvelopeBytes, so the length check refuses it first", len(tc.wire))
			}
			var err error
			spent := allocated(func() { _, err = contract.Decode(tc.wire) })
			assertRefused(t, err, contract.ErrTooLarge, tc.field)
			if spent > allocCeiling {
				t.Errorf("Decode allocated %d bytes to refuse %d; a refusal at the bound costs under %d", spent, len(tc.wire), allocCeiling)
			}
			t.Logf("%d bytes refused with %d bytes allocated", len(tc.wire), spent)
		})
	}
}

// TestDecodeRefusesBytesThatAreNotWireFormatBeforeTheParse: the pre-scan reads
// every byte before the parse does, so a valid 230 KB prefix with a cut-off
// field after it is refused before the parse builds the prefix. It renders as
// the parse's own refusal: a caller cannot tell which of the two refused.
func TestDecodeRefusesBytesThatAreNotWireFormatBeforeTheParse(t *testing.T) {
	const allocCeiling = 64 << 10
	env := withDelegation(contract.MaxDelegationDepth)
	for _, hop := range env.Delegation {
		for i := range contract.MaxLabels {
			hop.Scopes = append(hop.Scopes, strconv.Itoa(i)+strings.Repeat("s", 890))
		}
	}
	whole := marshalled(t, env)
	if _, err := contract.Decode(whole); err != nil {
		t.Fatalf("the envelope is refused before it is cut short, so this proves nothing: %v", err)
	}
	cut := concat(whole, []byte{0x12, 0x05, 'r'}) // request_id: five bytes promised, one sent

	var err error
	spent := allocated(func() { _, err = contract.Decode(cut) })
	_, garbage := contract.Decode([]byte{0xff, 0xff, 0xff, 0xff})
	if err == nil || err.Error() != garbage.Error() {
		t.Errorf("refused with %v; want the parse's own refusal, %v", err, garbage)
	}
	if spent > allocCeiling {
		t.Errorf("Decode allocated %d bytes to refuse %d that are not wire format; the parse ran first", spent, len(cut))
	}
	t.Logf("%d bytes refused with %d bytes allocated", len(cut), spent)
}

func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// oneElementRuns is n sensitivity labels, PUBLIC, sent as n packed runs of one
// element each.
func oneElementRuns(n int) []byte { return bytes.Repeat(lenField(1, []byte{0x01}), n) }

// TestTheRuntimeParseOfPackedRunsIsQuadratic pins why the pre-scan counts
// packed runs together, as a fact about the Protobuf runtime rather than about
// this package. The runtime copies a packed field once per run, so n runs of
// one element cost its parse at least n^2 bytes, while the same elements
// unpacked cost a few bytes each. Measured on the runtime alone and kept
// small: at the 86016 runs that fit in MaxEnvelopeBytes the same growth is
// gigabytes, which is why every test that sends that flood sends it through
// Decode. It fails the day the runtime stops copying, which is when the
// Limits section has to change.
func TestTheRuntimeParseOfPackedRunsIsQuadratic(t *testing.T) {
	const n = 2048
	parse := func(wire []byte) uint64 {
		return allocated(func() {
			if err := proto.Unmarshal(wire, &controlv1.DataLabels{}); err != nil {
				t.Fatalf("the runtime refuses the labels: %v", err)
			}
		})
	}
	packed, packedHalf := parse(oneElementRuns(n)), parse(oneElementRuns(n/2))
	unpacked := parse(bytes.Repeat(varintField(1, 1), n))
	if packed < n*n {
		t.Errorf("%d one-element packed runs cost the parse %d bytes, under n^2 = %d; the Limits section calls it quadratic", n, packed, n*n)
	}
	if growth := float64(packed) / float64(packedHalf); growth < 3 {
		t.Errorf("twice the runs cost %.2f times as much; quadratic is about 4", growth)
	}
	if unpacked > 64*n {
		t.Errorf("the same %d labels unpacked cost %d bytes, so the comparison with packed runs says nothing", n, unpacked)
	}
	t.Logf("one-element packed runs: %d cost %d bytes, %d cost %d; %d unpacked labels cost %d", n/2, packedHalf, n, packed, n, unpacked)
}

// attributeFlood fills an envelope's worth of principal with map entries. Every
// key is distinct, so what refuses it is the count and not the rule on one key
// sent in two entries.
func attributeFlood() []byte {
	var body []byte
	for i := 0; ; i++ {
		entry := lenField(fieldAttributes, concat(lenField(1, []byte("k"+strconv.Itoa(i))), lenField(2, []byte("v"))))
		if len(body)+len(entry) > contract.MaxEnvelopeBytes-8 {
			return lenField(fieldPrincipal, body)
		}
		body = append(body, entry...)
	}
}

// TestDecodeCountsToTheBoundValidateHolds: one number on both paths, so the
// last entry Validate accepts passes the wire count too, and the next is
// refused before the parse. Validate refuses the same count, with the same
// sentinel and field, once the runtime has built every element, so only the
// missing message tells the pre-scan's refusal from Validate's. Packed and
// unpacked elements of one field count together, and so do packed runs.
func TestDecodeCountsToTheBoundValidateHolds(t *testing.T) {
	base := marshalled(t, valid())
	labels := func(parts ...[]byte) []byte { return concat(base, lenField(fieldData, concat(parts...))) }
	half := lenField(1, bytes.Repeat([]byte{0x01}, contract.MaxLabels/2))
	attributes := func(n int) []byte {
		env := valid()
		env.Principal.Attributes = entries(n)
		return marshalled(t, env)
	}
	for _, tc := range []struct {
		name, field string
		at, over    []byte
	}{
		{"delegation hops", "delegation",
			marshalled(t, withDelegation(contract.MaxDelegationDepth)), marshalled(t, withDelegation(contract.MaxDelegationDepth+1))},
		{"principal attributes", "principal.attributes", attributes(contract.MaxLabels), attributes(contract.MaxLabels + 1)},
		{"labels in two packed runs, then one unpacked", "data.sensitivities",
			labels(half, half), labels(half, half, varintField(1, 1))},
		{"labels in one-element packed runs", "data.sensitivities",
			labels(oneElementRuns(contract.MaxLabels)), labels(oneElementRuns(contract.MaxLabels + 1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := contract.Decode(tc.at); err != nil {
				t.Errorf("at the bound: refused with %v", err)
			}
			env, err := contract.Decode(tc.over)
			assertRefused(t, err, contract.ErrTooLarge, tc.field)
			if env != nil {
				t.Error("past the bound: refused after the parse built the message, so the pre-scan did not count it")
			}
		})
	}
}

// TestDecodeKeepsAnUnknownFieldFloodAsBytes pins what the Limits section says
// about the fields the pre-scan does not count: a field this build does not
// know, or a known number on a wire type it is not read from. The runtime
// keeps them as unknown bytes, and the walk refuses the first after the parse,
// so the message comes back with its request id. That costs a few times the
// input, not the 86 times of a flood the runtime builds. It fails when the
// factor passes what the page promises, and logs the number the page rounds.
func TestDecodeKeepsAnUnknownFieldFloodAsBytes(t *testing.T) {
	const ceiling = 6
	base := marshalled(t, valid())
	for _, tc := range []struct {
		name, field string
		unit        []byte
	}{
		{"a field this build does not know", "<field 100>", varintField(100, 1)},
		{"delegation sent as a varint", "<field 11>", varintField(fieldDelegation, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := concat(base, bytes.Repeat(tc.unit, (contract.MaxEnvelopeBytes-len(base))/len(tc.unit)))
			var env *controlv1.ActionEnvelope
			var err error
			spent := allocated(func() { env, err = contract.Decode(wire) })
			assertRefused(t, err, contract.ErrUnknownField, tc.field)
			if env == nil {
				t.Error("refused with no message; the page says the walk refuses this after the parse")
			}
			factor := float64(spent) / float64(len(wire))
			if factor > ceiling {
				t.Errorf("Decode allocated %d bytes for %d, %.1f times; the Limits section says under %d", spent, len(wire), factor, ceiling)
			}
			t.Logf("Decode allocated %d bytes for %d bytes of unknown fields, %.2f times", spent, len(wire), factor)
		})
	}
}

// TestDecodeAcceptsWhatTheWireAllows: the pre-scan refuses what it names and
// nothing else. A repeated scalar may come packed, unpacked or both, fields in
// any order, a map entry without its value. Outside a map entry, a field this
// build does not know, or a known number sent as the wrong wire type, stays
// the walk's to refuse, by number, as before.
func TestDecodeAcceptsWhatTheWireAllows(t *testing.T) {
	base := marshalled(t, valid())
	noPrincipal := valid()
	noPrincipal.Principal = nil
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"labels packed", concat(base, lenField(fieldData, lenField(1, []byte{1, 5})))},
		{"labels unpacked", concat(base, lenField(fieldData, concat(varintField(1, 1), varintField(1, 5))))},
		{"labels packed and unpacked", concat(base, lenField(fieldData, concat(lenField(1, []byte{1}), varintField(1, 5))))},
		// Not a repeated field among them: reversing those reverses a list.
		{"the fields in reverse order", reversed(t, marshalled(t, valid()))},
		{"a map entry with no value", concat(marshalled(t, noPrincipal), lenField(fieldPrincipal,
			concat(marshalled(t, valid().Principal), lenField(5, lenField(1, []byte("team"))))))},
	} {
		if _, err := contract.Decode(tc.wire); err != nil {
			t.Errorf("%s: refused with %v", tc.name, err)
		}
	}
	_, err := contract.Decode(concat(base, varintField(99, 1)))
	assertRefused(t, err, contract.ErrUnknownField, "<field 99>")
	_, err = contract.Decode(concat(base, varintField(2, 7))) // request_id is a string
	assertRefused(t, err, contract.ErrUnknownField, "<field 2>")
}

// reversed returns b's top-level fields in the opposite order.
func reversed(t *testing.T, b []byte) []byte {
	t.Helper()
	var fields [][]byte
	for len(b) > 0 {
		_, _, n := protowire.ConsumeField(b)
		if n < 0 {
			t.Fatalf("the base does not parse: %v", protowire.ParseError(n))
		}
		fields = append(fields, b[:n])
		b = b[n:]
	}
	slices.Reverse(fields)
	return concat(fields...)
}

// TestNoVarintThePreScanLeavesUncheckedIsReachable: the pre-scan holds an
// enum number and a singular int32 to int32, and the runtime truncates any
// other 32-bit varint unseen, so a sint32, a uint32 or a repeated int32 the
// envelope reaches would need a check of its own.
func TestNoVarintThePreScanLeavesUncheckedIsReachable(t *testing.T) {
	seen := map[protoreflect.FullName]bool{}
	singularInt32 := 0
	var walk func(protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		fields := md.Fields()
		for i := range fields.Len() {
			fd := fields.Get(i)
			switch {
			case fd.Kind() == protoreflect.Sint32Kind, fd.Kind() == protoreflect.Uint32Kind:
				t.Errorf("%s is a %s, which the pre-scan does not hold to its width", fd.FullName(), fd.Kind())
			case fd.Kind() == protoreflect.Int32Kind && fd.IsList():
				t.Errorf("%s is a repeated int32, which the pre-scan does not hold to its width", fd.FullName())
			case fd.Kind() == protoreflect.Int32Kind:
				singularInt32++
			}
			if m := fd.Message(); m != nil {
				walk(m)
			}
		}
	}
	walk((*controlv1.ActionEnvelope)(nil).ProtoReflect().Descriptor())
	if singularInt32 == 0 {
		t.Fatalf("the walk met no int32 in %d messages, so it reached nothing the pre-scan holds", len(seen))
	}
}
