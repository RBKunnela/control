package contract

import (
	"errors"
	"fmt"
	"math"
	"strconv"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// prescan reads binary wire bytes against the descriptors before the runtime
// builds anything from them, and refuses what the parse would hide or pay for
// (ADR-0011; docs/contracts.md, "Decoding and validation"):
//
//   - a second occurrence of a field that is not repeated, at any depth. The
//     runtime keeps the last scalar and merges a second message into the
//     first, so two byte strings become one accepted envelope, and a reader of
//     the bytes that kept the first occurrence would see a different action;
//   - an enum number, or a singular int32 member, outside int32 when its varint is read
//     as a two's-complement int64. The runtime truncates it, and 2^32+1
//     arrives as a declared class or as a timestamp's one nanosecond. A number
//     inside int32 is the declared-value or timestamp check's;
//   - a repeated or map field past the bound Validate holds it to. The runtime
//     builds every element before any check runs: 262144 bytes of empty
//     delegation hops cost 22 MB to refuse the ninth. It also copies a packed
//     field once per run, so a field sent as many one-element runs costs the
//     parse quadratic time unless the runs are counted together;
//   - two entries of one map that the runtime files under one key, and
//     anything in an entry besides its key and value (scanEntry).
//
// The JSON path refuses a field sent twice, an enum outside int32 and a key
// sent twice in its codec, so those carry no sentinel here either. Bytes that
// are not wire format are refused as the parse would refuse them, in the same
// words.
func prescan(b []byte) error {
	return scanMessage(b, (*controlv1.ActionEnvelope)(nil).ProtoReflect().Descriptor(), "", 0)
}

// fieldState is what the scan of one message keeps about one of its fields:
// how many occurrences arrived and, for a map, the key each entry is filed
// under. The count comes first, so a map keeps at most MaxLabels keys.
type fieldState struct {
	count int
	keys  [][]byte
}

// scanMessage checks one message's fields in the order they arrive. A field
// this build does not know, or a known number sent as a wire type its kind is
// not read from, is skipped: the runtime keeps both as unknown fields, and the
// walk refuses them by number. Depth is bounded as the walk's is, and for the
// same reason.
func scanMessage(b []byte, md protoreflect.MessageDescriptor, path string, depth int) error {
	if depth > MaxNesting {
		return &ValidationError{Field: path, Err: fmt.Errorf("%w: nested deeper than %d", ErrTooLarge, MaxNesting)}
	}
	fields := md.Fields()
	states := make([]fieldState, fields.Len())
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return malformed(n)
		}
		value, size := consumeValue(num, typ, b[n:])
		if size < 0 {
			return malformed(size)
		}
		b = b[n+size:]
		fd := fields.ByNumber(num)
		if fd == nil || !readsAs(fd, typ) {
			continue
		}
		if err := scanField(fd, typ, value, &states[fd.Index()], join(path, string(fd.Name())), depth); err != nil {
			return err
		}
	}
	return nil
}

// wireValue is what one field carries: the payload of a length-delimited field
// or the body of a group, or the number a varint holds.
type wireValue struct {
	bytes  []byte
	varint uint64
}

// consumeValue parses the value after a tag once, so no check reads bytes that
// were not parsed.
func consumeValue(num protowire.Number, typ protowire.Type, b []byte) (wireValue, int) {
	switch typ {
	case protowire.VarintType:
		v, n := protowire.ConsumeVarint(b)
		return wireValue{varint: v}, n
	case protowire.BytesType:
		v, n := protowire.ConsumeBytes(b)
		return wireValue{bytes: v}, n
	case protowire.StartGroupType:
		v, n := protowire.ConsumeGroup(num, b)
		return wireValue{bytes: v}, n
	}
	return wireValue{}, protowire.ConsumeFieldValue(num, typ, b)
}

// scanField counts one occurrence of a declared field and checks what it
// carries.
func scanField(fd protoreflect.FieldDescriptor, typ protowire.Type, v wireValue, st *fieldState, path string, depth int) error {
	switch {
	case isPackedRun(fd, typ):
		return scanPacked(fd, v.bytes, &st.count, path)
	case fd.IsMap():
		if err := count(fd, &st.count, path); err != nil {
			return err
		}
		key, err := scanEntry(fd, v.bytes, path, depth+1)
		if err != nil {
			return err
		}
		return st.file(key, path)
	case fd.IsList():
		index := st.count
		if err := count(fd, &st.count, path); err != nil {
			return err
		}
		return scanValue(fd, v, path+"["+strconv.Itoa(index)+"]", depth)
	}
	st.count++
	if st.count > 1 {
		return sentTwice(path)
	}
	return scanValue(fd, v, path, depth)
}

// scanValue checks one value: an enum's number, an int32's width, a
// message's fields.
func scanValue(fd protoreflect.FieldDescriptor, v wireValue, path string, depth int) error {
	switch fd.Kind() {
	case protoreflect.EnumKind:
		if !fitsInt32(v.varint) {
			return enumOutsideInt32(path)
		}
	case protoreflect.Int32Kind:
		if !fitsInt32(v.varint) {
			return int32OutsideInt32(path)
		}
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return scanMessage(v.bytes, fd.Message(), path, depth+1)
	}
	return nil
}

// scanPacked reads one packed run of a repeated scalar. Every element counts
// towards the bound, across runs and unpacked elements alike, and an enum
// element is held to int32.
func scanPacked(fd protoreflect.FieldDescriptor, run []byte, seen *int, path string) error {
	for len(run) > 0 {
		var v uint64
		var n int
		switch wireType(fd.Kind()) {
		case protowire.VarintType:
			v, n = protowire.ConsumeVarint(run)
		case protowire.Fixed32Type:
			_, n = protowire.ConsumeFixed32(run)
		default:
			_, n = protowire.ConsumeFixed64(run)
		}
		if n < 0 {
			return malformed(n)
		}
		run = run[n:]
		index := *seen
		if err := count(fd, seen, path); err != nil {
			return err
		}
		if fd.Kind() == protoreflect.EnumKind && !fitsInt32(v) {
			return enumOutsideInt32(path + "[" + strconv.Itoa(index) + "]")
		}
	}
	return nil
}

// count adds one element to a collection and refuses it past the bound
// Validate holds the collection to, so both paths refuse the same count.
func count(fd protoreflect.FieldDescriptor, seen *int, path string) error {
	*seen++
	limit, unit := MaxLabels, "entries"
	if fd.Name() == "delegation" && fd.ContainingMessage().FullName() == fullName((*controlv1.ActionEnvelope)(nil)) {
		limit, unit = MaxDelegationDepth, "hops"
	}
	if *seen > limit {
		return &ValidationError{Field: path, Err: fmt.Errorf("%w: more than %d %s", ErrTooLarge, limit, unit)}
	}
	return nil
}

// fitsInt32 reads v as the runtime reads it before truncating, as a two's-
// complement int64. A negative int32 arrives sign-extended to ten bytes and
// fits.
func fitsInt32(v uint64) bool {
	const minInt32Varint = 1<<64 - 1<<31 // math.MinInt32, sign-extended
	return v <= math.MaxInt32 || v >= minInt32Varint
}

// readsAs reports whether the runtime reads fd from a value of wire type typ.
func readsAs(fd protoreflect.FieldDescriptor, typ protowire.Type) bool {
	return typ == wireType(fd.Kind()) || isPackedRun(fd, typ)
}

// isPackedRun reports a packed run: a repeated scalar sent length-delimited,
// which a parser accepts whether or not the field was declared packed.
func isPackedRun(fd protoreflect.FieldDescriptor, typ protowire.Type) bool {
	if !fd.IsList() || typ != protowire.BytesType {
		return false
	}
	switch wireType(fd.Kind()) {
	case protowire.VarintType, protowire.Fixed32Type, protowire.Fixed64Type:
		return true
	}
	return false
}

// wireType is the type the runtime reads a value of kind k from.
func wireType(k protoreflect.Kind) protowire.Type {
	switch k {
	case protoreflect.BoolKind, protoreflect.EnumKind, protoreflect.Int32Kind, protoreflect.Sint32Kind,
		protoreflect.Uint32Kind, protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Uint64Kind:
		return protowire.VarintType
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return protowire.Fixed32Type
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return protowire.Fixed64Type
	case protoreflect.GroupKind:
		return protowire.StartGroupType
	}
	return protowire.BytesType
}

// malformed refuses bytes that are not wire format, as the parse would.
func malformed(n int) error {
	return &ValidationError{Err: &codecError{reason: binaryDecodeReason, cause: protowire.ParseError(n)}}
}

func sentTwice(path string) error {
	return &ValidationError{Field: path, Err: errors.New("decode: a field that is not repeated occurs twice")}
}

func enumOutsideInt32(path string) error {
	return &ValidationError{Field: path, Err: errors.New("decode: an enum number outside int32")}
}

func int32OutsideInt32(path string) error {
	return &ValidationError{Field: path, Err: errors.New("decode: an int32 outside int32")}
}
