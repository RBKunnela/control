package pyschema

import (
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	typeString  = descriptorpb.FieldDescriptorProto_TYPE_STRING
	typeBytes   = descriptorpb.FieldDescriptorProto_TYPE_BYTES
	typeBool    = descriptorpb.FieldDescriptorProto_TYPE_BOOL
	typeInt64   = descriptorpb.FieldDescriptorProto_TYPE_INT64
	typeEnum    = descriptorpb.FieldDescriptorProto_TYPE_ENUM
	typeMessage = descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
)

// compile builds one proto3 file of package wire.test the way the compiler
// would, beside the well-known types a field of it may name.
func compile(t *testing.T, messages []*descriptorpb.DescriptorProto, enums []*descriptorpb.EnumDescriptorProto) protoreflect.FileDescriptor {
	t.Helper()
	files := new(protoregistry.Files)
	known := []protoreflect.FileDescriptor{
		timestamppb.File_google_protobuf_timestamp_proto,
		durationpb.File_google_protobuf_duration_proto,
		anypb.File_google_protobuf_any_proto,
	}
	fdp := &descriptorpb.FileDescriptorProto{
		Name: proto.String("wire/test/planted.proto"), Package: proto.String("wire.test"), Syntax: proto.String("proto3"),
		MessageType: messages, EnumType: enums,
	}
	for _, fd := range known {
		if err := files.RegisterFile(fd); err != nil {
			t.Fatalf("registering %s: %v", fd.Path(), err)
		}
		fdp.Dependency = append(fdp.Dependency, fd.Path())
	}
	fd, err := protodesc.NewFile(fdp, files)
	if err != nil {
		t.Fatalf("building the planted file: %v", err)
	}
	return fd
}

func field(name string, number int32, typ descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
	f := &descriptorpb.FieldDescriptorProto{
		Name: proto.String(name), Number: proto.Int32(number), Type: typ.Enum(),
		Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
	}
	if typeName != "" {
		f.TypeName = proto.String(typeName)
	}
	return f
}

func repeated(f *descriptorpb.FieldDescriptorProto) *descriptorpb.FieldDescriptorProto {
	f.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	return f
}

// entry is the nested message a map field is compiled to.
func entry(name string, key descriptorpb.FieldDescriptorProto_Type, value *descriptorpb.FieldDescriptorProto) *descriptorpb.DescriptorProto {
	return &descriptorpb.DescriptorProto{
		Name:    proto.String(name),
		Field:   []*descriptorpb.FieldDescriptorProto{field("key", 1, key, ""), value},
		Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
	}
}

func colour() *descriptorpb.EnumDescriptorProto {
	return &descriptorpb.EnumDescriptorProto{
		Name: proto.String("Colour"),
		Value: []*descriptorpb.EnumValueDescriptorProto{
			{Name: proto.String("COLOUR_UNSPECIFIED"), Number: proto.Int32(0)},
			{Name: proto.String("COLOUR_BLUE"), Number: proto.Int32(9)},
			{Name: proto.String("COLOUR_RED"), Number: proto.Int32(7)},
		},
	}
}

// Every kind and shape the table holds, in one message that also reaches
// itself, beside a message and an enum nothing reaches. Part declares its
// members and Colour its values out of number order.
func TestBuildHoldsEveryKindAndShape(t *testing.T) {
	whole := &descriptorpb.DescriptorProto{
		Name: proto.String("Whole"),
		Field: []*descriptorpb.FieldDescriptorProto{
			field("id", 1, typeString, ""),
			field("raw_bytes", 2, typeBytes, ""),
			field("on", 3, typeBool, ""),
			field("count", 4, typeInt64, ""),
			field("colour", 5, typeEnum, ".wire.test.Colour"),
			field("part", 6, typeMessage, ".wire.test.Part"),
			field("at", 7, typeMessage, ".google.protobuf.Timestamp"),
			field("wait_for", 8, typeMessage, ".google.protobuf.Duration"),
			repeated(field("tags", 9, typeString, "")),
			repeated(field("parts", 10, typeMessage, ".wire.test.Part")),
			repeated(field("labels", 11, typeMessage, ".wire.test.Whole.LabelsEntry")),
			repeated(field("shades", 12, typeMessage, ".wire.test.Whole.ShadesEntry")),
			repeated(field("seen_at", 13, typeMessage, ".google.protobuf.Timestamp")),
			field("next", 14, typeMessage, ".wire.test.Whole"),
		},
		NestedType: []*descriptorpb.DescriptorProto{
			entry("LabelsEntry", typeString, field("value", 2, typeString, "")),
			entry("ShadesEntry", typeString, field("value", 2, typeEnum, ".wire.test.Colour")),
		},
	}
	part := &descriptorpb.DescriptorProto{
		Name: proto.String("Part"),
		Field: []*descriptorpb.FieldDescriptorProto{
			field("blob", 2, typeBytes, ""),
			field("name", 1, typeString, ""),
		},
	}
	unreached := &descriptorpb.DescriptorProto{
		Name:  proto.String("Unreached"),
		Field: []*descriptorpb.FieldDescriptorProto{field("shade", 1, typeEnum, ".wire.test.Unused")},
	}
	unused := &descriptorpb.EnumDescriptorProto{
		Name:  proto.String("Unused"),
		Value: []*descriptorpb.EnumValueDescriptorProto{{Name: proto.String("UNUSED_UNSPECIFIED"), Number: proto.Int32(0)}},
	}
	fd := compile(t, []*descriptorpb.DescriptorProto{whole, part, unreached}, []*descriptorpb.EnumDescriptorProto{colour(), unused})

	got, err := Build(fd.Messages().ByName("Whole"))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := Model{
		Messages: []Message{
			{Name: "wire.test.Part", Members: []Member{
				{JSONName: "name", Number: 1, Kind: KindString, Shape: ShapeOne},
				{JSONName: "blob", Number: 2, Kind: KindBytes, Shape: ShapeOne},
			}},
			{Name: "wire.test.Whole", Members: []Member{
				{JSONName: "id", Number: 1, Kind: "string", Shape: "one"},
				{JSONName: "rawBytes", Number: 2, Kind: "bytes", Shape: "one"},
				{JSONName: "on", Number: 3, Kind: "bool", Shape: "one"},
				{JSONName: "count", Number: 4, Kind: "int64", Shape: "one"},
				{JSONName: "colour", Number: 5, Kind: "enum", Shape: "one", TypeName: "wire.test.Colour"},
				{JSONName: "part", Number: 6, Kind: "message", Shape: "one", TypeName: "wire.test.Part"},
				{JSONName: "at", Number: 7, Kind: "timestamp", Shape: "one"},
				{JSONName: "waitFor", Number: 8, Kind: "duration", Shape: "one"},
				{JSONName: "tags", Number: 9, Kind: "string", Shape: "list"},
				{JSONName: "parts", Number: 10, Kind: "message", Shape: "list", TypeName: "wire.test.Part"},
				{JSONName: "labels", Number: 11, Kind: "string", Shape: "map"},
				{JSONName: "shades", Number: 12, Kind: "enum", Shape: "map", TypeName: "wire.test.Colour"},
				{JSONName: "seenAt", Number: 13, Kind: "timestamp", Shape: "list"},
				{JSONName: "next", Number: 14, Kind: "message", Shape: "one", TypeName: "wire.test.Whole"},
			}},
		},
		Enums: []Enum{
			{Name: "wire.test.Colour", Values: []Value{
				{Name: "COLOUR_UNSPECIFIED", Number: 0},
				{Name: "COLOUR_RED", Number: 7},
				{Name: "COLOUR_BLUE", Number: 9},
			}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Build:\n got %+v\nwant %+v", got, want)
	}
}

// planted is one field the table has no kind for, in message Odd, with what
// the compiler would declare beside it.
type planted struct {
	field  *descriptorpb.FieldDescriptorProto
	nested []*descriptorpb.DescriptorProto
	oneofs []string
	want   string
}

func kindCase(typ descriptorpb.FieldDescriptorProto_Type, kind string) planted {
	return planted{field: field("odd", 1, typ, ""), want: "wire.test.Odd.odd: kind " + kind + ": the table has no rule for this field"}
}

func plantedCases() map[string]planted {
	inOneof := field("left", 1, typeString, "")
	inOneof.OneofIndex = proto.Int32(0)
	optional := field("score", 1, typeInt64, "")
	optional.OneofIndex = proto.Int32(0)
	optional.Proto3Optional = proto.Bool(true)
	return map[string]planted{
		"a double":           kindCase(descriptorpb.FieldDescriptorProto_TYPE_DOUBLE, "double"),
		"a float":            kindCase(descriptorpb.FieldDescriptorProto_TYPE_FLOAT, "float"),
		"an int32":           kindCase(descriptorpb.FieldDescriptorProto_TYPE_INT32, "int32"),
		"a sint32":           kindCase(descriptorpb.FieldDescriptorProto_TYPE_SINT32, "sint32"),
		"a sfixed32":         kindCase(descriptorpb.FieldDescriptorProto_TYPE_SFIXED32, "sfixed32"),
		"a uint32":           kindCase(descriptorpb.FieldDescriptorProto_TYPE_UINT32, "uint32"),
		"a fixed32":          kindCase(descriptorpb.FieldDescriptorProto_TYPE_FIXED32, "fixed32"),
		"a uint64":           kindCase(descriptorpb.FieldDescriptorProto_TYPE_UINT64, "uint64"),
		"a fixed64":          kindCase(descriptorpb.FieldDescriptorProto_TYPE_FIXED64, "fixed64"),
		"a sint64":           kindCase(descriptorpb.FieldDescriptorProto_TYPE_SINT64, "sint64"),
		"a sfixed64":         kindCase(descriptorpb.FieldDescriptorProto_TYPE_SFIXED64, "sfixed64"),
		"a list of doubles":  {field: repeated(field("ratios", 1, descriptorpb.FieldDescriptorProto_TYPE_DOUBLE, "")), want: "wire.test.Odd.ratios: kind double: the table has no rule for this field"},
		"a oneof member":     {field: inOneof, oneofs: []string{"side"}, want: "wire.test.Odd.left: member of oneof side: the table has no rule for this field"},
		"a tracked presence": {field: optional, oneofs: []string{"_score"}, want: "wire.test.Odd.score: scalar that tracks presence: the table has no rule for this field"},
		"another well-known type": {
			field: field("anything", 1, typeMessage, ".google.protobuf.Any"),
			want:  "wire.test.Odd.anything: well-known type google.protobuf.Any: the table has no rule for this field",
		},
		"a map keyed by a number": {
			field:  repeated(field("by_number", 1, typeMessage, ".wire.test.Odd.ByNumberEntry")),
			nested: []*descriptorpb.DescriptorProto{entry("ByNumberEntry", typeInt64, field("value", 2, typeString, ""))},
			want:   "wire.test.Odd.by_number: map keyed by int64: the table has no rule for this field",
		},
		"a map keyed by a bool": {
			field:  repeated(field("by_flag", 1, typeMessage, ".wire.test.Odd.ByFlagEntry")),
			nested: []*descriptorpb.DescriptorProto{entry("ByFlagEntry", typeBool, field("value", 2, typeString, ""))},
			want:   "wire.test.Odd.by_flag: map keyed by bool: the table has no rule for this field",
		},
		"a map of messages": {
			field:  repeated(field("children", 1, typeMessage, ".wire.test.Odd.ChildrenEntry")),
			nested: []*descriptorpb.DescriptorProto{entry("ChildrenEntry", typeString, field("value", 2, typeMessage, ".wire.test.Child"))},
			want:   "wire.test.Odd.children: map of messages: the table has no rule for this field",
		},
		"a map of timestamps": {
			field:  repeated(field("seen", 1, typeMessage, ".wire.test.Odd.SeenEntry")),
			nested: []*descriptorpb.DescriptorProto{entry("SeenEntry", typeString, field("value", 2, typeMessage, ".google.protobuf.Timestamp"))},
			want:   "wire.test.Odd.seen: map of messages: the table has no rule for this field",
		},
		"a map of doubles": {
			field:  repeated(field("scores", 1, typeMessage, ".wire.test.Odd.ScoresEntry")),
			nested: []*descriptorpb.DescriptorProto{entry("ScoresEntry", typeString, field("value", 2, descriptorpb.FieldDescriptorProto_TYPE_DOUBLE, ""))},
			want:   "wire.test.Odd.scores: kind double: the table has no rule for this field",
		},
	}
}

func TestBuildRefusesAFieldTheTableHasNoKindFor(t *testing.T) {
	for name, c := range plantedCases() {
		t.Run(name, func(t *testing.T) {
			odd := &descriptorpb.DescriptorProto{Name: proto.String("Odd"), Field: []*descriptorpb.FieldDescriptorProto{c.field}, NestedType: c.nested}
			for _, o := range c.oneofs {
				odd.OneofDecl = append(odd.OneofDecl, &descriptorpb.OneofDescriptorProto{Name: proto.String(o)})
			}
			child := &descriptorpb.DescriptorProto{Name: proto.String("Child"), Field: []*descriptorpb.FieldDescriptorProto{field("id", 1, typeString, "")}}
			fd := compile(t, []*descriptorpb.DescriptorProto{odd, child}, nil)

			got, err := Build(fd.Messages().ByName("Odd"))
			if err == nil {
				t.Fatalf("Build accepted the field and returned %+v", got)
			}
			if !errors.Is(err, ErrUnsupported) {
				t.Errorf("the refusal is not ErrUnsupported: %v", err)
			}
			if err.Error() != c.want {
				t.Errorf("refusal:\n got %q\nwant %q", err, c.want)
			}
			if !reflect.DeepEqual(got, Model{}) {
				t.Errorf("a refusal came with a model: %+v", got)
			}
		})
	}
}

// The field is two messages away from the one the closure starts at, behind
// a list.
func TestBuildRefusesAFieldOfAMessageItReaches(t *testing.T) {
	top := &descriptorpb.DescriptorProto{
		Name:  proto.String("Top"),
		Field: []*descriptorpb.FieldDescriptorProto{field("id", 1, typeString, ""), repeated(field("middles", 2, typeMessage, ".wire.test.Middle"))},
	}
	middle := &descriptorpb.DescriptorProto{
		Name:  proto.String("Middle"),
		Field: []*descriptorpb.FieldDescriptorProto{field("leaf", 1, typeMessage, ".wire.test.Leaf")},
	}
	leaf := &descriptorpb.DescriptorProto{
		Name:  proto.String("Leaf"),
		Field: []*descriptorpb.FieldDescriptorProto{field("ratio", 1, descriptorpb.FieldDescriptorProto_TYPE_FLOAT, "")},
	}
	fd := compile(t, []*descriptorpb.DescriptorProto{top, middle, leaf}, nil)

	_, err := Build(fd.Messages().ByName("Top"))
	const want = "wire.test.Leaf.ratio: kind float: the table has no rule for this field"
	if err == nil || err.Error() != want || !errors.Is(err, ErrUnsupported) {
		t.Errorf("Build: got %v, want %q", err, want)
	}
}

// A proto3 optional message tracks nothing a plain message field does not, so
// it is read as one.
func TestBuildReadsAnOptionalMessageAsAMessage(t *testing.T) {
	optional := field("part", 1, typeMessage, ".wire.test.Part")
	optional.OneofIndex = proto.Int32(0)
	optional.Proto3Optional = proto.Bool(true)
	holder := &descriptorpb.DescriptorProto{
		Name: proto.String("Holder"), Field: []*descriptorpb.FieldDescriptorProto{optional},
		OneofDecl: []*descriptorpb.OneofDescriptorProto{{Name: proto.String("_part")}},
	}
	part := &descriptorpb.DescriptorProto{Name: proto.String("Part")}
	fd := compile(t, []*descriptorpb.DescriptorProto{holder, part}, nil)

	got, err := Build(fd.Messages().ByName("Holder"))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := Model{Messages: []Message{
		{Name: "wire.test.Holder", Members: []Member{{JSONName: "part", Number: 1, Kind: "message", Shape: "one", TypeName: "wire.test.Part"}}},
		{Name: "wire.test.Part", Members: []Member{}},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Build:\n got %+v\nwant %+v", got, want)
	}
}
