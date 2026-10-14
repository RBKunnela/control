package pyschema

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/reflect/protoreflect"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
)

// Kind is how one value of a member is written in JSON.
type Kind string

// The kinds a reader has a rule for. A Timestamp and a Duration are kinds and
// not messages: each is written as one string its fields do not describe.
const (
	KindString    Kind = "string"
	KindBytes     Kind = "bytes"
	KindBool      Kind = "bool"
	KindInt64     Kind = "int64"
	KindEnum      Kind = "enum"
	KindMessage   Kind = "message"
	KindTimestamp Kind = "timestamp"
	KindDuration  Kind = "duration"
)

// Shape is how many values a member holds.
type Shape string

// The shapes a reader has a rule for. A map is keyed by strings.
const (
	ShapeOne  Shape = "one"
	ShapeList Shape = "list"
	ShapeMap  Shape = "map"
)

// ErrUnsupported is the refusal of a field no Kind and Shape describe. A
// reader given a guess in its place would read an answer wrongly.
var ErrUnsupported = errors.New("the table has no rule for this field")

// Member is one field of a message. TypeName is the full name of the enum or
// message a value is one of, and empty for every other kind.
type Member struct {
	JSONName string
	Number   int32
	Kind     Kind
	Shape    Shape
	TypeName string
}

// Message is a message by its full name, its members in field-number order.
type Message struct {
	Name    string
	Members []Member
}

// Value is one declared value of an enum.
type Value struct {
	Name   string
	Number int32
}

// Enum is an enum by its full name, its values in number order.
type Enum struct {
	Name   string
	Values []Value
}

// Model is a set of messages and the enums they use, each sorted by full
// name.
type Model struct {
	Messages []Message
	Enums    []Enum
}

const (
	timestampName protoreflect.FullName = "google.protobuf.Timestamp"
	durationName  protoreflect.FullName = "google.protobuf.Duration"
	// Every other message of this package may have a JSON form of its own,
	// which its fields do not describe.
	wellKnownPackage protoreflect.FullName = "google.protobuf"
)

// Roots are the bodies of the enforcement API: what a client writes and what
// it reads at the top of a request or an answer.
func Roots() []protoreflect.MessageDescriptor {
	return []protoreflect.MessageDescriptor{
		(&enforcev1alpha1.AdmitRequest{}).ProtoReflect().Descriptor(),
		(&enforcev1alpha1.AdmitResponse{}).ProtoReflect().Descriptor(),
		(&enforcev1alpha1.CompleteRequest{}).ProtoReflect().Descriptor(),
		(&enforcev1alpha1.CompleteResponse{}).ProtoReflect().Descriptor(),
		(&enforcev1alpha1.AbortRequest{}).ProtoReflect().Descriptor(),
		(&enforcev1alpha1.AbortResponse{}).ProtoReflect().Descriptor(),
		(&enforcev1alpha1.Error{}).ProtoReflect().Descriptor(),
	}
}

// Build returns the closure of roots: each of them and every message and
// enum a member reaches. It refuses, with ErrUnsupported and the field's
// full name, a field that is not a string, bytes, bool, int64, enum, message,
// Timestamp or Duration held once, in a list or in a map from strings: a
// oneof member, a scalar that tracks presence, a map keyed by anything else
// or holding messages, and any other well-known type are among them.
func Build(roots ...protoreflect.MessageDescriptor) (Model, error) {
	b := builder{messages: map[protoreflect.FullName]Message{}, enums: map[protoreflect.FullName]Enum{}}
	for _, root := range roots {
		if err := b.message(root); err != nil {
			return Model{}, err
		}
	}
	var m Model
	for _, msg := range b.messages {
		m.Messages = append(m.Messages, msg)
	}
	for _, e := range b.enums {
		m.Enums = append(m.Enums, e)
	}
	slices.SortFunc(m.Messages, func(x, y Message) int { return cmp.Compare(x.Name, y.Name) })
	slices.SortFunc(m.Enums, func(x, y Enum) int { return cmp.Compare(x.Name, y.Name) })
	return m, nil
}

type builder struct {
	messages map[protoreflect.FullName]Message
	enums    map[protoreflect.FullName]Enum
}

func (b *builder) message(md protoreflect.MessageDescriptor) error {
	name := md.FullName()
	if _, seen := b.messages[name]; seen {
		return nil
	}
	// Entered before its members are read, so a message that reaches itself
	// ends here.
	b.messages[name] = Message{}
	fields := md.Fields()
	members := make([]Member, 0, fields.Len())
	for i := range fields.Len() {
		member, err := b.member(fields.Get(i))
		if err != nil {
			return err
		}
		members = append(members, member)
	}
	slices.SortFunc(members, func(x, y Member) int { return cmp.Compare(x.Number, y.Number) })
	b.messages[name] = Message{Name: string(name), Members: members}
	return nil
}

func (b *builder) member(f protoreflect.FieldDescriptor) (Member, error) {
	shape, value, reason := shapeOf(f)
	if reason != "" {
		return Member{}, refusal(f, reason)
	}
	member := Member{JSONName: f.JSONName(), Number: int32(f.Number()), Shape: shape}
	switch value.Kind() {
	case protoreflect.StringKind:
		member.Kind = KindString
	case protoreflect.BytesKind:
		member.Kind = KindBytes
	case protoreflect.BoolKind:
		member.Kind = KindBool
	case protoreflect.Int64Kind:
		member.Kind = KindInt64
	case protoreflect.EnumKind:
		member.Kind, member.TypeName = KindEnum, string(value.Enum().FullName())
		b.enum(value.Enum())
	case protoreflect.MessageKind:
		return b.messageMember(f, value.Message(), member)
	default:
		return Member{}, refusal(f, "kind "+value.Kind().String())
	}
	return member, nil
}

// messageMember fills in a member whose values are messages: a Timestamp or
// a Duration is a kind of its own, and any other message joins the closure.
func (b *builder) messageMember(f protoreflect.FieldDescriptor, md protoreflect.MessageDescriptor, member Member) (Member, error) {
	switch {
	case md.FullName() == timestampName:
		member.Kind = KindTimestamp
	case md.FullName() == durationName:
		member.Kind = KindDuration
	case md.ParentFile().Package() == wellKnownPackage:
		return Member{}, refusal(f, "well-known type "+string(md.FullName()))
	default:
		member.Kind, member.TypeName = KindMessage, string(md.FullName())
		if err := b.message(md); err != nil {
			return Member{}, err
		}
	}
	return member, nil
}

func (b *builder) enum(ed protoreflect.EnumDescriptor) {
	if _, seen := b.enums[ed.FullName()]; seen {
		return
	}
	declared := ed.Values()
	values := make([]Value, 0, declared.Len())
	for i := range declared.Len() {
		values = append(values, Value{Name: string(declared.Get(i).Name()), Number: int32(declared.Get(i).Number())})
	}
	slices.SortStableFunc(values, func(x, y Value) int { return cmp.Compare(x.Number, y.Number) })
	b.enums[ed.FullName()] = Enum{Name: string(ed.FullName()), Values: values}
}

// shapeOf returns how many values f holds and the descriptor of one of them,
// or why no shape describes it.
func shapeOf(f protoreflect.FieldDescriptor) (Shape, protoreflect.FieldDescriptor, string) {
	switch {
	case f.IsMap():
		if key := f.MapKey().Kind(); key != protoreflect.StringKind {
			return "", nil, "map keyed by " + key.String()
		}
		if f.MapValue().Message() != nil {
			return "", nil, "map of messages"
		}
		return ShapeMap, f.MapValue(), ""
	case f.IsList():
		return ShapeList, f, ""
	case f.ContainingOneof() != nil && !f.ContainingOneof().IsSynthetic():
		return "", nil, "member of oneof " + string(f.ContainingOneof().Name())
	case f.HasPresence() && f.Message() == nil:
		return "", nil, "scalar that tracks presence"
	}
	return ShapeOne, f, ""
}

func refusal(f protoreflect.FieldDescriptor, reason string) error {
	return fmt.Errorf("%s: %s: %w", f.FullName(), reason, ErrUnsupported)
}
