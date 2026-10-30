package otelgenai

import (
	"errors"
	"slices"
	"strings"
)

const (
	inputMessages  = "gen_ai.input.messages"
	outputMessages = "gen_ai.output.messages"
)

var errNoParts = errors.New("message without parts or part without a type")

func messagesKey(key string) bool { return key == inputMessages || key == outputMessages }

// contentKey reports a key the record never holds unless the allowlist
// copies it: every GenAI attribute and every named content attribute.
func contentKey(key string) bool {
	return strings.HasPrefix(key, "gen_ai.") || slices.Contains(ContentAttributes, key)
}

// tally is the content one or more attribute lists held: the content keys,
// and the reasoning parts and unparsed values among their messages. One line
// cannot hold enough elements to overflow it.
type tally struct{ keys, reasoning, unparsed uint32 }

func (t *tally) add(o tally) {
	t.keys += o.keys
	t.reasoning += o.reasoning
	t.unparsed += o.unparsed
}

// count tallies one attribute, parsing a messages value within parts.
func (t *tally) count(kv *keyValue, parts *budget) {
	if !contentKey(kv.key) {
		return
	}
	t.keys++
	if !messagesKey(kv.key) {
		return
	}
	if n, ok := reasoningParts(&kv.value, parts); ok {
		t.reasoning += n
	} else {
		t.unparsed++
	}
}

// spanCounts is what one span, or the attributes around spans, lost on the
// way into the records.
type spanCounts struct {
	contentDropped uint32
	reasoning      uint64
	unparsed       uint64
	runIDsDropped  uint64
	stringsDropped uint64
}

func (c *spanCounts) add(t tally) {
	c.contentDropped += t.keys
	c.reasoning += uint64(t.reasoning)
	c.unparsed += uint64(t.unparsed)
}

// drop counts the content of l that the record does not keep: every content
// key but those kept names, which attributes() always retains.
func (c *spanCounts) drop(l *attrList, kept func(key string) bool) {
	t := l.content
	for i := range l.kept {
		if k := l.kept[i].key; contentKey(k) && kept(k) {
			t.keys--
		}
	}
	c.add(t)
}

func keepNone(string) bool { return false }

// reasoningParts counts the parts typed "reasoning" or "thinking" in a
// messages value, sent as a JSON string or as an array of key-value lists.
// ok is false when the value is not a list of messages with parts, so a
// value the importer could not read is never reported as holding none.
func reasoningParts(v *anyValue, parts *budget) (uint32, bool) {
	switch v.kind {
	case kindString:
		return reasoningInJSON(v.str, parts)
	case kindArray:
		return reasoningInArray(v.array)
	}
	return 0, false
}

func reasoningType(t string) bool { return t == "reasoning" || t == "thinking" }

// ignored reads any one JSON value and keeps nothing of it.
type ignored struct{}

func (*ignored) UnmarshalJSON([]byte) error { return nil }

// reasoningInJSON reads a messages string as strictly as the line: a member
// named twice, a part without a type, or more messages, parts and members
// than the line's parts budget has left, leaves it unparsed. Members other
// than parts and type are skipped whole.
func reasoningInJSON(s string, b *budget) (uint32, bool) {
	r := newReader(strings.NewReader(s), b)
	var n uint32
	err := r.array(func() error {
		k, err := r.message()
		n += k
		return err
	})
	if err != nil || !r.atEnd() {
		return 0, false
	}
	return n, true
}

func (r *reader) message() (uint32, error) {
	var n uint32
	found := false
	err := r.object(func(name string) error {
		if err := r.budget.take(); err != nil {
			return err
		}
		if name != "parts" {
			return r.dec.Decode(&ignored{})
		}
		found = true
		return r.array(func() error {
			reasoning, err := r.part()
			if reasoning {
				n++
			}
			return err
		})
	})
	if err == nil && !found {
		err = errNoParts
	}
	return n, err
}

func (r *reader) part() (bool, error) {
	var t string
	found := false
	err := r.object(func(name string) (err error) {
		if err := r.budget.take(); err != nil {
			return err
		}
		if name != "type" {
			return r.dec.Decode(&ignored{})
		}
		found = true
		t, err = r.str()
		return err
	})
	if err == nil && !found {
		err = errNoParts
	}
	return reasoningType(t), err
}

func reasoningInArray(messages []anyValue) (uint32, bool) {
	var n uint32
	for i := range messages {
		parts, ok := lookup(&messages[i], "parts")
		if !ok || parts.kind != kindArray {
			return 0, false
		}
		for j := range parts.array {
			t, ok := lookup(&parts.array[j], "type")
			if !ok || t.kind != kindString {
				return 0, false
			}
			if reasoningType(t.str) {
				n++
			}
		}
	}
	return n, true
}

func lookup(v *anyValue, key string) (*anyValue, bool) {
	if v.kind != kindKVList {
		return nil, false
	}
	for i := range v.kvlist {
		if v.kvlist[i].key == key {
			return &v.kvlist[i].value, true
		}
	}
	return nil, false
}
