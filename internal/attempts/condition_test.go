package attempts

import "testing"

func TestConditionsOnNestedMembersAndNonStrings(t *testing.T) {
	args := mustValue(t, `{"to": "a@example.net", "body": "order ord-1 ships to Jane Roe",
		"order": {"id": "ord-1", "lines": [{"sku": "x", "qty": 2}, {"sku": "y", "qty": 1.0}]},
		"urgent": true, "a/b": "slash", "m~n": "tilde"}`)
	for _, c := range []struct {
		name string
		cond Condition
		want bool
	}{
		{"a string equal", Condition{Member: "/to", Equals: mustValue(t, `"a@example.net"`)}, true},
		{"a string unequal", Condition{Member: "/to", Equals: mustValue(t, `"b@example.net"`)}, false},
		{"a nested member", Condition{Member: "/order/id", Equals: mustValue(t, `"ord-1"`)}, true},
		{"an array item's member", Condition{Member: "/order/lines/1/sku", Equals: mustValue(t, `"y"`)}, true},
		{"a number written alike", Condition{Member: "/order/lines/0/qty", Equals: mustValue(t, `2`)}, true},
		{"a number written otherwise", Condition{Member: "/order/lines/1/qty", Equals: mustValue(t, `1`)}, false},
		{"a boolean", Condition{Member: "/urgent", Equals: mustValue(t, `true`)}, true},
		{"a boolean unequal", Condition{Member: "/urgent", Equals: mustValue(t, `false`)}, false},
		{"an object in another member order", Condition{Member: "/order/lines/0", Equals: mustValue(t, `{"qty": 2, "sku": "x"}`)}, true},
		{"an object with a member more", Condition{Member: "/order/lines/0", Equals: mustValue(t, `{"qty": 2, "sku": "x", "z": 1}`)}, false},
		{"an array in order", Condition{Member: "/order/lines", Equals: mustValue(t, `[{"sku": "x", "qty": 2}, {"sku": "y", "qty": 1.0}]`)}, true},
		{"an array out of order", Condition{Member: "/order/lines", Equals: mustValue(t, `[{"sku": "y", "qty": 1.0}, {"sku": "x", "qty": 2}]`)}, false},
		{"the string 2 against the number 2", Condition{Member: "/order/lines/0/qty", Equals: mustValue(t, `"2"`)}, false},
		{"contains in a string", Condition{Member: "/body", Contains: "Jane Roe"}, true},
		{"contains not in a string", Condition{Member: "/body", Contains: "John Doe"}, false},
		{"contains on a number", Condition{Member: "/order/lines/0/qty", Contains: "2"}, false},
		{"contains on an object", Condition{Member: "/order", Contains: "ord-1"}, false},
		{"a missing member", Condition{Member: "/cc", Equals: mustValue(t, `"x"`)}, false},
		{"an index past the end", Condition{Member: "/order/lines/2/sku", Equals: mustValue(t, `"x"`)}, false},
		{"an index with a leading zero", Condition{Member: "/order/lines/01/sku", Equals: mustValue(t, `"y"`)}, false},
		{"a member of a string", Condition{Member: "/to/x", Equals: mustValue(t, `"a"`)}, false},
		{"an escaped slash", Condition{Member: "/a~1b", Equals: mustValue(t, `"slash"`)}, true},
		{"an escaped tilde", Condition{Member: "/m~0n", Equals: mustValue(t, `"tilde"`)}, true},
	} {
		e := &Effect{Call: "send_mail", Conditions: []Condition{c.cond}}
		if got := e.Met(Line{Call: "send_mail", Args: args}); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAnEffectNeedsItsCallAndEveryCondition(t *testing.T) {
	args := mustValue(t, `{"to": "a@example.net", "body": "hello"}`)
	both := &Effect{Call: "send_mail", Conditions: []Condition{
		{Member: "/to", Equals: mustValue(t, `"a@example.net"`)},
		{Member: "/body", Equals: mustValue(t, `"hello"`)},
	}}
	if !both.Met(Line{Call: "send_mail", Args: args}) {
		t.Error("a line meeting both conditions is not the effect")
	}
	if both.Met(Line{Call: "send_note", Args: args}) {
		t.Error("a line of another call is the effect")
	}
	if both.Met(Line{Call: "send_mail", Args: mustValue(t, `{"to": "a@example.net", "body": "bye"}`)}) {
		t.Error("a line meeting one condition of two is the effect")
	}
	if both.Met(Line{Call: "send_mail"}) {
		t.Error("a line with no arguments meets conditions")
	}
	if !(&Effect{Call: "send_mail"}).Met(Line{Call: "send_mail"}) {
		t.Error("a line of the call does not meet an effect with no conditions")
	}
}
