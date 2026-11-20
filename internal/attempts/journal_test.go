package attempts

import (
	"errors"
	"strings"
	"testing"
)

func TestJournalLinesParse(t *testing.T) {
	j, err := ParseJournal([]byte("{\"call\":\"read_order\",\"args\":{\"id\":\"ord-1\"}}\n{\"call\":\"ping\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Lines) != 2 || j.Lines[0].Call != "read_order" || j.Lines[0].Args.Canonical() != `{"id":"ord-1"}` ||
		j.Lines[1].Call != "ping" || j.Lines[1].Args != nil {
		t.Errorf("lines %+v", j.Lines)
	}
	if j, err := ParseJournal(nil); err != nil || len(j.Lines) != 0 {
		t.Errorf("an empty journal: %v, %v", j, err)
	}
}

func TestJournalRefusals(t *testing.T) {
	for _, c := range []struct{ name, raw string }{
		{"a torn last line", "{\"call\":\"a\"}\n{\"call\":\"b\""},
		{"a last line with no newline", "{\"call\":\"a\"}"},
		{"a whole line and one byte after it", "{\"call\":\"a\"}}"},
		{"a line that is not JSON", "{\"call\":\"a\"}\nnot json\n"},
		{"an empty line", "{\"call\":\"a\"}\n\n"},
		{"an unknown member", "{\"call\":\"a\",\"from\":\"x\"}\n"},
		{"a repeated member", "{\"call\":\"a\",\"call\":\"b\"}\n"},
		{"no call", "{\"args\":{}}\n"},
		{"an empty call", "{\"call\":\"\"}\n"},
		{"a call that is not a string", "{\"call\":1}\n"},
		{"a null", "{\"call\":\"a\",\"args\":null}\n"},
		{"two values on a line", "{\"call\":\"a\"} {\"call\":\"b\"}\n"},
		{"bytes that are not UTF-8", "{\"call\":\"a\xff\"}\n"},
	} {
		if _, err := ParseJournal([]byte(c.raw)); !errors.Is(err, ErrJournal) {
			t.Errorf("%s: %v, want %v", c.name, err, ErrJournal)
		}
	}
}

func TestJournalSizeBound(t *testing.T) {
	line := "{\"call\":\"a\",\"args\":\"" + strings.Repeat("x", MaxJournalBytes-len("{\"call\":\"a\",\"args\":\"\"}\n")) + "\"}\n"
	if _, err := ParseJournal([]byte(line)); err != nil {
		t.Errorf("a journal of exactly the bound: %v", err)
	}
	if _, err := ParseJournal([]byte(line + "\n")); err == nil || !strings.Contains(err.Error(), "the bound is") {
		t.Errorf("a journal one byte past the bound: %v", err)
	}
}
