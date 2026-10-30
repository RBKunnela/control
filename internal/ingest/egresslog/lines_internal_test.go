package egresslog

import (
	"bytes"
	"strings"
	"testing"
)

// A long line is dropped as it is read: next never holds more of it than the
// bound, and hands back none of it.
func TestLongLineIsNotHeld(t *testing.T) {
	in := strings.Repeat("x", 4*MaxLineBytes) + "\n" + "{}\n" + "partial"
	l := newLines(strings.NewReader(in))
	line, tooLong, ok, err := l.next()
	if err != nil || !ok || !tooLong || line != nil {
		t.Fatalf("long line: %d bytes, tooLong %v, ok %v, err %v", len(line), tooLong, ok, err)
	}
	line, tooLong, ok, err = l.next()
	if err != nil || !ok || tooLong || !bytes.Equal(line, []byte("{}")) {
		t.Fatalf("next line: %q, tooLong %v, ok %v, err %v", line, tooLong, ok, err)
	}
	if _, _, ok, err := l.next(); ok || err != nil {
		t.Fatalf("a line with no newline was read: ok %v, err %v", ok, err)
	}
	if want := uint64(4*MaxLineBytes + 1 + 3); l.consumed != want {
		t.Fatalf("consumed %d, want %d", l.consumed, want)
	}
}

// Past the bound by one byte, the line is already not kept.
func TestLineOverTheBoundByOne(t *testing.T) {
	l := newLines(strings.NewReader(strings.Repeat("x", MaxLineBytes+1) + "\n"))
	if line, tooLong, ok, err := l.next(); err != nil || !ok || !tooLong || line != nil {
		t.Fatalf("%d bytes held, tooLong %v, ok %v, err %v", len(line), tooLong, ok, err)
	}
}

func TestFirstLineDigest(t *testing.T) {
	l := newLines(strings.NewReader("test\nsecond\n"))
	for {
		if _, _, ok, _ := l.next(); !ok {
			break
		}
	}
	// SHA-256 of "test".
	if got := l.firstLineSHA256(); got != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("first line digest %s", got)
	}
	l = newLines(strings.NewReader("no newline"))
	if _, _, ok, _ := l.next(); ok {
		t.Fatal("a line with no newline was read")
	}
	if got := l.firstLineSHA256(); got != "" {
		t.Fatalf("digest of no line: %q", got)
	}
}
