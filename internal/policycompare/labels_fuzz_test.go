package policycompare

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzReadLabels: no input panics the reader, every refusal is one of its two
// sentinels, and what it reads keeps every bound it states.
func FuzzReadLabels(f *testing.F) {
	corpus, err := os.ReadFile(filepath.Join("..", "..", "testdata", "policy", "compare", "labels.json"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(corpus)
	f.Add([]byte(labelsHead + `"labels":[{"case":"a","label":"attack"}]}`))
	f.Add([]byte(`{"kind":"policy-case-labels/v1alpha2"}`))
	f.Add([]byte(labelsHead + `"labels":[{"case":"a","label":"attack"},{"case":"a","label":"legitimate"}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		l, err := ReadLabels(raw)
		if err != nil {
			if !errors.Is(err, ErrLabels) && !errors.Is(err, ErrLabelsKind) {
				t.Fatalf("a refusal of neither kind: %v", err)
			}
			return
		}
		checkReadLabels(t, l)
	})
}

func checkReadLabels(t *testing.T, l *Labels) {
	t.Helper()
	if n := len(l.Labeller); n == 0 || n > maxLabellerBytes || !utf8.ValidString(l.Labeller) || strings.ContainsFunc(l.Labeller, unicode.IsControl) {
		t.Fatalf("labeller %q read", l.Labeller)
	}
	if n := len(l.ByCase); n == 0 || n > MaxLabels {
		t.Fatalf("%d labels read", n)
	}
	for id, label := range l.ByCase {
		if id == "" || (label != Attack && label != Legitimate) {
			t.Fatalf("case %q labelled %q", id, label)
		}
	}
}
