package policycompare

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const labelsHead = `{"kind":"policy-case-labels/v1alpha1","labeller":"Orders security review",`

func TestReadLabelsReadsAWholeFile(t *testing.T) {
	l, err := ReadLabels([]byte(labelsHead + `"labels":[{"case":"case:a.json","label":"attack"},` +
		`{"label":"legitimate","case":"request:r1"}]}` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l.Labeller != "Orders security review" || len(l.ByCase) != 2 || l.ByCase["case:a.json"] != Attack || l.ByCase["request:r1"] != Legitimate {
		t.Errorf("read %+v", l)
	}
}

func TestReadLabelsRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		raw  string
		kind bool
		want string
	}{
		"not an object":         {raw: `[]`, want: "want a JSON object"},
		"kind not first":        {raw: `{"labeller":"x","kind":"policy-case-labels/v1alpha1","labels":[]}`, want: "kind: want it as the first member"},
		"another kind":          {raw: `{"kind":"policy-case-labels/v1alpha2","labeller":"x"}`, kind: true, want: "kind"},
		"kind null":             {raw: `{"kind":null,"labeller":"x"}`, want: "kind: want a string"},
		"kind another case":     {raw: `{"Kind":"policy-case-labels/v1alpha1"}`, want: "kind: want it as the first member"},
		"an unknown member":     {raw: labelsHead + `"labels":[{"case":"a","label":"attack"}],"author":"x"}`, want: `"author": a member the format does not have`},
		"a member twice":        {raw: labelsHead + `"labeller":"y","labels":[{"case":"a","label":"attack"}]}`, want: "labeller: given twice"},
		"labels missing":        {raw: labelsHead[:len(labelsHead)-1] + `}`, want: "labels: missing"},
		"labeller missing":      {raw: `{"kind":"policy-case-labels/v1alpha1","labels":[{"case":"a","label":"attack"}]}`, want: "labeller: missing"},
		"labeller null":         {raw: `{"kind":"policy-case-labels/v1alpha1","labeller":null,"labels":[{"case":"a","label":"attack"}]}`, want: "labeller: want a string"},
		"labeller empty":        {raw: `{"kind":"policy-case-labels/v1alpha1","labeller":"","labels":[{"case":"a","label":"attack"}]}`, want: "labeller: want 1 to 200 bytes"},
		"labeller too long":     {raw: `{"kind":"policy-case-labels/v1alpha1","labeller":"` + strings.Repeat("x", 201) + `","labels":[{"case":"a","label":"attack"}]}`, want: "labeller: want 1 to 200 bytes"},
		"labeller control":      {raw: `{"kind":"policy-case-labels/v1alpha1","labeller":"a\u001bb","labels":[{"case":"a","label":"attack"}]}`, want: "labeller: a control character"},
		"labels null":           {raw: labelsHead + `"labels":null}`, want: "labels: want a list"},
		"labels empty":          {raw: labelsHead + `"labels":[]}`, want: "labels: want 1 to 4096 labels"},
		"a label null":          {raw: labelsHead + `"labels":[null]}`, want: "labels[0]: want a JSON object"},
		"a label's case null":   {raw: labelsHead + `"labels":[{"case":null,"label":"attack"}]}`, want: "labels[0].case: want a string"},
		"a label's case empty":  {raw: labelsHead + `"labels":[{"case":"","label":"attack"}]}`, want: "labels[0].case: want a case id"},
		"a label unknown":       {raw: labelsHead + `"labels":[{"case":"a","label":"benign"}]}`, want: "labels[0].label: want attack or legitimate"},
		"a label's extra":       {raw: labelsHead + `"labels":[{"case":"a","label":"attack","why":"x"}]}`, want: `labels[0]."why": a member the format does not have`},
		"a label's member case": {raw: labelsHead + `"labels":[{"Case":"a","label":"attack"}]}`, want: `labels[0]."Case": a member the format does not have`},
		"a label missing":       {raw: labelsHead + `"labels":[{"case":"a"}]}`, want: "labels[0].label: missing"},
		"a case twice":          {raw: labelsHead + `"labels":[{"case":"a","label":"attack"},{"case":"a","label":"attack"}]}`, want: `labels[1]: case "a" is labelled twice`},
		"data after":            {raw: labelsHead + `"labels":[{"case":"a","label":"attack"}]}{}`, want: "data after the object"},
		"not UTF-8":             {raw: labelsHead + `"labels":[{"case":"a` + "\xff" + `","label":"attack"}]}`, want: "not UTF-8"},
	} {
		_, err := ReadLabels([]byte(c.raw))
		switch {
		case err == nil:
			t.Errorf("%s: read", name)
		case c.kind && !errors.Is(err, ErrLabelsKind):
			t.Errorf("%s: %v, want the kind refusal", name, err)
		case !c.kind && (!errors.Is(err, ErrLabels) || errors.Is(err, ErrLabelsKind)):
			t.Errorf("%s: %v, want a labels refusal", name, err)
		case !strings.Contains(err.Error(), c.want):
			t.Errorf("%s: %v, want it to say %q", name, err, c.want)
		}
	}
}

// MaxLabels labels are read; one more is refused for the count.
func TestReadLabelsBound(t *testing.T) {
	file := func(n int) []byte {
		entries := make([]string, n)
		for i := range entries {
			entries[i] = fmt.Sprintf(`{"case":"c%d","label":"attack"}`, i)
		}
		return []byte(labelsHead + `"labels":[` + strings.Join(entries, ",") + `]}`)
	}
	if l, err := ReadLabels(file(4096)); err != nil || len(l.ByCase) != 4096 {
		t.Fatalf("4096 labels: %v", err)
	}
	if _, err := ReadLabels(file(4097)); err == nil || !strings.Contains(err.Error(), "want 1 to 4096 labels") {
		t.Errorf("4097 labels: %v, want the bound", err)
	}
}
