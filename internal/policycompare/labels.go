package policycompare

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// LabelsKind is the one kind of labels file this build reads.
const LabelsKind = "policy-case-labels/v1alpha1"

const (
	// MaxLabels bounds the labels of one file: a case is labelled once, and a
	// run holds at most MaxCases.
	MaxLabels = MaxCases
	// maxLabellerBytes bounds the labeller's name.
	maxLabellerBytes = 200
)

// Label is what a labeller says a case is.
type Label string

const (
	// Attack is a case the labeller calls an attack.
	Attack Label = "attack"
	// Legitimate is a case the labeller calls legitimate work.
	Legitimate Label = "legitimate"
)

// Labels is one labels file: who labelled, and each case's label.
type Labels struct {
	Labeller string
	ByCase   map[string]Label
}

// ReadLabels reads a labels file strictly: kind first and checked before any
// other member, each member once and spelled exactly, none the format does
// not have, no null, valid UTF-8, nothing after the object. A kind this build
// does not read is ErrLabelsKind; every other refusal is ErrLabels and names
// the member it is about. Whether each case is one of the run is the run's to
// judge.
func ReadLabels(raw []byte) (*Labels, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: not UTF-8", ErrLabels)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("%w: want a JSON object", ErrLabels)
	}
	if err := readKind(dec); err != nil {
		return nil, err
	}
	m, err := members(dec, "", []string{"labeller", "labels"})
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after the object", ErrLabels)
	}
	l := &Labels{}
	if l.Labeller, err = labeller(m["labeller"]); err != nil {
		return nil, err
	}
	if l.ByCase, err = labelList(m["labels"]); err != nil {
		return nil, err
	}
	return l, nil
}

func labelList(raw json.RawMessage) (map[string]Label, error) {
	var list []json.RawMessage
	if isNull(raw) || json.Unmarshal(raw, &list) != nil {
		return nil, fmt.Errorf("%w: labels: want a list", ErrLabels)
	}
	if len(list) == 0 || len(list) > MaxLabels {
		return nil, fmt.Errorf("%w: labels: want 1 to %d labels, not %d", ErrLabels, MaxLabels, len(list))
	}
	byCase := make(map[string]Label, len(list))
	for i, entry := range list {
		at := fmt.Sprintf("labels[%d]", i)
		id, label, err := readLabel(entry, at)
		if err != nil {
			return nil, err
		}
		if _, twice := byCase[id]; twice {
			return nil, fmt.Errorf("%w: %s: case %s is labelled twice", ErrLabels, at, strconv.Quote(id))
		}
		byCase[id] = label
	}
	return byCase, nil
}

// readKind reads the first member, which has to be kind.
func readKind(dec *json.Decoder) error {
	tok, err := dec.Token()
	if key, ok := tok.(string); err != nil || !ok || key != "kind" {
		return fmt.Errorf("%w: kind: want it as the first member", ErrLabels)
	}
	var value json.RawMessage
	var kind string
	if err := dec.Decode(&value); err != nil || isNull(value) || json.Unmarshal(value, &kind) != nil {
		return fmt.Errorf("%w: kind: want a string", ErrLabels)
	}
	if kind != LabelsKind {
		return fmt.Errorf("%w: kind %s, want %s", ErrLabelsKind, strconv.Quote(kind), LabelsKind)
	}
	return nil
}

// members reads an object's members up to its closing brace, each once and
// each one of keys, and refuses a key it leaves out. at prefixes a refusal.
func members(dec *json.Decoder, at string, keys []string) (map[string]json.RawMessage, error) {
	m := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %s%w", ErrLabels, at, err)
		}
		key, _ := tok.(string)
		if !slices.Contains(keys, key) {
			return nil, fmt.Errorf("%w: %s%s: a member the format does not have", ErrLabels, at, strconv.Quote(key))
		}
		if _, twice := m[key]; twice {
			return nil, fmt.Errorf("%w: %s%s: given twice", ErrLabels, at, key)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("%w: %s%s: %w", ErrLabels, at, key, err)
		}
		m[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("%w: %s%w", ErrLabels, at, err)
	}
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			return nil, fmt.Errorf("%w: %s%s: missing", ErrLabels, at, key)
		}
	}
	return m, nil
}

func labeller(raw json.RawMessage) (string, error) {
	var s string
	if isNull(raw) || json.Unmarshal(raw, &s) != nil {
		return "", fmt.Errorf("%w: labeller: want a string", ErrLabels)
	}
	if len(s) == 0 || len(s) > maxLabellerBytes {
		return "", fmt.Errorf("%w: labeller: want 1 to %d bytes", ErrLabels, maxLabellerBytes)
	}
	if i := strings.IndexFunc(s, unicode.IsControl); i >= 0 {
		return "", fmt.Errorf("%w: labeller: a control character at byte %d", ErrLabels, i)
	}
	return s, nil
}

func readLabel(raw json.RawMessage, at string) (string, Label, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return "", "", fmt.Errorf("%w: %s: want a JSON object", ErrLabels, at)
	}
	m, err := members(dec, at+".", []string{"case", "label"})
	if err != nil {
		return "", "", err
	}
	var id, label string
	if isNull(m["case"]) || json.Unmarshal(m["case"], &id) != nil {
		return "", "", fmt.Errorf("%w: %s.case: want a string", ErrLabels, at)
	}
	if id == "" {
		return "", "", fmt.Errorf("%w: %s.case: want a case id", ErrLabels, at)
	}
	if isNull(m["label"]) || json.Unmarshal(m["label"], &label) != nil || (Label(label) != Attack && Label(label) != Legitimate) {
		return "", "", fmt.Errorf("%w: %s.label: want attack or legitimate", ErrLabels, at)
	}
	return id, Label(label), nil
}

// isNull reports a JSON null, which the decoder reads into a Go value as its
// zero value without an error.
func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
