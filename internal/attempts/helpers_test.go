package attempts

import (
	"strings"
	"testing"
)

// validManifest is a manifest every refusal test changes in one place.
const validManifest = `{
  "kind": "attempt-manifest/v1alpha1",
  "about": "a refund attempt beside a read",
  "selection": "the one attack the fixture has",
  "repetitions": 2,
  "model": "no model",
  "demo": "../demo.yaml",
  "policy": "../policy.json",
  "planes": [
    {"id": "enforce", "mode": "ENFORCE", "decision_point": "silent", "role": "measured"},
    {"id": "observe", "mode": "OBSERVE", "decision_point": "none", "role": "positive"}
  ],
  "attempts": [
    {"id": "deny", "scenario": "../scenarios/deny.json", "steps": [
      {"step": 0, "label": "attack", "effects": ["refund"]},
      {"step": 1, "label": "legitimate"}
    ]}
  ],
  "effects": [
    {"id": "refund", "server": "orders", "call": "refund", "args": [{"member": "/id", "equals": "ord-1"}]}
  ],
  "thresholds": {"attack_observed_max": 0, "legitimate_completed_min": 0.75}
}`

// replaced is validManifest with the one occurrence of old replaced by
// with; a test whose old text is not there fails rather than passing on the
// unchanged document.
func replaced(t *testing.T, old, with string) []byte {
	t.Helper()
	if n := strings.Count(validManifest, old); n != 1 {
		t.Fatalf("%q occurs %d times in the fixture, want 1", old, n)
	}
	return []byte(strings.Replace(validManifest, old, with, 1))
}

func mustRead(t *testing.T, raw []byte) *Manifest {
	t.Helper()
	m, err := ReadManifest(raw)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	return m
}

func mustValue(t *testing.T, raw string) *Value {
	t.Helper()
	v, err := ParseValue([]byte(raw))
	if err != nil {
		t.Fatalf("ParseValue(%s): %v", raw, err)
	}
	return v
}
