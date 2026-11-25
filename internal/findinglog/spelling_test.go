package findinglog

import (
	"strings"
	"testing"

	findingv1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/finding/v1alpha1"
)

// TestAMemberTheWriterLeavesOutIsRefusedSpelledAtItsDefault: the writer
// never spells a member at its default, so a member present at it is no
// line the writer wrote, and a member of "0.2" given at its default would
// read as a "0.1" record that carries it. The same lines without the member
// read.
func TestAMemberTheWriterLeavesOutIsRefusedSpelledAtItsDefault(t *testing.T) {
	for name, good := range map[string]string{"a finding": finding01, "a report": report01} {
		if _, err := unmarshalLine([]byte(good)); err != nil {
			t.Fatalf("%s as written: %v", name, err)
		}
	}
	for name, bad := range map[string]string{
		"references left out at zero": strings.Replace(finding01, `"finding":{`, `"refsLeftOut":"0","finding":{`, 1),
		"an empty list of sources":    strings.Replace(report01, `"findingsWritten":"1"`, `"findingsWritten":"1","sourcesInDoubt":[]`, 1),
		"an empty run tree":           strings.Replace(report01, `"findingsWritten":"1"`, `"findingsWritten":"1","runTree":[]`, 1),
		"no children mode, spelled":   strings.Replace(report01, `"findingsWritten":"1"`, `"findingsWritten":"1","children":"CHILDREN_MODE_UNSPECIFIED"`, 1),
		"an event's run, empty":       strings.Replace(finding01, `"requestId":"req-1"`, `"requestId":"req-1","runId":""`, 1),
		"an empty map":                strings.Replace(report01, `"eventsTaken":"4"`, `"eventsTaken":"4","observationsLeftOut":{}`, 1),
		"a count of zero":             strings.Replace(report01, `"eventsTaken":"4"`, `"eventsTaken":"4","observationsTaken":"0"`, 1),
		"a count of zero as a number": strings.Replace(report01, `"eventsTaken":"4"`, `"eventsTaken":"4","observationsTaken":0`, 1),
		"an empty string":             strings.Replace(finding01, `"ruleVersion":"1"`, `"ruleVersion":"1","requestId":""`, 1),
		"a rule's empty reason":       strings.Replace(report01, `"state":"RULE_STATE_CHECKED"`, `"state":"RULE_STATE_CHECKED","why":""`, 1),
	} {
		if bad == finding01 || bad == report01 {
			t.Fatalf("%s: the change did not apply", name)
		}
		if got, err := unmarshalLine([]byte(bad)); err == nil || got != nil {
			t.Errorf("%s: unmarshalLine = %v, %v; want a refusal", name, got, err)
		}
	}
}

// TestAConfirmedFindingRestsOnPlaneEventsAlone: an observation suggests at
// most, so a finding citing one is never confirmed, whatever else it cites;
// the same finding suggested reads.
func TestAConfirmedFindingRestsOnPlaneEventsAlone(t *testing.T) {
	const obs = `{"observation":{"sourceId":"s1","observationId":"obs-0123456789abcdef0123456789abcdef"}}`
	alone := strings.Replace(finding01, `{"event":{"eventId":"evt-1","requestId":"req-1"}}`, obs, 1)
	beside := strings.Replace(finding01, `{"event":{"eventId":"evt-1","requestId":"req-1"}}`,
		`{"event":{"eventId":"evt-1","requestId":"req-1"}},`+obs, 1)
	for name, l := range map[string]string{"an observation alone": alone, "an observation beside an event": beside} {
		if l == finding01 {
			t.Fatalf("%s: the change did not apply", name)
		}
		if got, err := unmarshalLine([]byte(l)); err == nil || got != nil || !strings.HasPrefix(err.Error(), "finding.verdict:") {
			t.Errorf("%s, confirmed: unmarshalLine = %v, %v; want a refusal naming finding.verdict", name, got, err)
		}
		suggested := strings.Replace(l, "FINDING_VERDICT_CONFIRMED", "FINDING_VERDICT_SUSPECTED", 1)
		if _, err := unmarshalLine([]byte(suggested)); err != nil {
			t.Errorf("%s, suspected: %v", name, err)
		}
	}
	f := finding(idA, confirmed, "STEP_OUTSIDE_PROCEDURE")
	f.Refs = append(f.Refs, &findingv1alpha1.Reference{Ref: &findingv1alpha1.Reference_Observation{
		Observation: &findingv1alpha1.ObservationRef{SourceId: "s1", ObservationId: "obs-0123456789abcdef0123456789abcdef"}}})
	if _, err := marshalLine(findingRecord(f)); err == nil || !strings.HasPrefix(err.Error(), "finding.verdict:") {
		t.Errorf("the writer took a confirmed finding citing an observation: %v", err)
	}
}
