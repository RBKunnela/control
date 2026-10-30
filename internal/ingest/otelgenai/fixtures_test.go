package otelgenai_test

import (
	"strings"
	"testing"

	observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"
	"github.com/guardana/control/internal/observe"
)

func TestZeroIDsAreRefused(t *testing.T) {
	b := importFile(t, "zero_ids.jsonl")
	wantCounts(t, b, &observev1.ImportCounts{Read: 5, Observed: 1, Refused: 4})
	if got := b.Observations[0].GetCorrelation().GetSpanId(); got != spanID(5) {
		t.Errorf("observed span %s, want %s", got, spanID(5))
	}
}

func TestUppercaseIDsAreRefused(t *testing.T) {
	wantCounts(t, importFile(t, "uppercase_ids.jsonl"), &observev1.ImportCounts{Read: 3, Refused: 3})
}

// Lines 1 to 4 repeat an attribute key, a resource attribute, a span member
// and a key inside a key-value list; each refuses every span on its line.
func TestDuplicatesRefuseTheLine(t *testing.T) {
	b := importFile(t, "duplicate_attributes.jsonl")
	wantCounts(t, b, &observev1.ImportCounts{Read: 6, Observed: 1, Refused: 5})
	if got := b.Observations[0].GetCorrelation().GetSpanId(); got != spanID(7) {
		t.Errorf("observed span %s, want %s", got, spanID(7))
	}
}

func TestUnknownMemberRefusesTheLine(t *testing.T) {
	wantCounts(t, importFile(t, "unknown_member.jsonl"), &observev1.ImportCounts{Read: 6, Refused: 6})
}

func TestUnsetStatus(t *testing.T) {
	b := importFile(t, "unset_status.jsonl")
	wantCounts(t, b, &observev1.ImportCounts{Read: 4, Observed: 3, Refused: 1})
	want := map[int]observev1.Status{1: observev1.Status_STATUS_UNSET, 2: observev1.Status_STATUS_UNSET, 3: observev1.Status_STATUS_OK}
	for span, status := range want {
		o := byID(t, b, span)
		if o.GetOutcome().GetStatus() != status || o.GetStage() != observev1.Stage_STAGE_COMPLETED {
			t.Errorf("span %d: %v %v, want %v completed", span, o.GetOutcome().GetStatus(), o.GetStage(), status)
		}
	}
}

func TestReasoningAndThinkingPartsAreCountedNotKept(t *testing.T) {
	b := importFile(t, "reasoning.jsonl")
	wantCounts(t, b, &observev1.ImportCounts{Read: 1, Observed: 1, ContentAttributesDropped: 3, ReasoningPartsDropped: 3})
	if got := b.Observations[0].GetContentAttributesDropped(); got != 3 {
		t.Errorf("observation dropped %d content attributes, want 3", got)
	}
	if lines := checkBatch(t, b); strings.Contains(lines, "SECRET") {
		t.Fatalf("content reached a record:\n%s", lines)
	}
}

func TestOversizedAndUnprintableStringsAreDropped(t *testing.T) {
	b := importFile(t, "oversized_tool_name.jsonl")
	wantCounts(t, b, &observev1.ImportCounts{Read: 5, Observed: 5, StringsDropped: 5})
	if got := byID(t, b, 1).GetSubject().GetName(); got != strings.Repeat("t", 256) {
		t.Errorf("a 256-byte name became %q", got)
	}
	for span := 2; span <= 4; span++ {
		if got := byID(t, b, span).GetSubject().GetName(); got != "" {
			t.Errorf("span %d kept name %q", span, got)
		}
	}
	s := byID(t, b, 5).GetSubject()
	if s.GetName() != "ok" || s.GetProvider() != "" || s.GetServerAddress() != "" {
		t.Errorf("span 5 subject %v, want name ok and nothing else", s)
	}
}

func TestStatusMessageAndSpanNameAreNeverCopied(t *testing.T) {
	b := importFile(t, "status_message.jsonl")
	wantCounts(t, b, &observev1.ImportCounts{Read: 1, Observed: 1})
	o := b.Observations[0]
	if o.GetStage() != observev1.Stage_STAGE_FAILED || o.GetOutcome().GetStatus() != observev1.Status_STATUS_ERROR {
		t.Errorf("stage %v status %v, want failed and error", o.GetStage(), o.GetOutcome().GetStatus())
	}
	if lines := checkBatch(t, b); strings.Contains(lines, "SECRET") {
		t.Fatalf("a status message or span name reached a record:\n%s", lines)
	}
}

func TestOldAndFutureTimesAreKeptAsRead(t *testing.T) {
	b := importFile(t, "old_and_future.jsonl")
	wantCounts(t, b, &observev1.ImportCounts{Read: 2, Observed: 2})
	old, future := ts(t, "2001-09-09T01:46:40Z"), ts(t, "2300-01-01T00:00:00Z")
	equal(t, byID(t, b, 1).GetEventTime(), future)
	equal(t, byID(t, b, 2).GetEventTime(), old)
	equal(t, byID(t, b, 1).GetReceivedTime(), ts(t, "2026-10-04T10:05:00Z"))
	equal(t, b.Report.GetEarliestEventTime(), old)
	equal(t, b.Report.GetLatestEventTime(), future)
}

func TestNoEndTimeIsUnknown(t *testing.T) {
	b := importFile(t, "no_end_time.jsonl")
	wantCounts(t, b, &observev1.ImportCounts{Read: 3, Observed: 3})
	want := map[int]observev1.Stage{1: observev1.Stage_STAGE_UNSPECIFIED, 2: observev1.Stage_STAGE_UNSPECIFIED, 3: observev1.Stage_STAGE_FAILED}
	for span, stage := range want {
		o := byID(t, b, span)
		if o.GetStage() != stage || o.GetEventTime() != nil {
			t.Errorf("span %d: stage %v event time %v, want %v and none", span, o.GetStage(), o.GetEventTime(), stage)
		}
	}
	if b.Report.GetEarliestEventTime() != nil || b.Report.GetLatestEventTime() != nil {
		t.Errorf("report times %v %v, want none", b.Report.GetEarliestEventTime(), b.Report.GetLatestEventTime())
	}
}

func TestMalformedRunIDIsDropped(t *testing.T) {
	b := importFile(t, "malformed_run_id.jsonl")
	wantCounts(t, b, &observev1.ImportCounts{Read: 6, Observed: 6, RunIdsDropped: 4})
	for span := 1; span <= 6; span++ {
		c := byID(t, b, span).GetCorrelation()
		wantBasis, wantRun := observev1.Basis_BASIS_NONE, ""
		if span == 1 {
			wantBasis, wantRun = observev1.Basis_BASIS_CLAIMED, runA
		}
		if c.GetBasis() != wantBasis || c.GetRunId() != wantRun {
			t.Errorf("span %d: %v %q, want %v %q", span, c.GetBasis(), c.GetRunId(), wantBasis, wantRun)
		}
	}
}

func TestNoRunAttributeClaimsNothing(t *testing.T) {
	d := descriptor(t)
	d.RunAttribute = ""
	b := importBytes(t, readTestdata(t, "malformed_run_id.jsonl"), d)
	wantCounts(t, b, &observev1.ImportCounts{Read: 6, Observed: 6})
	for _, o := range b.Observations {
		if c := o.GetCorrelation(); c.GetBasis() != observev1.Basis_BASIS_NONE || c.GetRunId() != "" {
			t.Errorf("%s: %v %q, want none", c.GetSpanId(), c.GetBasis(), c.GetRunId())
		}
	}
	emptyKey := oneSpan("", `,{"key":"","value":{"stringValue":"x"}}`)
	wantCounts(t, importBytes(t, []byte(emptyKey+"\n"), d), &observev1.ImportCounts{Read: 1, Observed: 1})
}

// A run attribute in the gen_ai namespace is the run's, not dropped content.
func TestRunAttributeInGenAINamespace(t *testing.T) {
	d := descriptor(t)
	d.RunAttribute = "gen_ai.conversation.id"
	line := oneSpan("", `,{"key":"gen_ai.conversation.id","value":{"stringValue":"`+runA+`"}}`)
	b := importBytes(t, []byte(line+"\n"), d)
	wantCounts(t, b, &observev1.ImportCounts{Read: 1, Observed: 1})
	if c := b.Observations[0].GetCorrelation(); c.GetBasis() != observev1.Basis_BASIS_CLAIMED || c.GetRunId() != runA {
		t.Errorf("correlation %v, want claimed %s", c, runA)
	}
}

func TestUnparsableContentIsCountedNotZero(t *testing.T) {
	b := importFile(t, "content_unparsable.jsonl")
	wantCounts(t, b, &observev1.ImportCounts{Read: 8, Observed: 8, ContentAttributesDropped: 8, ContentUnparsed: 7})
}

// No descriptor member turns capture on: the reader refuses one, and every
// content attribute a span carries is dropped and counted.
func TestEveryContentAttributeIsDropped(t *testing.T) {
	b := importFile(t, "content_dropped.jsonl")
	wantCounts(t, b, &observev1.ImportCounts{Read: 1, Observed: 1, ContentAttributesDropped: 10})
	if got := b.Observations[0].GetContentAttributesDropped(); got != 10 {
		t.Errorf("observation dropped %d content attributes, want 10", got)
	}
	if lines := checkBatch(t, b); strings.Contains(lines, "CONTENT-MARKER") {
		t.Fatalf("content reached a record:\n%s", lines)
	}
	withCapture := strings.Replace(string(readTestdata(t, "descriptor.json")), `"run_attribute"`, `"capture": {"content": true}, "run_attribute"`, 1)
	if _, err := observe.ReadNeutral([]byte(withCapture)); err == nil {
		t.Fatal("a descriptor asking for capture was read")
	}
}
