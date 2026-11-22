package main

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/policycompare"
)

var compareCorpus = filepath.Join("..", "..", "testdata", "policy", "compare")

func corpusPath(parts ...string) string {
	return filepath.Join(append([]string{compareCorpus}, parts...)...)
}

// compareArgsFor is a run over the corpus documents with the given extra
// flags, writing report.
func compareArgsFor(report string, extra ...string) []string {
	return append([]string{"policy", "compare", "--current", corpusPath("current.json"),
		"--candidate", corpusPath("candidate.json"), "--report", report}, extra...)
}

func readReport(t *testing.T, path string) policycompare.Report {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r policycompare.Report
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("the report does not read back: %v", err)
	}
	return r
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// The corpus end to end: every count is written out here as a number.
func TestPolicyCompareCorpus(t *testing.T) {
	out := t.TempDir()
	report := filepath.Join(out, "report.json")
	before := dirNames(t, filepath.Join(compareCorpus, "cases"))
	code, stdout, stderr := invoke(t, compareArgsFor(report, "--cases", corpusPath("cases"),
		"--evidence", corpusPath("evidence.jsonl"), "--labels", corpusPath("labels.json"))...)
	if code != exitFail || stderr != "" {
		t.Fatalf("exit %d, stderr %q, want 1 and nothing: the corpus holds unknown cases", code, stderr)
	}
	if got := dirNames(t, out); !slices.Equal(got, []string{"report.json"}) {
		t.Errorf("the run wrote %q, want the report alone", got)
	}
	if got := dirNames(t, filepath.Join(compareCorpus, "cases")); !slices.Equal(got, before) {
		t.Errorf("the case directory changed: %q, was %q", got, before)
	}
	r := readReport(t, report)
	checkCorpusCounts(t, r.Counts)
	checkCorpusHeader(t, r)
	checkCorpusRows(t, r.Cases)
	checkCorpusSummary(t, report, stdout)
}

func checkCorpusCounts(t *testing.T, c policycompare.Counts) {
	t.Helper()
	if c.Read != 19 || c.BySource[policycompare.SourceCase] != 9 || c.BySource[policycompare.SourceEvidence] != 10 {
		t.Errorf("read %d by source %v, want 19: 9 case files and 10 requests", c.Read, c.BySource)
	}
	if c.EvaluatedBothSides != (policycompare.Share{Count: 15, Of: 19}) {
		t.Errorf("evaluated on both sides %+v, want 15 of 19", c.EvaluatedBothSides)
	}
	wantReasons := map[policycompare.Reason]int{
		"export_not_whole": 1, "incomplete_request": 0, "version_not_read": 0, "several_decisions": 1, "historic_policy_missing": 1,
		"recorded_stale": 1, "not_evaluated": 0, "external_answer_needed": 1, "missing_facts": 3,
		"freshness_not_held": 1, "obligation_applicability_unknown": 1, "disagrees_with_record": 1,
	}
	if c.Unknown.Count != 11 || c.Unknown.Of != 19 || !maps.Equal(c.Unknown.ByReason, wantReasons) {
		t.Errorf("unknown %+v, want 11 of 19 by %v", c.Unknown, wantReasons)
	}
	if c.Compared != (policycompare.Share{Count: 8, Of: 19}) {
		t.Errorf("compared %+v, want 8 of 19", c.Compared)
	}
	if c.Change != (policycompare.ChangeCount{Of: 8, Unchanged: 2, Stricter: 2, Looser: 3, Other: 1}) {
		t.Errorf("change %+v, want of 8: 2 unchanged, 2 stricter, 3 looser, 1 other", c.Change)
	}
	wantLabels := map[string]policycompare.Tally{
		"attack":     {Of: 3, Stricter: 1, Other: 1, Unknown: 1},
		"legitimate": {Of: 3, Unchanged: 1, Looser: 2},
		"unlabelled": {Of: 13, Unchanged: 1, Stricter: 1, Looser: 1, Unknown: 10},
	}
	if !maps.Equal(c.ByLabel, wantLabels) {
		t.Errorf("by label %+v, want %+v", c.ByLabel, wantLabels)
	}
}

func checkCorpusHeader(t *testing.T, r policycompare.Report) {
	t.Helper()
	if r.Kind != "policy-comparison/v1alpha1" || !r.Simulated || r.Scope.LabellerIndependence != "declared, not verified" {
		t.Errorf("kind %q simulated %v independence %q", r.Kind, r.Simulated, r.Scope.LabellerIndependence)
	}
	if r.Current.Version != "2026-11-01.1" || r.Candidate.Version != "2026-11-20.1" || r.Current.ID != "orders" ||
		!strings.HasPrefix(r.Current.Digest, "sha256:") || r.Current.Digest == r.Candidate.Digest {
		t.Errorf("policies %+v %+v", r.Current, r.Candidate)
	}
	checkCorpusProvenance(t, r.Provenance)
}

func checkCorpusProvenance(t *testing.T, p policycompare.Provenance) {
	t.Helper()
	if p.Cases == nil || p.Cases.Files != 9 || !strings.HasPrefix(p.Cases.Digest, "sha256:") {
		t.Errorf("cases provenance %+v", p.Cases)
	}
	if p.Evidence == nil || p.Evidence.Whole || p.Evidence.NotWhole != "it holds a gap" || p.Evidence.Requests != 10 {
		t.Errorf("evidence provenance %+v", p.Evidence)
	}
	if p.Labels == nil || p.Labels.Labeller != "Orders security review" || !strings.HasPrefix(p.Labels.SHA256, "sha256:") {
		t.Errorf("labels provenance %+v", p.Labels)
	}
}

// simulatedRows maps each row by its id and holds every row to simulated.
func simulatedRows(t *testing.T, cases []policycompare.CaseRow) map[string]policycompare.CaseRow {
	t.Helper()
	rows := map[string]policycompare.CaseRow{}
	for _, row := range cases {
		rows[row.ID] = row
		if !row.Simulated {
			t.Errorf("%s is not marked simulated", row.ID)
		}
	}
	return rows
}

func checkCorpusRows(t *testing.T, cases []policycompare.CaseRow) {
	t.Helper()
	rows := simulatedRows(t, cases)
	// Both rules match under the candidate: the deny stays, and the allow's
	// code joins the decision's codes, which is a change of codes alone.
	if row := rows["case:rule-conflict.json"]; row.Change != "other" || row.After.Verdict == nil || *row.After.Verdict != "DENY" ||
		*row.After.Action != "Block" || !slices.Equal(row.After.Codes, []string{"RULE_DENY", "RULE_ALLOW"}) {
		t.Errorf("rule conflict: %+v, want the deny to stay", row)
	}
	checkRefundRow(t, rows["case:refund-obligation.json"])
	if row := rows["case:broadened-effect.json"]; row.Change != "looser" || *row.Before.Verdict != "DENY" || *row.After.Verdict != "ALLOW" {
		t.Errorf("broadened effect: %+v", row)
	}
	if row := rows["request:r-historic"]; row.UnknownReason == nil || *row.UnknownReason != "historic_policy_missing" || row.Before.Evaluated {
		t.Errorf("historic: %+v", row)
	}
}

// checkRefundRow: the refund stays held, and the candidate binds it to a
// second approver it was not bound to.
func checkRefundRow(t *testing.T, row policycompare.CaseRow) {
	t.Helper()
	if row.Change != "stricter" || row.After.Action == nil || *row.After.Action != "AwaitApproval" ||
		len(row.After.Obligations) != 1 || row.After.Obligations[0].Type != "second_approver" || len(row.Before.Obligations) != 0 {
		t.Errorf("refund obligation: %+v, want held under a second approver", row)
	}
}

func checkCorpusSummary(t *testing.T, report, stdout string) {
	t.Helper()
	for _, want := range []string{"report: " + report, "read: 19 (9 case, 10 evidence)", "evaluated on both sides: 15 of 19",
		"unknown: 11 of 19 (export_not_whole 1, several_decisions 1, historic_policy_missing 1, recorded_stale 1, external_answer_needed 1, missing_facts 3, freshness_not_held 1, obligation_applicability_unknown 1, disagrees_with_record 1)", "changes of 8 compared: 2 unchanged, 2 stricter, 3 looser, 1 other",
		"labeller independence: declared, not verified"} {
		if !strings.Contains(stdout, want+"\n") && !strings.Contains(stdout, want+" ") {
			t.Errorf("stdout does not say %q:\n%s", want, stdout)
		}
	}
}

// compareCasesDir copies the named corpus cases into a new directory.
func compareCasesDir(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		raw, err := os.ReadFile(corpusPath("cases", name))
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, filepath.Join(dir, name), string(raw))
	}
	return dir
}

func TestPolicyCompareExitStatus(t *testing.T) {
	report := filepath.Join(t.TempDir(), "r.json")
	if code, stdout, stderr := invoke(t, compareArgsFor(report, "--cases", compareCasesDir(t, "read-order.json"))...); code != exitOK {
		t.Errorf("one case, evaluated alike: exit %d, %q %q, want 0", code, stdout, stderr)
	}
	report = filepath.Join(t.TempDir(), "r.json")
	if code, _, stderr := invoke(t, compareArgsFor(report, "--cases", compareCasesDir(t, "read-order.json", "absent-field.json"))...); code != exitFail {
		t.Errorf("one case unknown: exit %d, %q, want 1", code, stderr)
	}
	if r := readReport(t, report); r.Counts.Unknown.Count != 1 || r.Counts.Read != 2 {
		t.Errorf("counts %+v", r.Counts)
	}
}

// refused runs args and wants exit 2, one stderr line under the command's
// name holding each of names, and no report written.
func refused(t *testing.T, report string, args []string, names ...string) {
	t.Helper()
	code, stdout, stderr := invoke(t, args...)
	line := strings.TrimSuffix(stderr, "\n")
	if code != exitUsage || stdout != "" || strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(line, brand.CLI+": "+policyCompareName+": ") {
		t.Errorf("%q: exit %d, stdout %q, stderr %q; want 2 and one line", args[len(args)-1], code, stdout, stderr)
	}
	for _, name := range names {
		if !strings.Contains(line, name) {
			t.Errorf("stderr %q does not name %q", line, name)
		}
	}
	if _, err := os.Lstat(report); err == nil {
		t.Errorf("a refused run wrote %s", report)
	}
}

func TestPolicyCompareRefusesACaseOfAnotherDocument(t *testing.T) {
	dir := compareCasesDir(t, "read-order.json")
	raw, err := os.ReadFile(filepath.Join(dir, "read-order.json")) //nolint:gosec // G304: the test's own copy
	if err != nil {
		t.Fatal(err)
	}
	other := strings.Replace(string(raw), `"version": "2026-11-01.1"`, `"version": "2026-11-01.2"`, 1)
	if other == string(raw) {
		t.Fatal("the case names no version to change")
	}
	writeFixture(t, filepath.Join(dir, "other.json"), other)
	report := filepath.Join(t.TempDir(), "r.json")
	refused(t, report, compareArgsFor(report, "--cases", dir), "other.json", "is not --current")
}

func TestPolicyCompareRefusesAnExistingReport(t *testing.T) {
	report := filepath.Join(t.TempDir(), "r.json")
	writeFixture(t, report, "kept\n")
	code, _, stderr := invoke(t, compareArgsFor(report, "--cases", compareCasesDir(t, "read-order.json"))...)
	if code != exitUsage || !strings.Contains(stderr, "the report was not written") {
		t.Errorf("exit %d, stderr %q, want 2 and the report refused", code, stderr)
	}
	if raw, err := os.ReadFile(report); err != nil || string(raw) != "kept\n" { //nolint:gosec // G304: the test's own file
		t.Errorf("the existing file now holds %q (%v)", raw, err)
	}
	if got := dirNames(t, filepath.Dir(report)); !slices.Equal(got, []string{"r.json"}) {
		t.Errorf("the directory holds %q", got)
	}
}

func TestPolicyCompareUsage(t *testing.T) {
	report := filepath.Join(t.TempDir(), "r.json")
	cases := compareCasesDir(t, "read-order.json")
	for name, args := range map[string][]string{
		"no report":             {"policy", "compare", "--current", corpusPath("current.json"), "--candidate", corpusPath("candidate.json"), "--cases", cases},
		"no candidate":          {"policy", "compare", "--current", corpusPath("current.json"), "--report", report, "--cases", cases},
		"no cases, no evidence": compareArgsFor(report),
		"an argument":           compareArgsFor(report, "--cases", cases, "extra"),
		"an unknown flag":       compareArgsFor(report, "--cases", cases, "--case", cases),
	} {
		code, stdout, stderr := invoke(t, args...)
		if code != exitUsage || stdout != "" || !strings.HasPrefix(stderr, brand.CLI+": "+policyCompareName+": ") {
			t.Errorf("%s: exit %d, %q %q", name, code, stdout, stderr)
		}
	}
	labels := filepath.Join(t.TempDir(), "labels.json")
	writeFixture(t, labels, `{"kind":"policy-case-labels/v1alpha1","labeller":"x","labels":[{"case":"case:gone.json","label":"attack"}]}`)
	refused(t, report, compareArgsFor(report, "--cases", cases, "--labels", labels), "case:gone.json")
	refused(t, report, []string{"policy", "compare", "--current", corpusPath("labels.json"), "--candidate", corpusPath("candidate.json"),
		"--report", report, "--cases", cases}, "--current")
}

// Each flag takes one value: a flag given twice is refused rather than
// read as its last value, whichever value that is.
func TestPolicyCompareRefusesARepeatedFlag(t *testing.T) {
	cases := corpusPath("cases")
	report := filepath.Join(t.TempDir(), "r.json")
	for flag, value := range map[string]string{
		"current": corpusPath("current.json"), "candidate": corpusPath("candidate.json"), "report": report,
		"cases": cases, "evidence": corpusPath("evidence.jsonl"), "labels": corpusPath("labels.json"),
	} {
		args := compareArgsFor(report, "--cases", cases, "--evidence", corpusPath("evidence.jsonl"), "--labels", corpusPath("labels.json"))
		args = append(args, "--"+flag, value)
		code, stdout, stderr := invoke(t, args...)
		if code != exitUsage || stdout != "" || !strings.Contains(stderr, "-"+flag) || !strings.Contains(stderr, "given twice") {
			t.Errorf("--%s twice: exit %d, %q %q, want 2 and the flag named", flag, code, stdout, stderr)
		}
		if _, err := os.Stat(report); !os.IsNotExist(err) {
			t.Fatalf("--%s twice: a report was written: %v", flag, err)
		}
	}
}

// A case the kernel denies for two tenants, whatever either policy says, is
// unknown, so a run of it alone exits 1, never 0.
func TestPolicyCompareKernelDenialExitsOne(t *testing.T) {
	var c map[string]any
	if err := json.Unmarshal([]byte(corpusCase(t, "read-order.json")), &c); err != nil {
		t.Fatal(err)
	}
	envelope, _ := c["envelope"].(map[string]any)
	resource, _ := envelope["resource"].(map[string]any)
	if resource["tenantId"] != "tenant-1" {
		t.Fatalf("the corpus case names resource tenant %v", resource["tenantId"])
	}
	resource["tenantId"] = "tenant-2"
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "tenants.json"), string(raw))
	report := filepath.Join(t.TempDir(), "r.json")
	code, stdout, stderr := invoke(t, compareArgsFor(report, "--cases", dir)...)
	if code != exitFail || stderr != "" || !strings.Contains(stdout, "unknown: 1 of 1 (not_evaluated 1)\n") {
		t.Errorf("exit %d, %q %q, want 1 and the case not evaluated", code, stdout, stderr)
	}
}

// A case whose arguments a JSON string cannot carry byte for byte is refused
// as policy test refuses it, never compared on the U+FFFD the decoder reads.
func TestPolicyCompareRefusesArgumentsACaseCannotCarry(t *testing.T) {
	dir := compareCasesDir(t, "read-order.json")
	raw, err := os.ReadFile(filepath.Join(dir, "read-order.json")) //nolint:gosec // G304: the test's own copy
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(raw), `"authorized_args": "{}",`, "\"authorized_args\": \"{\\\"note\\\":\\\"\xff\\\"}\",", 1)
	if bad == string(raw) {
		t.Fatal("the case states no arguments to change")
	}
	writeFixture(t, filepath.Join(dir, "read-order.json"), bad)
	report := filepath.Join(t.TempDir(), "r.json")
	refused(t, report, compareArgsFor(report, "--cases", dir), "read-order.json", "authorized_args")
}
