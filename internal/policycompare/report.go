package policycompare

import (
	"bytes"
	"encoding/json"
)

// ReportKind is the kind of report this build writes.
const ReportKind = "policy-comparison/v1alpha1"

// Report is one comparison, as the report file holds it.
type Report struct {
	Kind       string     `json:"kind"`
	Simulated  bool       `json:"simulated"`
	Build      string     `json:"build"`
	Current    PolicyRef  `json:"current"`
	Candidate  PolicyRef  `json:"candidate"`
	Provenance Provenance `json:"provenance"`
	Scope      Scope      `json:"scope"`
	Counts     Counts     `json:"counts"`
	Cases      []CaseRow  `json:"cases"`
}

// PolicyRef names one of the two policies.
type PolicyRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// Provenance is where the cases came from; a member is null when its input
// was not given.
type Provenance struct {
	Cases    *CasesSource    `json:"cases"`
	Evidence *EvidenceSource `json:"evidence"`
	Labels   *LabelsSource   `json:"labels"`
}

// CasesSource is the case directory: its path as given, how many files it
// held and a digest over their names and contents.
type CasesSource struct {
	Dir    string `json:"dir"`
	Files  int    `json:"files"`
	Digest string `json:"digest"`
}

// EvidenceSource is the export: its path as given, the SHA-256 of its bytes,
// whether it held every line of its trail and why not, and how many requests
// it named.
type EvidenceSource struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Whole    bool   `json:"whole"`
	NotWhole string `json:"not_whole"`
	Requests int    `json:"requests"`
}

// LabelsSource is the labels file and the labeller it names.
type LabelsSource struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Labeller string `json:"labeller"`
}

// Scope is what the comparison cannot see.
type Scope struct {
	Evaluation           string   `json:"evaluation"`
	NotSeen              []string `json:"not_seen"`
	LabellerIndependence string   `json:"labeller_independence"`
}

// CaseRow is one case's result. Change is unknown exactly when
// UnknownReason is set, and then neither side carries a verdict.
type CaseRow struct {
	ID            string  `json:"id"`
	Source        Source  `json:"source"`
	Simulated     bool    `json:"simulated"`
	Label         *Label  `json:"label"`
	Before        SideRow `json:"before"`
	After         SideRow `json:"after"`
	Change        Change  `json:"change"`
	UnknownReason *Reason `json:"unknown_reason"`
	UnknownDetail *string `json:"unknown_detail"`
}

// SideRow is one policy's decision of a case. Verdict, action, codes and
// obligations are null on a case that is unknown.
type SideRow struct {
	Evaluated    bool            `json:"evaluated"`
	Verdict      *string         `json:"verdict"`
	Action       *string         `json:"action"`
	Codes        []string        `json:"codes"`
	Obligations  []ObligationRow `json:"obligations"`
	MissingFacts []string        `json:"missing_facts"`
}

// ObligationRow is one obligation of a decision.
type ObligationRow struct {
	Type     string            `json:"type"`
	Params   map[string]string `json:"params"`
	Advisory bool              `json:"advisory"`
}

// Counts are the report's counts, each beside the count it is out of.
type Counts struct {
	Read               int              `json:"read"`
	BySource           map[Source]int   `json:"by_source"`
	EvaluatedBothSides Share            `json:"evaluated_both_sides"`
	Unknown            UnknownCount     `json:"unknown"`
	Compared           Share            `json:"compared"`
	Change             ChangeCount      `json:"change"`
	ByLabel            map[string]Tally `json:"by_label"`
}

// Share is a count out of a denominator.
type Share struct {
	Count int `json:"count"`
	Of    int `json:"of"`
}

// UnknownCount is the unknown cases out of those read, by reason.
type UnknownCount struct {
	Count    int            `json:"count"`
	Of       int            `json:"of"`
	ByReason map[Reason]int `json:"by_reason"`
}

// ChangeCount is the cases compared on both sides, by change.
type ChangeCount struct {
	Of        int `json:"of"`
	Unchanged int `json:"unchanged"`
	Stricter  int `json:"stricter"`
	Looser    int `json:"looser"`
	Other     int `json:"other"`
}

// Tally is the cases of one label, by change, unknown included.
type Tally struct {
	Of        int `json:"of"`
	Unchanged int `json:"unchanged"`
	Stricter  int `json:"stricter"`
	Looser    int `json:"looser"`
	Other     int `json:"other"`
	Unknown   int `json:"unknown"`
}

// Complete reports whether every case was evaluated on both sides and none
// is unknown.
func (r *Report) Complete() bool {
	return r.Counts.Read > 0 && r.Counts.Unknown.Count == 0 && r.Counts.EvaluatedBothSides.Count == r.Counts.Read
}

// Marshal is the report's bytes: indented JSON and a final newline, with no
// HTML escaping, so a case id reads as it was written.
func (r *Report) Marshal() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
