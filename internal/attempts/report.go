package attempts

import (
	"encoding/json"
	"fmt"
	"os"
)

// ReportKind is the kind of report this build writes.
const ReportKind = "attempt-report/v1alpha1"

// The exits of a run: complete with every threshold met and nothing unknown
// or absent and not sent; complete otherwise; and a run that could not
// complete.
const (
	ExitMet        = 0
	ExitNotMet     = 1
	ExitIncomplete = 2
)

// Exit is the status a run ends with.
func Exit(complete bool, c Counts) int {
	switch {
	case !complete:
		return ExitIncomplete
	case c.ThresholdsMet && c.Unknown == 0 && c.AbsentNotSent == 0:
		return ExitMet
	}
	return ExitNotMet
}

// Report is a report file being written: created by this run alone, each
// line synced before the next is written, so a file cut short keeps every
// line before the cut and lacks its summary.
type Report struct {
	f *os.File
}

// CreateReport creates the report at path, which must not exist, owner-only.
func CreateReport(path string) (*Report, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator names the report, and an existing file is refused
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReport, err)
	}
	return &Report{f: f}, nil
}

// Write writes v as one line and syncs it.
func (r *Report) Write(v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrReport, err)
	}
	if _, err := r.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("%w: %w", ErrReport, err)
	}
	if err := r.f.Sync(); err != nil {
		return fmt.Errorf("%w: %w", ErrReport, err)
	}
	return nil
}

// Close closes the file.
func (r *Report) Close() error { return r.f.Close() }

// FileDigest is one file and the sha256 of its bytes, in lower-case hex.
type FileDigest struct {
	Role   string `json:"role,omitempty"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Build is what the running binary says of its own build.
type Build struct {
	Commit          string `json:"commit"`
	Modified        *bool  `json:"modified"`
	BelongsToCommit bool   `json:"belongs_to_commit"`
	Go              string `json:"go"`
}

// PlaneLine is one plane configuration as the header records it.
type PlaneLine struct {
	ID            string `json:"id"`
	Mode          string `json:"mode"`
	DecisionPoint string `json:"decision_point"`
	Role          Role   `json:"role"`
}

// Header is the report's first line.
type Header struct {
	Kind        string       `json:"kind"`
	Line        string       `json:"line"`
	Started     string       `json:"started"`
	Platform    string       `json:"platform"`
	Build       Build        `json:"build"`
	Manifest    FileDigest   `json:"manifest"`
	Corpus      string       `json:"corpus_sha256"`
	Files       []FileDigest `json:"corpus"`
	Binaries    []FileDigest `json:"binaries"`
	About       string       `json:"about"`
	Selection   string       `json:"selection"`
	Model       string       `json:"model"`
	Repetitions int          `json:"repetitions"`
	Planes      []PlaneLine  `json:"planes"`
	State       string       `json:"state"`
}

// NewHeader is the header of a report on m.
func NewHeader(m *Manifest) Header {
	h := Header{Kind: ReportKind, Line: "header", About: m.About, Selection: m.Selection, Model: m.Model, Repetitions: m.Repetitions}
	for _, p := range m.Planes {
		h.Planes = append(h.Planes, PlaneLine(p))
	}
	return h
}

// AnswerLine is the answer a call got.
type AnswerLine struct {
	Kind  string   `json:"kind"`
	Codes []string `json:"codes"`
}

// StepLine is one step of an attempt-run as the report records it.
type StepLine struct {
	Step          int         `json:"step"`
	Label         Label       `json:"label"`
	Kind          string      `json:"kind"`
	Tool          string      `json:"tool,omitempty"`
	Sent          *bool       `json:"sent,omitempty"`
	NotSent       string      `json:"not_sent,omitempty"`
	Answer        *AnswerLine `json:"answer,omitempty"`
	AnswerUnknown string      `json:"answer_unknown,omitempty"`
	Agreement     string      `json:"agreement,omitempty"`
	Outcome       string      `json:"outcome,omitempty"`
	Why           string      `json:"why,omitempty"`
	Ran           *bool       `json:"ran,omitempty"`
	NotRun        string      `json:"not_run,omitempty"`
}

// EffectLine is one effect's outcome at the victim in one attempt-run.
type EffectLine struct {
	Effect  string `json:"effect"`
	Outcome string `json:"at_victim"`
	Why     string `json:"why,omitempty"`
}

// AttemptLine is one attempt-run.
type AttemptLine struct {
	Line         string       `json:"line"`
	Attempt      string       `json:"attempt"`
	Scenario     string       `json:"scenario"`
	Plane        string       `json:"plane"`
	Repetition   int          `json:"repetition"`
	Started      bool         `json:"started"`
	NotRun       string       `json:"not_run,omitempty"`
	PolicyDigest string       `json:"policy_digest,omitempty"`
	Unfinished   string       `json:"unfinished,omitempty"`
	Steps        []StepLine   `json:"steps"`
	Effects      []EffectLine `json:"effects"`
}

// LineOf is the report's line of one judged run.
func LineOf(scenarioPath string, res *RunResult) AttemptLine {
	r := res.Run
	l := AttemptLine{Line: "attempt", Attempt: r.Attempt, Scenario: scenarioPath, Plane: r.Plane, Repetition: r.Repetition,
		Started: r.Started, NotRun: r.NotRun, PolicyDigest: r.PolicyDigest, Unfinished: r.Unfinished, Steps: []StepLine{}, Effects: []EffectLine{}}
	for i, s := range r.Steps {
		sr := res.Steps[i]
		sl := StepLine{Step: s.Step, Label: s.Label, Kind: s.Kind, Tool: s.Tool, Agreement: sr.Agreement, Outcome: sr.Outcome, Why: sr.Why}
		if s.Kind == "call" {
			sent := s.Sent
			sl.Sent, sl.NotSent, sl.AnswerUnknown = &sent, s.NotSent, s.AnswerUnknown
			if s.Answer != "" {
				sl.Answer = &AnswerLine{Kind: s.Answer, Codes: append([]string{}, s.Codes...)}
			}
		} else {
			ran := s.Ran
			sl.Ran, sl.NotRun = &ran, s.NotRun
		}
		l.Steps = append(l.Steps, sl)
	}
	for _, er := range res.Effects {
		l.Effects = append(l.Effects, EffectLine{Effect: er.Effect, Outcome: er.Outcome, Why: er.Why})
	}
	return l
}

// Runs counts the attempt-runs a manifest selects and how many started.
type Runs struct {
	Attempts int `json:"attempts"`
	Selected int `json:"selected"`
	Started  int `json:"started"`
	NotRun   int `json:"not_run"`
}

// Window is the time the run took, from its first line to its last.
type Window struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Scope is what the result covers and what it does not.
type Scope struct {
	ToolsDeclared  []string `json:"tools_declared"`
	ToolsExercised []string `json:"tools_exercised"`
	Planes         []string `json:"planes"`
	Sources        []string `json:"sources"`
	Unobserved     []string `json:"unobserved_channels"`
	Window         Window   `json:"time_window"`
	Missing        []string `json:"missing_inputs"`
	DevWiring      []string `json:"dev_wiring"`
	NotMeasured    []string `json:"not_measured"`
	Model          string   `json:"model"`
	BrokenCopies   string   `json:"broken_copies_of_the_code"`
}

// Summary is the report's last line; a file without it is incomplete.
type Summary struct {
	Line            string       `json:"line"`
	Complete        bool         `json:"complete"`
	Incomplete      []string     `json:"incomplete"`
	Exit            int          `json:"exit"`
	BelongsToCommit bool         `json:"belongs_to_commit"`
	Runs            Runs         `json:"runs"`
	PolicyDigests   []string     `json:"policy_digests"`
	BinariesAfter   []FileDigest `json:"binaries_after"`
	Counts
	Scope Scope `json:"scope"`
}

// The scope's fixed parts: what the dev wiring is, and what this kind of
// run cannot measure.
var (
	Sources    = []string{"the victim journal"}
	Unobserved = []string{
		"anything a victim did besides receiving a tool call",
		"calls to a server the demo does not declare",
		"resources and prompts",
		"the plane's own trail, which no count reads",
	}
	DevWiring = []string{
		"keys made in process",
		"bundle signed at start",
		"collector in process",
		"dev owns approvals, trust, operators and runs",
		"the approver is dev's key",
		"no run tokens",
		"no taint across runs",
	}
	NotMeasured = []string{
		"pause and stops: no positive control, since OBSERVE does not run what they stop",
		"broken copies of the plane's code: not run",
	}
)
