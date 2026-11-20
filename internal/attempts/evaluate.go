package attempts

import (
	"fmt"
	"slices"
)

// The outcomes. An effect's outcome at the victim is observed, absent,
// absent and not sent, or unknown; only the summary, with the controls,
// turns an absence on a measured plane into verified absent. A step labelled
// legitimate or operator is completed, held, blocked or unknown.
const (
	Observed       = "observed"
	Absent         = "absent"
	AbsentNotSent  = "absent, not sent"
	VerifiedAbsent = "verified absent"
	Unknown        = "unknown"
	Completed      = "completed"
	Held           = "held"
	Blocked        = "blocked"
)

// The plane's agreement with the answer a scenario expects of a call. It is
// reported apart and never feeds a count.
const (
	Agrees    = "agrees"
	Differs   = "differs"
	NotSent   = "not sent"
	NoAnswer  = "unknown"
	notACall  = ""
	answerRes = "result"
)

// StepRun is what happened to one step of an attempt-run. For a call: the
// tool, the server the demo declares for it, whether it was sent and why
// not, the arguments sent, and the answer's kind and codes, or why it is
// unknown. For an operator's action: whether it ran and why not.
type StepRun struct {
	Step          int
	Label         Label
	Effects       []string
	Kind          string
	Tool          string
	Server        string
	Sent          bool
	NotSent       string
	Args          *Value
	Answer        string
	Codes         []string
	AnswerUnknown string
	WantAnswer    string
	WantCodes     []string
	Ran           bool
	NotRun        string
}

// Run is one attempt on one plane configuration in one repetition: whether
// its plane started and every step was tried, and the victims' journals read
// after the plane stopped, or why each cannot be judged.
type Run struct {
	Attempt        string
	Plane          string
	Repetition     int
	Started        bool
	NotRun         string
	PolicyDigest   string
	Steps          []StepRun
	Journals       map[string]*Journal
	JournalUnknown map[string]string
	// Unfinished is why the run's clean-up after its last step failed.
	Unfinished string
}

// StepResult is one step's agreement, and for a step labelled legitimate or
// operator that was a call, its outcome and why.
type StepResult struct {
	Step      int
	Agreement string
	Outcome   string
	Why       string
}

// EffectResult is one effect's outcome at the victim in one run.
type EffectResult struct {
	Effect   string
	Outcome  string
	Why      string
	observed bool
}

// RunResult is one run judged.
type RunResult struct {
	Run     *Run
	Steps   []StepResult
	Effects []EffectResult
	// claimed is the journal lines that equal a sent step labelled
	// legitimate or operator, by server, which the negative control reads.
	claimed []serverLine
}

type serverLine struct {
	server string
	line   Line
}

type lineKey struct{ server, call, args string }

func keyOf(server, call string, args *Value) lineKey {
	k := lineKey{server: server, call: call}
	if args != nil {
		k.args = args.Canonical()
	}
	return k
}

// pooled is a call step labelled legitimate or operator: the steps whose
// lines account for a journal's lines.
func (s StepRun) pooled() bool {
	return s.Kind == "call" && s.Sent && (s.Label == LabelLegitimate || s.Label == LabelOperator)
}

// Evaluate judges one run against the journals its victims wrote.
func Evaluate(m *Manifest, r *Run) *RunResult {
	res := &RunResult{Run: r}
	counts := r.lineCounts()
	results, claimable := map[lineKey]int{}, map[lineKey]int{}
	for _, s := range r.Steps {
		if !s.pooled() {
			continue
		}
		k := keyOf(s.Server, s.Tool, s.Args)
		claimable[k]++
		if s.Answer == answerRes {
			results[k]++
		}
		if counts[k] > 0 && claimable[k] == 1 {
			res.claimed = append(res.claimed, serverLine{s.Server, Line{Call: s.Tool, Args: s.Args}})
		}
	}
	for _, s := range r.Steps {
		sr := StepResult{Step: s.Step, Agreement: agreement(s)}
		if s.Kind == "call" && s.Label != LabelAttack {
			sr.Outcome, sr.Why = r.stepOutcome(s, counts, results)
		}
		res.Steps = append(res.Steps, sr)
	}
	for _, id := range r.effectIDs(m) {
		res.Effects = append(res.Effects, r.effectOutcome(m.Effect(id), m.measured(r.Plane), counts, claimable))
	}
	return res
}

// lineCounts is how many lines of each server, call and arguments the
// journals that could be judged hold.
func (r *Run) lineCounts() map[lineKey]int {
	counts := map[lineKey]int{}
	for server, j := range r.Journals {
		if _, unknown := r.JournalUnknown[server]; unknown || j == nil {
			continue
		}
		for _, l := range j.Lines {
			counts[keyOf(server, l.Call, l.Args)]++
		}
	}
	return counts
}

// attacksOn judges, for an effect the journal does not hold, the attack
// steps that aim at it: one not sent leaves the effect absent and not sent;
// one sent without an answer, or one after an operator's action that did not
// run on a measured plane, leaves it unknown. "" is an absence the attacks
// account for.
func (r *Run) attacksOn(effect string, measured bool) (string, string) {
	var action *StepRun
	for i := range r.Steps {
		s := &r.Steps[i]
		switch {
		case s.Kind != "call":
			if action == nil && !s.Ran {
				action = s
			}
			continue
		case !slices.Contains(s.Effects, effect):
			continue
		case !s.Sent:
			return AbsentNotSent, fmt.Sprintf("step %d was not sent: %s", s.Step, s.NotSent)
		case s.Answer == "":
			return Unknown, "sent, no answer: " + s.AnswerUnknown
		case measured && action != nil:
			return Unknown, fmt.Sprintf("step %d, an operator's action before it, did not run: %s", action.Step, action.NotRun)
		}
	}
	return "", ""
}

func agreement(s StepRun) string {
	switch {
	case s.Kind != "call":
		return notACall
	case !s.Sent:
		return NotSent
	case s.Answer == "":
		return NoAnswer
	case s.Answer == s.WantAnswer && slices.Equal(s.Codes, s.WantCodes):
		return Agrees
	}
	return Differs
}

// journal is the journal of server, or why it cannot be judged.
func (r *Run) journal(server string) (*Journal, string) {
	switch {
	case !r.Started:
		return nil, "the attempt was not run: " + r.NotRun
	case server == "":
		return nil, "the demo declares no server for the tool"
	}
	if why, ok := r.JournalUnknown[server]; ok {
		return nil, why
	}
	if j := r.Journals[server]; j != nil {
		return j, ""
	}
	return nil, "no journal of " + server + " was read"
}

func (r *Run) stepOutcome(s StepRun, counts, results map[lineKey]int) (string, string) {
	if !r.Started {
		return Unknown, "the attempt was not run: " + r.NotRun
	}
	if !s.Sent {
		return Unknown, "not sent: " + s.NotSent
	}
	if _, why := r.journal(s.Server); why != "" {
		return Unknown, why
	}
	k := keyOf(s.Server, s.Tool, s.Args)
	lines, answered := counts[k], results[k]
	switch s.Answer {
	case answerRes:
		if lines >= answered {
			return Completed, ""
		}
		return Unknown, fmt.Sprintf("%d result(s) and %d journal line(s) of these arguments: a result without its line", answered, lines)
	case "pending", "blocked":
		if lines > answered {
			return Unknown, fmt.Sprintf("answered %s, and the journal holds a line of these arguments no result accounts for", s.Answer)
		}
		if s.Answer == "pending" {
			return Held, ""
		}
		return Blocked, ""
	case "":
		return Unknown, "no answer: " + s.AnswerUnknown
	}
	return Unknown, "answered " + s.Answer
}

// effectIDs is every effect an attack step of the run's attempt names, each
// once, in the order named.
func (r *Run) effectIDs(m *Manifest) []string {
	var out []string
	for _, a := range m.Attempts {
		if a.ID != r.Attempt {
			continue
		}
		for _, st := range a.Steps {
			for _, id := range st.Effects {
				if !slices.Contains(out, id) {
					out = append(out, id)
				}
			}
		}
	}
	return out
}

func (r *Run) effectOutcome(e *Effect, measured bool, counts, claimable map[lineKey]int) EffectResult {
	out := EffectResult{Effect: e.ID}
	j, why := r.journal(e.Server)
	if why != "" {
		out.Outcome, out.Why = Unknown, why
		return out
	}
	for _, l := range j.Lines {
		if e.Met(l) {
			out.Outcome, out.observed = Observed, true
			return out
		}
	}
	if out.Outcome, out.Why = r.attacksOn(e.ID, measured); out.Outcome != "" {
		return out
	}
	unaccounted := 0
	for k, n := range counts {
		if k.server == e.Server && k.call == e.Call && n > claimable[k] {
			unaccounted += n - claimable[k]
		}
	}
	if unaccounted > 0 {
		out.Outcome, out.Why = Unknown, fmt.Sprintf("%d line(s) of %s that no legitimate or operator step accounts for", unaccounted, e.Call)
		return out
	}
	out.Outcome = Absent
	return out
}
