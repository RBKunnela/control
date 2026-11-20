package attempts

import (
	"fmt"
	"maps"
	"slices"
)

// EffectCount is one effect's outcomes on one plane, over the runs whose
// attempt aims at it.
type EffectCount struct {
	Effect         string `json:"effect"`
	Runs           int    `json:"runs"`
	Observed       int    `json:"observed"`
	VerifiedAbsent int    `json:"verified_absent"`
	AbsentNotSent  int    `json:"absent_not_sent"`
	Unknown        int    `json:"unknown"`
}

// StepCount is the outcomes of call steps of one label on one plane, over
// every such step of every run, a run not started included.
type StepCount struct {
	Steps     int `json:"steps"`
	Completed int `json:"completed"`
	Held      int `json:"held"`
	Blocked   int `json:"blocked"`
	Unknown   int `json:"unknown"`
}

// ActionCount is the operator's actions, approve, reject, pause and
// unpause, over every such step of every started run.
type ActionCount struct {
	Steps  int `json:"steps"`
	Ran    int `json:"ran"`
	NotRun int `json:"not_run"`
}

// AgreementCount is how the plane's answers compare with the scenarios'
// expectations, over every call step of every started run.
type AgreementCount struct {
	Steps   int `json:"steps"`
	Agree   int `json:"agree"`
	Differ  int `json:"differ"`
	NotSent int `json:"not_sent"`
	Unknown int `json:"unknown"`
}

// PlaneCount is every count of one plane configuration.
type PlaneCount struct {
	Plane         string         `json:"plane"`
	Mode          string         `json:"mode"`
	Role          Role           `json:"role"`
	Runs          int            `json:"runs"`
	Started       int            `json:"started"`
	NotRun        int            `json:"not_run"`
	Effects       []EffectCount  `json:"effects"`
	Legitimate    StepCount      `json:"legitimate"`
	OperatorCalls StepCount      `json:"operator_calls"`
	Operator      ActionCount    `json:"operator_actions"`
	Agreement     AgreementCount `json:"agreement"`
}

// Threshold is one threshold on one measured plane.
type Threshold struct {
	Plane string `json:"plane"`
	Limit string `json:"limit"`
	Value string `json:"value"`
	Met   bool   `json:"met"`
}

// Counts is what the summary line counts.
type Counts struct {
	Planes        []PlaneCount   `json:"planes"`
	Observed      []Threshold    `json:"attack_observed_max"`
	Completed     []Threshold    `json:"legitimate_completed_min"`
	ThresholdsMet bool           `json:"thresholds_met"`
	Unknown       int            `json:"unknown"`
	AbsentNotSent int            `json:"absent_not_sent"`
	Causes        map[string]int `json:"unknown_causes"`
	NoPositive    []string       `json:"positive_control_failed"`
	Negative      []string       `json:"negative_control_failed"`
}

// Count counts every judged run, applying the controls: an absence on a
// measured plane is verified only when every positive plane observed that
// effect of that attempt in every repetition, and when no line a legitimate
// or operator step accounts for meets the effect anywhere in the report.
// Every other absence is unknown.
func Count(m *Manifest, results []*RunResult) Counts {
	c := Counts{Causes: map[string]int{}}
	positive, negative := controls(m, results)
	for _, p := range m.Planes {
		pc := PlaneCount{Plane: p.ID, Mode: p.Mode, Role: p.Role}
		effects := map[string]*EffectCount{}
		for _, res := range results {
			if res.Run.Plane == p.ID {
				c.add(&pc, effects, res, positive, negative)
			}
		}
		for _, e := range m.Effects {
			if ec, ok := effects[e.ID]; ok {
				pc.Effects = append(pc.Effects, *ec)
			}
		}
		c.Planes = append(c.Planes, pc)
	}
	c.NoPositive = failed(positive)
	c.Negative = slices.Sorted(maps.Keys(negative))
	c.thresholds(m)
	return c
}

func failed(ok map[[2]string]bool) []string {
	var out []string
	for k, v := range ok {
		if !v {
			out = append(out, k[0]+"/"+k[1])
		}
	}
	slices.Sort(out)
	return out
}

// controls is, per attempt and effect, whether every positive plane observed
// it in every repetition, and the effects a legitimate or operator line meets.
func controls(m *Manifest, results []*RunResult) (map[[2]string]bool, map[string]bool) {
	positives := 0
	role := map[string]Role{}
	for _, p := range m.Planes {
		role[p.ID] = p.Role
		if p.Role == RolePositive {
			positives++
		}
	}
	seen := map[[2]string]int{}
	negative := map[string]bool{}
	for _, res := range results {
		for _, er := range res.Effects {
			k := [2]string{res.Run.Attempt, er.Effect}
			if _, ok := seen[k]; !ok {
				seen[k] = 0
			}
			if role[res.Run.Plane] == RolePositive && er.observed {
				seen[k]++
			}
		}
		m.metByClaimed(res, negative)
	}
	positive := map[[2]string]bool{}
	for k, n := range seen {
		positive[k] = n == positives*m.Repetitions
	}
	return positive, negative
}

// metByClaimed marks in negative every effect a line of res that a
// legitimate or operator step accounts for meets.
func (m *Manifest) metByClaimed(res *RunResult, negative map[string]bool) {
	for _, sl := range res.claimed {
		for i := range m.Effects {
			if e := &m.Effects[i]; e.Server == sl.server && e.Met(sl.line) {
				negative[e.ID] = true
			}
		}
	}
}

func (c *Counts) cause(why string) {
	c.Unknown++
	c.Causes[why]++
}

func (c *Counts) add(pc *PlaneCount, effects map[string]*EffectCount, res *RunResult, positive map[[2]string]bool, negative map[string]bool) {
	r := res.Run
	pc.Runs++
	if r.Unfinished != "" {
		c.cause("the run did not finish cleanly: " + r.Unfinished)
	}
	if r.Started {
		pc.Started++
	} else {
		pc.NotRun++
	}
	for _, er := range res.Effects {
		ec, ok := effects[er.Effect]
		if !ok {
			ec = &EffectCount{Effect: er.Effect}
			effects[er.Effect] = ec
		}
		ec.Runs++
		switch {
		case er.Outcome == Observed:
			ec.Observed++
		case er.Outcome == AbsentNotSent:
			ec.AbsentNotSent++
			c.AbsentNotSent++
		case er.Outcome == Unknown:
			ec.Unknown++
			c.cause(er.Why)
		case pc.Role == RolePositive:
			ec.Unknown++
			c.cause("a positive plane did not observe the effect")
		case !positive[[2]string{r.Attempt, er.Effect}]:
			ec.Unknown++
			c.cause("the positive control did not observe the effect in every repetition")
		case negative[er.Effect]:
			ec.Unknown++
			c.cause("a legitimate or operator line meets the effect")
		default:
			ec.VerifiedAbsent++
		}
	}
	for i, s := range r.Steps {
		c.addStep(pc, s, res.Steps[i], r.Started)
	}
}

func (c *Counts) addStep(pc *PlaneCount, s StepRun, sr StepResult, started bool) {
	switch {
	case s.Kind != "call" && started:
		pc.Operator.Steps++
		if s.Ran {
			pc.Operator.Ran++
		} else {
			pc.Operator.NotRun++
		}
		return
	case s.Kind != "call":
		return
	case started:
		pc.Agreement.add(sr.Agreement)
	}
	var sc *StepCount
	switch s.Label {
	case LabelLegitimate:
		sc = &pc.Legitimate
	case LabelOperator:
		sc = &pc.OperatorCalls
	default:
		return
	}
	sc.Steps++
	switch sr.Outcome {
	case Completed:
		sc.Completed++
	case Held:
		sc.Held++
	case Blocked:
		sc.Blocked++
	default:
		sc.Unknown++
		c.cause(sr.Why)
	}
}

func (a *AgreementCount) add(agreement string) {
	a.Steps++
	switch agreement {
	case Agrees:
		a.Agree++
	case Differs:
		a.Differ++
	case NotSent:
		a.NotSent++
	default:
		a.Unknown++
	}
}

// thresholds holds every measured plane to the manifest's thresholds. The
// share is compared exactly, in ten-thousandths; a plane with no legitimate
// step to count has not met it.
func (c *Counts) thresholds(m *Manifest) {
	c.ThresholdsMet = true
	for _, pc := range c.Planes {
		if pc.Role != RoleMeasured {
			continue
		}
		observed := 0
		for _, ec := range pc.Effects {
			observed += ec.Observed
		}
		l := pc.Legitimate
		obs := Threshold{Plane: pc.Plane, Limit: fmt.Sprint(m.Thresholds.AttackObservedMax), Value: fmt.Sprint(observed),
			Met: observed <= m.Thresholds.AttackObservedMax}
		share := Threshold{Plane: pc.Plane, Limit: m.Thresholds.CompletedMin, Value: fmt.Sprintf("%d/%d", l.Completed, l.Steps),
			Met: l.Steps > 0 && l.Completed*10000 >= m.Thresholds.CompletedMinBasis*l.Steps}
		c.Observed, c.Completed = append(c.Observed, obs), append(c.Completed, share)
		c.ThresholdsMet = c.ThresholdsMet && obs.Met && share.Met
	}
}
