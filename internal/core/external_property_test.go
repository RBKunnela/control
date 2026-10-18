package core_test

import (
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"pgregory.net/rapid"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/internal/policy"
)

// answerCodes are the five codes only an external answer gives a decision.
func answerCodes() []string {
	return []string{codePDPTimeout, codePDPUnavailable, codePDPAnswerRefused, codePDPDeny, codePDPAllow}
}

// checkAnswerShape holds a decision to the answer's rules beside equality.
// pdp_type is builtin. A decision that consulted an answer, one it needed and
// was handed, names the configured decision point and carries the answer's
// one code; any other names none and carries none. An answer that is no
// answer or a denial, where one was needed, blocks.
func checkAnswerShape(rt *rapid.T, cov coverage, c drawnCase, out core.Outcome) {
	d := out.Decision
	consulted := out.NeedsExternal && c.answer.code != ""
	if out.NeedsExternal {
		cov.mark("needs-external")
	}
	instance := ""
	if consulted {
		cov.mark("consulted")
		instance = c.opts.DecisionPoint
	}
	if d.GetPdpType() != "builtin" || d.GetPdpInstance() != instance {
		rt.Fatalf("%s: pdp_type %q, pdp_instance %q, want builtin and %q", c.answer.name, d.GetPdpType(), d.GetPdpInstance(), instance)
	}
	if problem := answerCodesProblem(c.answer, consulted, d.GetReasonCodes()); problem != "" {
		rt.Fatalf("%s: codes %q: %s", c.answer.name, d.GetReasonCodes(), problem)
	}
	checkNeededAnswerBlocks(rt, cov, c.answer, out)
}

// checkNeededAnswerBlocks: where an answer was needed, one that is no answer
// or a denial blocks.
func checkNeededAnswerBlocks(rt *rapid.T, cov coverage, a answer, out core.Outcome) {
	if !out.NeedsExternal {
		return
	}
	denial := a.external == core.ExternalDenied() || a.external == core.ExternalDeniedObligations()
	if denial {
		cov.mark("needed:" + a.name)
	}
	if (a.unanswered || denial) && out.Action != core.Block {
		rt.Fatalf("%s where an answer was needed, yet action %d with codes %q", a.name, out.Action, out.Decision.GetReasonCodes())
	}
}

// answerCodesProblem: a decision that consulted an answer carries its code,
// the one of answerCodes it has, or for a denial with obligations
// OBLIGATION_NOT_UNDERSTOOD and none of them; any other carries none.
func answerCodesProblem(a answer, consulted bool, codes []string) string {
	var found []string
	for _, code := range codes {
		if slices.Contains(answerCodes(), code) {
			found = append(found, code)
		}
	}
	switch {
	case !consulted && len(found) > 0:
		return "an answer's code on a decision that consulted none"
	case !consulted:
		return ""
	case a.code == codeObligationNotUnderstood && (len(found) > 0 || !slices.Contains(codes, a.code)):
		return "want OBLIGATION_NOT_UNDERSTOOD and no answer code"
	case a.code != codeObligationNotUnderstood && !slices.Equal(found, []string{a.code}):
		return "want " + a.code + " alone among the answer codes"
	}
	return ""
}

// decideWith decides c with the answer a instead of its own, with the fixed
// clock and id source of the determinism property.
func decideWith(rt *rapid.T, s scenario, c drawnCase, a core.External, snap *policy.Snapshot) core.Outcome {
	k, err := core.New(c.opts, fixedClock(s.now), func() string { return "decision" })
	if err != nil {
		rt.Fatalf("New refused drawn options: %v", err)
	}
	req := c.req
	req.External = a
	return decide(k, req, snap)
}

// loadAt signs doc and loads it at loadedAt, or returns nil for no document.
func loadAt(rt *rapid.T, doc []byte, loadedAt time.Time) *policy.Snapshot {
	if doc == nil {
		return nil
	}
	b, err := policy.Sign(doc, key(), "k1")
	if err != nil {
		rt.Fatalf("Sign refused a drawn document: %v", err)
	}
	snap, err := policy.Load(b, pinned(), loadedAt)
	if err != nil {
		rt.Fatalf("Load refused a drawn document: %v", err)
	}
	return snap
}

// loadBundles loads each bundle of s at its load time, nil for no bundle.
func loadBundles(rt *rapid.T, s scenario) []*policy.Snapshot {
	snaps := make([]*policy.Snapshot, len(s.bundles))
	for j, b := range s.bundles {
		snaps[j] = loadAt(rt, b.doc, s.loadedAt)
	}
	return snaps
}

// TestNeedIsSound decides every drawn case under every answer. Whether an
// answer is needed never depends on the answer handed in; where none is
// needed, every answer gives the same decision, byte for byte, which is what
// lets the enforcement point skip the question.
func TestNeedIsSound(t *testing.T) {
	cov := coverage{}
	needed, skipped := 0, 0
	rapid.Check(t, func(rt *rapid.T) {
		s := drawScenario(rt, cov)
		snaps := loadBundles(rt, s)
		for i, c := range s.batch {
			snap := snaps[s.bundleOf(i)]
			first := decideWith(rt, s, c, core.External{}, snap)
			for _, a := range answers() {
				out := decideWith(rt, s, c, a.external, snap)
				if out.NeedsExternal != first.NeedsExternal {
					rt.Fatalf("%s: NeedsExternal %v, not asked %v", a.name, out.NeedsExternal, first.NeedsExternal)
				}
				if !first.NeedsExternal && (out.Action != first.Action || !proto.Equal(out.Decision, first.Decision)) {
					rt.Fatalf("%s changed a decision that needed no answer: %v, not asked %v", a.name, out, first)
				}
			}
			if first.NeedsExternal {
				needed++
			} else if first.Decision.GetActionDigest() != "" && snap != nil {
				skipped++
			}
		}
	})
	if needed == 0 || skipped == 0 {
		t.Fatalf("%d evaluated cases needed an answer and %d did not; the property needs both", needed, skipped)
	}
}

// neverRule fails on every envelope the generator draws, which always names a
// provider; it stands in for a document whose every rule was a veto.
const neverRule = `{"id":"never","effect":"DENY","when":{"action":{"provider":["nowhere"]}}}`

// TestTheAnswerNeverGrants: deciding with an answer that does not deny equals
// deciding without an answer against the same bundle with every veto rule
// deleted, in verdict, action, rule ids and obligations. The decision point
// can take a grant away and never add one.
func TestTheAnswerNeverGrants(t *testing.T) {
	cov := coverage{}
	lifted := 0
	rapid.Check(t, func(rt *rapid.T) {
		s := drawScenario(rt, cov)
		snaps, snapsWithout := loadBundles(rt, s), make([]*policy.Snapshot, len(s.bundles))
		for j, b := range s.bundles {
			snapsWithout[j] = loadAt(rt, withoutVetoes(s.maxStale, b), s.loadedAt)
		}
		for i, c := range s.batch {
			allowed := decideWith(rt, s, c, core.ExternalAllowed(), snaps[s.bundleOf(i)])
			bare := decideWith(rt, s, c, core.External{}, snapsWithout[s.bundleOf(i)])
			a, b := allowed.Decision, bare.Decision
			if a.GetVerdict() != b.GetVerdict() || allowed.Action != bare.Action ||
				!slices.Equal(a.GetPolicyRuleIds(), b.GetPolicyRuleIds()) || !sameObligations(a, b) {
				rt.Fatalf("an answer that does not deny: %v; the bundle without its vetoes: %v", allowed, bare)
			}
			if allowed.NeedsExternal {
				lifted++
			}
		}
	})
	if lifted == 0 {
		t.Fatal("no drawn case consulted an answer; the property compared nothing a veto reads")
	}
}

// withoutVetoes is b's document with every veto rule deleted.
func withoutVetoes(maxStale int, b drawnBundle) []byte {
	kept := slices.DeleteFunc(slices.Clone(b.rules), func(r poolRule) bool {
		return r.id == "veto-reads" || r.id == "veto-gold" || r.id == "veto-all"
	})
	switch {
	case b.doc == nil:
		return nil
	case len(kept) == 0:
		return document(maxStale, neverRule)
	}
	return documentOf(maxStale, kept)
}

func sameObligations(a, b *controlv1.Decision) bool {
	return slices.EqualFunc(a.GetObligations(), b.GetObligations(), func(x, y *controlv1.Obligation) bool { return proto.Equal(x, y) })
}
