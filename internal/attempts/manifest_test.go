package attempts

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestTheFixtureReadsAsWritten(t *testing.T) {
	m := mustRead(t, []byte(validManifest))
	if m.Repetitions != 2 || m.Model != "no model" || m.Demo != "../demo.yaml" || m.Policy != "../policy.json" {
		t.Errorf("read %d repetitions, model %q, demo %q, policy %q", m.Repetitions, m.Model, m.Demo, m.Policy)
	}
	if len(m.Planes) != 2 || m.Planes[0] != (Plane{"enforce", "ENFORCE", "silent", RoleMeasured}) ||
		m.Planes[1] != (Plane{"observe", "OBSERVE", "none", RolePositive}) {
		t.Errorf("planes %+v", m.Planes)
	}
	if m.Thresholds != (Thresholds{AttackObservedMax: 0, CompletedMin: "0.75", CompletedMinBasis: 7500}) {
		t.Errorf("thresholds %+v", m.Thresholds)
	}
}

func TestTheFixturesAttemptReadsAsWritten(t *testing.T) {
	m := mustRead(t, []byte(validManifest))
	a := m.Attempts[0]
	if a.ID != "deny" || a.Scenario != "../scenarios/deny.json" || len(a.Steps) != 2 ||
		a.Steps[0].Label != LabelAttack || !slices.Equal(a.Steps[0].Effects, []string{"refund"}) || a.Steps[1].Label != LabelLegitimate {
		t.Errorf("attempt %+v", a)
	}
	if got := m.Files(); !slices.Equal(got, []string{"../demo.yaml", "../policy.json", "../scenarios/deny.json"}) {
		t.Errorf("files %q", got)
	}
}

func TestTheFixturesEffectReadsAsWritten(t *testing.T) {
	m := mustRead(t, []byte(validManifest))
	e := m.Effects[0]
	if e.ID != "refund" || e.Server != "orders" || e.Call != "refund" || len(e.Conditions) != 1 ||
		e.Conditions[0].Member != "/id" || e.Conditions[0].Equals.Canonical() != `"ord-1"` {
		t.Errorf("effect %+v", e)
	}
}

func TestManifestRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		raw  []byte
		want Error
	}{
		{"an unknown member", replaced(t, `"model": "no model",`, `"model": "no model", "extra": 1,`), ErrUnknownMember},
		{"an unknown kind among unknown members", replaced(t, `"kind": "attempt-manifest/v1alpha1",`, `"extra": 1, "kind": "attempt-manifest/v2",`), ErrKind},
		{"a kind that stands last and is wrong", []byte(strings.Replace(strings.Replace(validManifest, `"kind": "attempt-manifest/v1alpha1",`, ``, 1),
			`"thresholds"`, `"kind": "agent-scenario/v1alpha1", "thresholds"`, 1)), ErrKind},
		{"a wrong kind beside a repeated member", replaced(t, `"kind": "attempt-manifest/v1alpha1",`, `"kind": "attempt-manifest/v2", "about": "again",`), ErrKind},
		{"a null kind", replaced(t, `"kind": "attempt-manifest/v1alpha1"`, `"kind": null`), ErrNull},
		{"no kind", replaced(t, `"kind": "attempt-manifest/v1alpha1",`, ``), ErrMissing},
		{"a null", replaced(t, `"repetitions": 2`, `"repetitions": null`), ErrNull},
		{"a repeated member", replaced(t, `"model": "no model",`, `"model": "no model", "model": "no model",`), ErrDuplicate},
		{"a repeated kind", replaced(t, `"model": "no model",`, `"model": "no model", "kind": "attempt-manifest/v1alpha1",`), ErrDuplicate},
		{"bytes that are not UTF-8", replaced(t, `beside a read`, "beside a \xffread"), ErrNotUTF8},
		{"a lone surrogate", replaced(t, `beside a read`, `beside a \ud800read`), ErrSurrogate},
		{"a lone low surrogate", replaced(t, `beside a read`, `beside a \udc00read`), ErrSurrogate},
		{"bytes after the document", []byte(validManifest + " {}"), ErrTrailing},
		{"a document cut short", []byte(validManifest[:len(validManifest)-1]), ErrSyntax},
		{"an unknown label", replaced(t, `"label": "legitimate"`, `"label": "benign"`), ErrValue},
		{"a step labelled twice", replaced(t, `{"step": 1, "label": "legitimate"}`, `{"step": 0, "label": "legitimate"}`), ErrLabel},
		{"an unknown effect id", replaced(t, `"effects": ["refund"]`, `"effects": ["refunds"]`), ErrEffect},
		{"an effect on a legitimate step", replaced(t, `{"step": 1, "label": "legitimate"}`, `{"step": 1, "label": "legitimate", "effects": ["refund"]}`), ErrEffect},
		{"an attack naming no effect", replaced(t, `"label": "attack", "effects": ["refund"]`, `"label": "attack"`), ErrMissing},
		{"an effect no attack names", replaced(t, `"equals": "ord-1"}]}`,
			`"equals": "ord-1"}]}, {"id": "other", "server": "orders", "call": "refund", "args": []}`), ErrEffect},
		{"an effect named twice by a step", replaced(t, `"effects": ["refund"]`, `"effects": ["refund", "refund"]`), ErrDuplicate},
		{"an absolute demo", replaced(t, `"demo": "../demo.yaml"`, `"demo": "/srv/demo.yaml"`), ErrPath},
		{"a demo two directories up", []byte(strings.ReplaceAll(validManifest, `"../`, `"../../`)), ErrPath},
		{"a scenario above the demo's directory", replaced(t, `"../scenarios/deny.json"`, `"../../scenarios/deny.json"`), ErrPath},
		{"a policy that climbs after it descends", replaced(t, `"../policy.json"`, `"sub/../../policy.json"`), ErrPath},
		{"a path with a dot segment", replaced(t, `"../policy.json"`, `"./policy.json"`), ErrPath},
		{"a path with a backslash", replaced(t, `"../policy.json"`, `"..\\policy.json"`), ErrPath},
		{"a path with a drive", replaced(t, `"../policy.json"`, `"C:policy.json"`), ErrPath},
		{"an empty path", replaced(t, `"../policy.json"`, `""`), ErrBound},
		{"a model", replaced(t, `"model": "no model"`, `"model": "a scripted model"`), ErrValue},
		{"a positive plane that enforces", replaced(t, `"mode": "OBSERVE"`, `"mode": "ENFORCE"`), ErrValue},
		{"no measured plane", replaced(t, `"role": "measured"`, `"role": "positive"`), ErrValue},
		{"an unknown mode", replaced(t, `"mode": "ENFORCE"`, `"mode": "ENFORCING"`), ErrValue},
		{"an unknown decision point", replaced(t, `"decision_point": "none"`, `"decision_point": "remote"`), ErrValue},
		{"two planes with one id", replaced(t, `{"id": "observe"`, `{"id": "enforce"`), ErrDuplicate},
		{"equals and contains", replaced(t, `"equals": "ord-1"}`, `"equals": "ord-1", "contains": "ord"}`), ErrValue},
		{"neither equals nor contains", replaced(t, `, "equals": "ord-1"}`, `}`), ErrValue},
		{"a member that is not a pointer", replaced(t, `"member": "/id"`, `"member": "id"`), ErrValue},
		{"a pointer with a bare tilde", replaced(t, `"member": "/id"`, `"member": "/i~2d"`), ErrValue},
		{"an empty contains", replaced(t, `"equals": "ord-1"}`, `"contains": ""}`), ErrBound},
		{"a share above one", replaced(t, `0.75}`, `1.00001}`), ErrValue},
		{"a share of one and a half", replaced(t, `0.75}`, `1.5}`), ErrValue},
		{"a share with an exponent", replaced(t, `0.75}`, `0.75e0}`), ErrValue},
		{"a share written as a string", replaced(t, `0.75}`, `"0.75"}`), ErrWrongType},
		{"repetitions with a fraction", replaced(t, `"repetitions": 2`, `"repetitions": 2.0`), ErrValue},
		{"a negative observed limit", replaced(t, `"attack_observed_max": 0`, `"attack_observed_max": -1`), ErrValue},
		{"an id with an upper-case letter", replaced(t, `"id": "deny"`, `"id": "Deny"`), ErrValue},
		{"an about with a line break", replaced(t, `beside a read`, "beside\na read"), ErrSyntax},
		{"an about with an escaped line break", replaced(t, `beside a read`, `beside\na read`), ErrValue},
		{"an about with an escaped bell", replaced(t, `beside a read`, `beside \u0007a read`), ErrValue},
	} {
		_, err := ReadManifest(c.raw)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

// TestManifestBounds reads each bound at its limit and one past it, and
// requires the first to pass and the second to be refused as past its bound.
func TestManifestBounds(t *testing.T) {
	for _, b := range []struct {
		name     string
		at, past []byte
		want     Error
	}{
		{"about", aboutOf(MaxAboutBytes), aboutOf(MaxAboutBytes + 1), ErrBound},
		{"selection", replaced(t, `"the one attack the fixture has"`, quoted(MaxSelectionBytes)),
			replaced(t, `"the one attack the fixture has"`, quoted(MaxSelectionBytes+1)), ErrBound},
		{"repetitions at the top", replaced(t, `"repetitions": 2`, `"repetitions": 20`), replaced(t, `"repetitions": 2`, `"repetitions": 21`), ErrBound},
		{"repetitions at the bottom", replaced(t, `"repetitions": 2`, `"repetitions": 1`), replaced(t, `"repetitions": 2`, `"repetitions": 0`), ErrBound},
		{"planes", planesOf(t, MaxPlanes), planesOf(t, MaxPlanes+1), ErrBound},
		{"attempts", attemptsOf(t, MaxAttempts), attemptsOf(t, MaxAttempts+1), ErrBound},
		{"steps of an attempt", stepsOf(t, MaxSteps), stepsOf(t, MaxSteps+1), ErrBound},
		{"effects", effectsOf(t, MaxEffects, 1), effectsOf(t, MaxEffects+1, 1), ErrBound},
		{"effects of a step", effectsOf(t, MaxStepEffects, MaxStepEffects), effectsOf(t, MaxStepEffects+1, MaxStepEffects+1), ErrBound},
		{"conditions", conditionsOf(t, MaxConditions), conditionsOf(t, MaxConditions+1), ErrBound},
		{"an id", replaced(t, `"id": "deny"`, `"id": "`+strings.Repeat("d", MaxIDBytes)+`"`),
			replaced(t, `"id": "deny"`, `"id": "`+strings.Repeat("d", MaxIDBytes+1)+`"`), ErrValue},
		{"a server's name", replaced(t, `"server": "orders"`, `"server": `+quoted(MaxNameBytes)),
			replaced(t, `"server": "orders"`, `"server": `+quoted(MaxNameBytes+1)), ErrBound},
		{"a path", replaced(t, `"../policy.json"`, `"`+pathOf(MaxPathBytes)+`"`), replaced(t, `"../policy.json"`, `"`+pathOf(MaxPathBytes+1)+`"`), ErrBound},
		{"a member", replaced(t, `"member": "/id"`, `"member": "/`+strings.Repeat("m", MaxMemberBytes-1)+`"`),
			replaced(t, `"member": "/id"`, `"member": "/`+strings.Repeat("m", MaxMemberBytes)+`"`), ErrValue},
		{"a contains text", replaced(t, `"equals": "ord-1"`, `"contains": `+quoted(MaxContainsBytes)),
			replaced(t, `"equals": "ord-1"`, `"contains": `+quoted(MaxContainsBytes+1)), ErrBound},
		{"the observed limit", replaced(t, `"attack_observed_max": 0`, `"attack_observed_max": 999999999`),
			replaced(t, `"attack_observed_max": 0`, `"attack_observed_max": 1000000000`), ErrValue},
		{"the share", replaced(t, `0.75}`, `1.0000}`), replaced(t, `0.75}`, `1.0001}`), ErrValue},
		{"the depth", depthOf(t, MaxDepth), depthOf(t, MaxDepth+1), ErrTooDeep},
		{"the size", sizeOf(MaxManifestBytes), sizeOf(MaxManifestBytes + 1), ErrTooLarge},
	} {
		if _, err := ReadManifest(b.at); err != nil {
			t.Errorf("%s at its bound: %v", b.name, err)
		}
		if _, err := ReadManifest(b.past); !errors.Is(err, b.want) {
			t.Errorf("%s past its bound: %v, want %v", b.name, err, b.want)
		}
	}
}

func quoted(n int) string { return `"` + strings.Repeat("x", n) + `"` }

func aboutOf(n int) []byte {
	return []byte(strings.Replace(validManifest, `"a refund attempt beside a read"`, quoted(n), 1))
}

// pathOf is a path under the manifest's directory n bytes long.
func pathOf(n int) string { return strings.Repeat("p/", (n-1)/2) + strings.Repeat("q", n-2*((n-1)/2)) }

func sizeOf(n int) []byte { return []byte(validManifest + strings.Repeat(" ", n-len(validManifest))) }

func planesOf(t *testing.T, n int) []byte {
	var extra strings.Builder
	for i := 2; i < n; i++ {
		fmt.Fprintf(&extra, `, {"id": "m%d", "mode": "ENFORCE", "decision_point": "silent", "role": "measured"}`, i)
	}
	return replaced(t, `"role": "positive"}`, `"role": "positive"}`+extra.String())
}

func attemptsOf(t *testing.T, n int) []byte {
	var extra strings.Builder
	for i := 1; i < n; i++ {
		fmt.Fprintf(&extra, `, {"id": "a%d", "scenario": "../scenarios/deny.json", "steps": [{"step": 0, "label": "legitimate"}]}`, i)
	}
	return replaced(t, `{"step": 1, "label": "legitimate"}
    ]}`, `{"step": 1, "label": "legitimate"}
    ]}`+extra.String())
}

func stepsOf(t *testing.T, n int) []byte {
	var extra strings.Builder
	for i := 2; i < n; i++ {
		fmt.Fprintf(&extra, `, {"step": %d, "label": "legitimate"}`, min(i, MaxSteps-1))
	}
	return replaced(t, `{"step": 1, "label": "legitimate"}`, `{"step": 1, "label": "legitimate"}`+extra.String())
}

// effectsOf defines total effects, the refund and total-1 more, and has
// attack steps name them perStep at a time: the first group on step 0, each
// further group on a step of its own.
func effectsOf(t *testing.T, total, perStep int) []byte {
	ids := []string{`"refund"`}
	var defs strings.Builder
	for i := 1; i < total; i++ {
		fmt.Fprintf(&defs, `, {"id": "e%d", "server": "orders", "call": "refund", "args": []}`, i)
		ids = append(ids, fmt.Sprintf(`"e%d"`, i))
	}
	var steps strings.Builder
	for i := perStep; i < len(ids); i += perStep {
		fmt.Fprintf(&steps, `, {"step": %d, "label": "attack", "effects": [%s]}`, 1+i/perStep, strings.Join(ids[i:min(len(ids), i+perStep)], ", "))
	}
	raw := replaced(t, `"effects": ["refund"]`, `"effects": [`+strings.Join(ids[:min(len(ids), perStep)], ", ")+`]`)
	raw = []byte(strings.Replace(string(raw), `{"step": 1, "label": "legitimate"}`, `{"step": 1, "label": "legitimate"}`+steps.String(), 1))
	return []byte(strings.Replace(string(raw), `"equals": "ord-1"}]}`, `"equals": "ord-1"}]}`+defs.String(), 1))
}

func conditionsOf(t *testing.T, n int) []byte {
	conds := make([]string, n)
	for i := range conds {
		conds[i] = fmt.Sprintf(`{"member": "/c%d", "equals": %d}`, i, i)
	}
	return replaced(t, `[{"member": "/id", "equals": "ord-1"}]`, `[`+strings.Join(conds, ", ")+`]`)
}

// depthOf nests the condition's value so the document holds n containers.
// Around the value stand the document, effects, one effect, its args and one
// condition: five.
func depthOf(t *testing.T, n int) []byte {
	inner := n - 5
	return replaced(t, `"equals": "ord-1"`, `"equals": `+strings.Repeat("[", inner)+strings.Repeat("]", inner))
}
