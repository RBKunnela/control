package main

import (
	"strings"
	"testing"
)

// findingIn is a FINDING_RAISED linked after r1's last event, under mode.
func findingIn(mode string) string {
	return strings.Replace(evt("r1", "r1-5", "r1-4", "FINDING_RAISED", ""), `"ENFORCEMENT_MODE_ENFORCE"`, mode, 1)
}

func undeclaredFinding() string { return findingIn("99") }

const undeclaredNote = "event r1-5 names enforcement mode 99, which this reader does not declare"

// TestAnAnnotationAfterTheEndKeepsTheModeCheck: a completed ENFORCE request
// and then a linked FINDING_RAISED under an undeclared mode is unknown to the
// one-shot walk, and the follower raises it unknown too, in the export that
// ends the request and in a later one.
func TestAnAnnotationAfterTheEndKeepsTheModeCheck(t *testing.T) {
	r1 := chain("r1", allowed...)
	walked := report(t, newExport("1.0").event(r1...).event(undeclaredFinding()).whole())
	rows, _ := table(t, walked.stdout)
	if walked.code != 1 || len(rows) != 1 || !strings.HasSuffix(rows[0], "\tunknown\t"+undeclaredNote) {
		t.Fatalf("the walk: exit %d, rows %q; want 1 and r1 unknown", walked.code, rows)
	}
	trail := append(r1, undeclaredFinding())
	for name, exports := range map[string][]string{
		"one export":  {framed("a.trail", trail, 0, 5, 1000)},
		"two exports": {framed("a.trail", trail, 0, 4, 1000), framed("a.trail", trail, 4, 5, 1000)},
	} {
		t.Run(name, func(t *testing.T) {
			dir := newState(t)
			var last outcome
			for _, x := range exports {
				last = consume(t, dir, x)
			}
			if last.code != 1 || !strings.Contains(alertLines(last.stderr), `"alert":"lifecycle_unknown"`) ||
				!strings.Contains(last.stderr, undeclaredNote) {
				t.Fatalf("followed: exit %d, stderr:\n%s\nwant 1 and r1-5 unknown", last.code, last.stderr)
			}
		})
	}
}

// TestTheFollowerTakesAnAnnotationAsTheWalkDoes: after a completed ENFORCE
// request, a linked finding under its own mode leaves it completed for both
// the walk and the follower, and one under another mode makes both unknown.
func TestTheFollowerTakesAnAnnotationAsTheWalkDoes(t *testing.T) {
	r1 := chain("r1", allowed...)
	for mode, note := range map[string]string{
		`"ENFORCEMENT_MODE_ENFORCE"`:     "",
		`"ENFORCEMENT_MODE_OBSERVE"`:     "event r1-5 names enforcement mode OBSERVE, and the request's first event ENFORCE",
		`"ENFORCEMENT_MODE_UNSPECIFIED"`: "event r1-5 names no enforcement mode",
		"99":                             undeclaredNote,
	} {
		t.Run(mode, func(t *testing.T) {
			trail := append(append([]string(nil), r1...), findingIn(mode))
			walked := report(t, framed("a.trail", trail, 0, 5, 1000))
			rows, _ := table(t, walked.stdout)
			followed := consume(t, newState(t), framed("a.trail", trail, 0, 5, 1000))
			if note == "" {
				if walked.code != 0 || followed.code != 0 || followed.stderr != "" {
					t.Fatalf("walk exit %d, follow exit %d, stderr %q; want both 0", walked.code, followed.code, followed.stderr)
				}
				return
			}
			if walked.code != 1 || len(rows) != 1 || !strings.HasSuffix(rows[0], "\tunknown\t"+note) {
				t.Errorf("the walk: exit %d, rows %q; want r1 unknown: %s", walked.code, rows, note)
			}
			if followed.code != 1 || !strings.Contains(followed.stderr, `"note":"`+note+`"`) {
				t.Errorf("followed: exit %d, stderr %q; want 1 and %s", followed.code, followed.stderr, note)
			}
		})
	}
}

// TestALegacyStateIsReadAndItsClosedModesAreUnknown: a 1.0 state, whose
// closed requests hold no mode, is read; a linked finding after the end of
// such a request cannot be held to its mode and is unknown, and the state is
// written back as 1.1.
func TestALegacyStateIsReadAndItsClosedModesAreUnknown(t *testing.T) {
	trail := append(chain("r1", allowed...), findingIn(`"ENFORCEMENT_MODE_ENFORCE"`))
	dir := newState(t)
	if got := consume(t, dir, framed("a.trail", trail, 0, 4, 1000)); got.code != 0 {
		t.Fatalf("the first export: exit %d, stderr %q", got.code, got.stderr)
	}
	inTurn(editState(`"schema_version":"1.1"`, `"schema_version":"1.0"`), editState(`,"mode":"ENFORCEMENT_MODE_ENFORCE"`, ``))(t, dir)
	got := consume(t, dir, framed("a.trail", trail, 4, 5, 1000))
	note := "event r1-5 follows the end of a request whose enforcement mode the state does not hold"
	if got.code != 1 || !strings.Contains(got.stderr, `"note":"`+note+`"`) {
		t.Fatalf("after a 1.0 state: exit %d, stderr %q; want 1 and %s", got.code, got.stderr, note)
	}
	if s := stateOf(t, dir); !strings.HasPrefix(s, `{"schema_version":"1.1",`) {
		t.Errorf("the state written back:\n%s\nwant 1.1", s)
	}
}
