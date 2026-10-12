package main

import (
	"fmt"
	"testing"
)

// TestFollowAlertsAnUncertainEnd: a run that timed out or whose outcome
// nobody knows ends uncertain, prints as such and raises effect_uncertain at
// the event that ended it; a failure raises nothing.
func TestFollowAlertsAnUncertainEnd(t *testing.T) {
	ids := `"tenant":"t","project":"p","request":"%s","run":"run-%[1]s","event":"%s","offset":%d`
	for _, tc := range []struct {
		status string
		code   int
		alert  string
	}{
		{"TIMEOUT", 1, `{"v":1,"alert":"effect_uncertain",` + ids + `,"note":"event u-4 is ACTION_FAILED with result RESULT_STATUS_TIMEOUT: the effect may have happened"}` + "\n"},
		{"UNKNOWN", 1, `{"v":1,"alert":"effect_uncertain",` + ids + `,"note":"event u-4 is ACTION_FAILED with result RESULT_STATUS_UNKNOWN: the effect may have happened"}` + "\n"},
		{"FAILURE", 0, ""},
	} {
		t.Run(tc.status, func(t *testing.T) {
			lines := chain("u", allowed[0], allowed[1], allowed[2], step{"ACTION_FAILED", ended("x1", tc.status)})
			at := 0
			for _, l := range lines[:3] {
				at += len(l) + 1
			}
			got := consume(t, newState(t), framed("u.trail", lines, 0, len(lines), 1000))
			want := ""
			if tc.alert != "" {
				want = fmt.Sprintf(tc.alert, "u", "u-4", at)
			}
			if got.code != tc.code || withoutCursors(alertLines(got.stderr)) != want {
				t.Errorf("exit %d, alerts\n%s\nwant %d,\n%s", got.code, alertLines(got.stderr), tc.code, want)
			}
		})
	}
}
