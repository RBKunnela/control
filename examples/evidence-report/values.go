package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
)

// cursorOffset is where the line a cursor names ends, 0 for no cursor.
func cursorOffset(c string) int64 {
	parts := strings.Split(c, ":")
	if len(parts) != 4 {
		return 0
	}
	n, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// cursorSource is the source a v1 cursor names, empty for anything else.
func cursorSource(c string) string {
	if !isCursor(c) {
		return ""
	}
	return strings.Split(c, ":")[1]
}

func lineHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// oversize reports an event holding a value this reader does not keep:
// one longer than maxValueBytes as JSON writes it, which may escape one
// byte in six, or more than maxReasons reason codes.
func oversize(ev *controlv1.Event) bool {
	d := ev.GetDecision()
	if len(d.GetReasonCodes()) > maxReasons {
		return true
	}
	values := append([]string{ev.GetTenantId(), ev.GetProjectId(), ev.GetRequestId(), ev.GetRunId(), ev.GetEventId(),
		ev.GetPrevEventId(), ev.GetExecutionId(), ev.GetProposed().GetAction().GetName(), d.GetDecisionId()}, d.GetReasonCodes()...)
	return slices.ContainsFunc(values, func(v string) bool { return !fits(v) })
}

// fits reports whether JSON writes v in at most maxValueBytes.
func fits(v string) bool {
	b, err := json.Marshal(v)
	return err == nil && len(b)-len(`""`) <= maxValueBytes
}

const cutNote = "a value longer than 64 bytes as JSON writes it, or past 16 reason codes, is left out of this alert"

// boundedFacts is a decision as an alert may carry it: the first maxReasons
// of its reason codes that fit. Its id is only compared with the kernel's,
// never printed. A nil decision is nil.
func boundedFacts(d *controlv1.Decision) *decisionFacts {
	if d == nil {
		return nil
	}
	f := &decisionFacts{id: d.GetDecisionId(), verdict: verdictName(d)}
	for _, c := range d.GetReasonCodes() {
		if fits(c) && len(f.codes) < maxReasons {
			f.codes = append(f.codes, c)
		}
	}
	return f
}

const tooLongNote = "an event holds a value longer than 64 bytes as JSON writes it, or more than 16 reason codes, which this reader does not keep"
