package main

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// healthDoc is a /healthz answer with the counters a runner reads.
type healthDoc struct {
	status                             int
	unack, quarantined, partial, polls int
	pauseState, cause                  string
	entries                            int
	omit                               string
	// freshness is the policy's; empty is confirmed.
	freshness string
}

func (h healthDoc) body() string {
	parts := map[string]string{
		"halted":   `"halted":false`,
		"pipeline": `"pipeline":{"admitted":0}`,
		"spool":    fmt.Sprintf(`"spool":{"unacknowledged":%d,"quarantined_records":%d}`, h.unack, h.quarantined),
		"exporter": fmt.Sprintf(`"exporter":{"acknowledged":0,"partial_rejected":%d}`, h.partial),
		"pause":    fmt.Sprintf(`"pause":{"state":%q,"entries":%d,"polls":{"made":%d}}`, h.pauseState, h.entries, h.polls),
		"policy":   fmt.Sprintf(`"policy":{"freshness":%q}`, cmp.Or(h.freshness, "confirmed")),
	}
	if h.polls < 0 {
		parts["pause"] = fmt.Sprintf(`"pause":{"state":%q,"entries":%d}`, h.pauseState, h.entries)
	}
	if h.cause != "" {
		parts["pause"] = strings.TrimSuffix(parts["pause"], "}") + fmt.Sprintf(`,"cause":%q}`, h.cause)
	}
	members := []string{`"mode":"APPROVE"`, `"bundle":{"id":"b","digest":"sha256:bb"}`}
	for _, k := range []string{"halted", "pipeline", "spool", "exporter", "pause", "policy"} {
		if k != h.omit {
			members = append(members, parts[k])
		}
	}
	return "{" + strings.Join(members, ",") + "}"
}

// scriptedPlane answers /healthz with the n-th document of script on its
// n-th read, and the last one from then on.
func scriptedPlane(t *testing.T, script ...healthDoc) *runner {
	t.Helper()
	var reads atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		doc := script[min(int(reads.Add(1))-1, len(script)-1)]
		status := doc.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(doc.body()))
	}))
	t.Cleanup(ts.Close)
	return &runner{plane: planeTarget{healthURL: ts.URL}, timeout: 300 * time.Millisecond, http: ts.Client()}
}

// TestHealthRefusesAnAnswerWithoutACounter: a counter the answer does not
// carry is refused, never read as zero.
func TestHealthRefusesAnAnswerWithoutACounter(t *testing.T) {
	for _, omit := range []string{"halted", "pipeline", "spool", "exporter", "pause", "policy"} {
		r := scriptedPlane(t, healthDoc{pauseState: "clear", omit: omit})
		if _, err := r.health(context.Background()); err == nil || !strings.Contains(err.Error(), "without") {
			t.Errorf("an answer without %s: err = %v", omit, err)
		}
	}
	r := scriptedPlane(t, healthDoc{pauseState: "disabled", polls: -1})
	if s, err := r.health(context.Background()); err != nil || s.polls != -1 {
		t.Errorf("a plane with no pause file: %+v, %v", s, err)
	}
}

// TestServingRefusesAPolicyThatIsNotConfirmed: a scenario's verdicts are
// those of a confirmed policy, so a plane whose policy is unconfirmed or
// expired, answered 200 as degraded, is refused, and a confirmed one served.
func TestServingRefusesAPolicyThatIsNotConfirmed(t *testing.T) {
	for _, freshness := range []string{"unconfirmed", "expired"} {
		_, err := scriptedPlane(t, healthDoc{pauseState: "clear", freshness: freshness}).serving(context.Background())
		if err == nil || !strings.Contains(err.Error(), "policy "+freshness) {
			t.Errorf("a plane whose policy is %s: err = %v", freshness, err)
		}
	}
	if _, err := scriptedPlane(t, healthDoc{pauseState: "clear"}).serving(context.Background()); err != nil {
		t.Errorf("a confirmed plane was refused: %v", err)
	}
}

// TestServingWaitsOutALatePauseRead: a pause state that is unknown only
// because the plane's last read aged past its bound, or because a signed
// read outran the one interval it is held to, is a read running late, read
// again until the timeout; any other unknown cause is refused at once.
func TestServingWaitsOutALatePauseRead(t *testing.T) {
	lifted := healthDoc{pauseState: "clear"}
	for _, cause := range []string{"stale", "authority unavailable"} {
		late := healthDoc{status: http.StatusServiceUnavailable, pauseState: "unknown", cause: cause}
		if s, err := scriptedPlane(t, late, late, lifted).serving(context.Background()); err != nil || s.pauseState != "clear" {
			t.Errorf("%s: a late read that catches up: %+v, %v", cause, s, err)
		}
		if _, err := scriptedPlane(t, late).serving(context.Background()); err == nil || !strings.Contains(err.Error(), "answered 503") {
			t.Errorf("%s: a read that never catches up: err = %v", cause, err)
		}
	}
	malformed := healthDoc{status: http.StatusServiceUnavailable, pauseState: "unknown", cause: "malformed"}
	if _, err := scriptedPlane(t, malformed, lifted).serving(context.Background()); err == nil || !strings.Contains(err.Error(), "answered 503") {
		t.Errorf("a pause file the plane cannot read was waited out: err = %v", err)
	}
}

// TestTheDrainBarrier: the runner reads the trail only once the spool holds
// nothing unacknowledged, and refuses a spool or exporter that lost a record,
// a plane that stops answering 200, and a spool that never drains.
func TestTheDrainBarrier(t *testing.T) {
	base := planeState{quarantined: 1, partial: 2}
	settled := healthDoc{quarantined: 1, partial: 2, pauseState: "clear"}
	withUnack := func(n int) healthDoc { d := settled; d.unack = n; return d }

	r := scriptedPlane(t, withUnack(3), withUnack(1), withUnack(0))
	if s, err := r.drained(context.Background(), base); err != nil || s.unacknowledged != 0 {
		t.Errorf("a spool that drains: %+v, %v", s, err)
	}
	for _, c := range []struct {
		name   string
		script []healthDoc
		says   string
	}{
		{"never drains", []healthDoc{withUnack(1)}, "still holds 1 unacknowledged bytes"},
		{"a quarantined record", []healthDoc{withUnack(1), {quarantined: 2, partial: 2, pauseState: "clear"}}, "quarantined 1 record"},
		{"a record a collector dropped", []healthDoc{withUnack(1), {quarantined: 1, partial: 3, pauseState: "clear"}}, "dropped 1 record(s)"},
		{"a halted plane", []healthDoc{withUnack(1), {status: http.StatusServiceUnavailable, quarantined: 1, partial: 2}}, "answered 503"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := scriptedPlane(t, c.script...).drained(context.Background(), base); err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("err = %v, want one saying %q", err, c.says)
			}
		})
	}
}

// TestThePauseReadBarrier: a pause step holds until the plane has completed
// two reads after the write and shows the state the write made; one read is
// not enough, and neither is the count without the state.
func TestThePauseReadBarrier(t *testing.T) {
	doc := func(polls int, state string, entries int) healthDoc {
		return healthDoc{polls: polls, pauseState: state, entries: entries}
	}
	if err := scriptedPlane(t, doc(5, "clear", 0), doc(6, "paused", 1), doc(7, "paused", 1)).pauseRead(context.Background(), 1); err != nil {
		t.Errorf("two reads after the write, paused: %v", err)
	}
	for _, c := range []struct {
		name    string
		script  []healthDoc
		entries int
		says    string
	}{
		{"one read only", []healthDoc{doc(5, "clear", 0), doc(6, "paused", 1)}, 1, "1 time(s) since the write, as paused with 1 entries; want 2 reads and paused with 1"},
		{"the state never changes", []healthDoc{doc(5, "clear", 0), doc(9, "clear", 0)}, 1, "as clear with 0 entries; want 2 reads and paused with 1"},
		{"another entry count", []healthDoc{doc(5, "paused", 2), doc(9, "paused", 2)}, 1, "as paused with 2 entries; want 2 reads and paused with 1"},
		{"a lift not yet read", []healthDoc{doc(5, "paused", 1), doc(9, "paused", 1)}, 0, "as paused with 1 entries; want 2 reads and clear with 0"},
		{"no pause file read", []healthDoc{doc(-1, "disabled", 0)}, 1, "counts no read of the pause file"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := scriptedPlane(t, c.script...).pauseRead(context.Background(), c.entries); err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("err = %v, want one saying %q", err, c.says)
			}
		})
	}
}
