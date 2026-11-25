//go:build unix

package main

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

// wideStopsTree is a signed stops tree whose route also stops an agent on
// REPEATED_DENIAL and, under the procedure's next version, a principal, with a
// stop of the listener's agent and of its principal, which the plane holds,
// and a stop of agent-9 and of principal admin-1, which it does not serve.
// It returns the tree and the entry ids of the two it does not hold.
func wideStopsTree(t *testing.T) (tree, []string) {
	t.Helper()
	tr, route := signedStopsTreeWith(t, widerRule{"REPEATED_DENIAL", "2", "agent", ""},
		widerRule{"REPEATED_DENIAL", "2", "principal", "4"})
	var unheld []string
	for i, c := range []struct {
		scope, subject string
		held           bool
	}{
		{reaction.ScopeAgent, "orders-assistant", true}, {reaction.ScopeAgent, "agent-9", false},
		{reaction.ScopePrincipal, "agent-runner", true}, {reaction.ScopePrincipal, "admin-1", false},
	} {
		finding := "finding-" + string(rune('1'+i))
		procedure := "3"
		if c.scope == reaction.ScopePrincipal {
			procedure = "4"
		}
		stopAt := func(now time.Time) (reaction.Stop, error) {
			created := now.UTC().Truncate(time.Second)
			return reaction.Stop{EntryID: reaction.EntryID(finding), TenantID: "acme", ProjectID: "orders", Scope: c.scope,
				Subject: c.subject, RunID: "run-1", FindingID: finding, ProcedureID: "refund", ProcedureVersion: procedure,
				ProcedureDigest: fixtureProcedure, RuleID: "REPEATED_DENIAL", RuleVersion: "2", CreatedAt: created,
				ExpiresAt: created.Add(time.Hour)}, nil
		}
		if _, _, covered, err := stopwrite.AppendFinding(context.Background(), filepath.Join(tr.dir, "stops"), route, time.Now, stopAt); err != nil || covered {
			t.Fatalf("appending the stop of %s %s: covered %v, %v", c.scope, c.subject, covered, err)
		}
		if !c.held {
			unheld = append(unheld, reaction.EntryID(finding))
		}
	}
	return tr, unheld
}

// TestTheSocketNamesEachStopsScopeAndTheUnheldByEntry: health.socket's
// answer names each stop's scope and subject, and lists by entry id the
// agent and principal stops the listener does not serve, not those of its
// own agent and principal.
func TestTheSocketNamesEachStopsScopeAndTheUnheldByEntry(t *testing.T) {
	tr, unheld := wideStopsTree(t)
	p, err := buildOneAccount(t, tr)
	if err != nil {
		t.Fatalf("build on one account = %v", err)
	}
	p.stops.poller.Poll()
	whole := p.stopsAnswer(p.stops.poller.Current(), time.Now())
	var named []string
	for _, e := range whole.Entries {
		named = append(named, e.Scope+" "+e.Subject)
	}
	want := []string{"agent orders-assistant", "agent agent-9", "principal agent-runner", "principal admin-1"}
	if !slices.Equal(named, want) {
		t.Errorf("the socket names the stops %q, want %q", named, want)
	}
	got := slices.Clone(whole.UnheldEntries)
	slices.Sort(got)
	slices.Sort(unheld)
	if !slices.Equal(got, unheld) || whole.Unheld != 2 || len(whole.UnreadEntries) != 0 {
		t.Errorf("unheld %v (%d), unread %v; want %v", whole.UnheldEntries, whole.Unheld, whole.UnreadEntries, unheld)
	}
}

// TestDoctorNamesTheWiderRulesAndTheStopsTheListenerDoesNotServe: doctor
// says which rules stop an agent or a principal, prints each such stop with
// its subject and the run it was found on, and names the two whose subject
// the listener does not serve.
func TestDoctorNamesTheWiderRulesAndTheStopsTheListenerDoesNotServe(t *testing.T) {
	placedApart(t)
	doctorPlaneOwned = true
	t.Cleanup(func() { doctorPlaneOwned = false })
	tr, _ := wideStopsTree(t)
	_, out, _, _ := doctorRun(t, tr, "reaction")
	for _, want := range []string{
		"rule REPEATED_DENIAL 2 of procedure refund 3 stops the agent for 1h0m0s",
		"rule REPEATED_DENIAL 2 of procedure refund 4 stops the principal for 1h0m0s",
		"of agent agent-9, found on run run-1, for finding",
		"of principal agent-runner, found on run run-1, for finding",
		"stop of agent agent-9: this plane serves agent orders-assistant of tenant acme, so the stop matches no call",
		"stop of principal admin-1: this plane serves principal agent-runner of tenant acme, so the stop matches no call",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor does not say %q:\n%s", want, out)
		}
	}
	for _, held := range []string{"stop of agent orders-assistant:", "stop of principal agent-runner:"} {
		if strings.Contains(out, held) {
			t.Errorf("doctor names a stop the listener serves as unheld (%q):\n%s", held, out)
		}
	}
}
