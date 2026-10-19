package hookbridge_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/guardana/control/internal/hookbridge"
)

func FuzzParseProfile(f *testing.F) {
	paths, err := filepath.Glob("profiles/*/profile.json")
	if err != nil || len(paths) == 0 {
		f.Fatalf("no built-in profile: %v", err)
	}
	for _, path := range append(paths, neutralProfile) {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: a profile this package keeps
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte(`{"kind":"hook-profile/v1alpha2"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := hookbridge.ParseProfile(raw)
		if err == nil {
			if problem := profileProblem(raw, p); problem != "" {
				t.Fatal(problem)
			}
		}
	})
}

// profileProblem names what is wrong with a profile ParseProfile accepted
// from raw: a kind it does not name whole, a reply the bridge cannot give, a
// bound outside the format's, no admit, or two values read from one member.
func profileProblem(raw []byte, p *hookbridge.Profile) string {
	var doc struct {
		Kind string `json:"kind"`
	}
	m := p.Members
	members := []string{m.Event, m.Tool, m.Input, m.CallID, m.SessionID, m.Interrupt}
	switch {
	case json.Unmarshal(raw, &doc) != nil || doc.Kind != hookbridge.Kind:
		return "accepted a document that does not name the kind " + hookbridge.Kind
	case !replyIsGiven(p.Reply):
		return "accepted a reply the bridge cannot give"
	case p.HookTimeout < time.Second || p.HookTimeout > 600*time.Second || p.MaxEventBytes < 1:
		return "accepted a bound outside the format's"
	case !slices.Contains(slices.Collect(maps.Values(p.Events)), hookbridge.PhaseAdmit):
		return "accepted a profile with no admit"
	case slices.Contains(members, "") || len(slices.Compact(slices.Sorted(slices.Values(members)))) != len(members):
		return "accepted a member read twice or not at all"
	}
	return ""
}

// replyIsGiven reports whether the bridge can give r: by exit code, with two
// statuses a process can exit with, apart from 0 and each other.
func replyIsGiven(r hookbridge.Reply) bool {
	return r.Strategy == hookbridge.StrategyExitCode && r.BlockExitCode != r.ProblemExitCode &&
		min(r.BlockExitCode, r.ProblemExitCode) >= 1 && max(r.BlockExitCode, r.ProblemExitCode) <= 125
}
