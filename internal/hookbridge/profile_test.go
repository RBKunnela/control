package hookbridge_test

import (
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/hookbridge"
)

const neutralProfile = "testdata/neutral/profile.json"

func neutral(t testing.TB) *hookbridge.Profile {
	t.Helper()
	p, err := hookbridge.ReadProfileFile(neutralProfile)
	if err != nil {
		t.Fatalf("the neutral profile: %v", err)
	}
	return p
}

func TestTheNeutralProfileIsReadAsWritten(t *testing.T) {
	p := neutral(t)
	wantEvents := map[string]hookbridge.Phase{"BeforeTool": "admit", "AfterTool": "complete", "AfterToolFailed": "complete-failure"}
	switch {
	case p.ID != "neutral" || p.HookTimeout != 30*time.Second || p.MaxEventBytes != 4096:
		t.Fatalf("profile %+v", p)
	case len(p.Events) != len(wantEvents):
		t.Fatalf("events %v", p.Events)
	case p.Members != hookbridge.Members{Event: "event", Tool: "tool", Input: "input", CallID: "call", SessionID: "session", Interrupt: "interrupted"}:
		t.Fatalf("members %+v", p.Members)
	case p.Reply != hookbridge.Reply{Strategy: "exit-code", BlockExitCode: 2, ProblemExitCode: 1}:
		t.Fatalf("reply %+v", p.Reply)
	}
	for name, phase := range wantEvents {
		if p.Events[name] != phase {
			t.Errorf("event %s is %q, want %q", name, p.Events[name], phase)
		}
	}
}

func TestTheNeutralProfilesClaimsAreReadAsWritten(t *testing.T) {
	want := hookbridge.Claims{
		Runtime:    hookbridge.RuntimeClaim{Name: "Neutral Runner", TestedVersions: []string{"1.0.0"}, BackedBy: []string{"admit-plain"}},
		FailClosed: hookbridge.FailClosedClaim{Setting: "on_hook_failure=block", MinVersion: "1.0.0", BackedBy: []string{}},
		Pending:    hookbridge.TextClaim{Text: "deny-with-reason", BackedBy: []string{"pending"}},
		CallID:     hookbridge.FlagClaim{Holds: true, BackedBy: []string{"admit-plain", "complete-plain"}},
		ToolsSeen:  hookbridge.ListClaim{Items: []string{"refund", "read_file"}, BackedBy: []string{}},
		Bypasses:   []hookbridge.TextClaim{{Text: "a process the tool starts is not seen", BackedBy: []string{}}},
		Page:       "docs/reference/neutral.md",
	}
	if got := neutral(t).Claims; !reflect.DeepEqual(got, want) {
		t.Fatalf("claims %+v, want %+v", got, want)
	}
}

// edit returns the neutral profile with was replaced by now, once.
func edit(t *testing.T, was, now string) []byte {
	t.Helper()
	raw, err := os.ReadFile(neutralProfile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), was) != 1 {
		t.Fatalf("%q is not in the neutral profile exactly once", was)
	}
	return []byte(strings.Replace(string(raw), was, now, 1))
}

func TestAProfileIsReadStrictly(t *testing.T) {
	for _, tc := range []struct {
		name, old, new string
		want           error
	}{
		{"another version of the format", `"hook-profile/v1alpha1"`, `"hook-profile/v2"`, hookbridge.ErrProfileVersion},
		{"another format", `"hook-profile/v1alpha1"`, `"agent-policy/v1alpha1"`, hookbridge.ErrProfile},
		{"an unknown member", `"id": "neutral",`, `"id": "neutral", "replace": "whole",`, hookbridge.ErrProfile},
		{"a member named twice", `"id": "neutral",`, `"id": "neutral", "id": "other",`, hookbridge.ErrProfile},
		{"no id", `"id": "neutral",`, ``, hookbridge.ErrProfile},
		{"an id with a path in it", `"id": "neutral",`, `"id": "../neutral",`, hookbridge.ErrProfile},
		{"a phase the format lacks", `"AfterTool": "complete",`, `"AfterTool": "observe",`, hookbridge.ErrProfile},
		{"no admitting event", `"BeforeTool": "admit",`, `"BeforeTool": "complete",`, hookbridge.ErrProfile},
		{"an unknown member of members", `"interrupted"`, `"interrupted", "agent": "agent"`, hookbridge.ErrProfile},
		{"two values in one member", `"call_id": "call"`, `"call_id": "tool"`, hookbridge.ErrProfile},
		{"no interrupt member", `,
    "interrupt": "interrupted"`, ``, hookbridge.ErrProfile},
		{"another reply strategy", `"exit-code"`, `"json"`, hookbridge.ErrProfile},
		{"one exit code for both", `"problem_exit_code": 1`, `"problem_exit_code": 2`, hookbridge.ErrProfile},
		{"exit code zero", `"block_exit_code": 2`, `"block_exit_code": 0`, hookbridge.ErrProfile},
		{"an exit code past 125", `"block_exit_code": 2`, `"block_exit_code": 126`, hookbridge.ErrProfile},
		{"an exit code as a string", `"block_exit_code": 2`, `"block_exit_code": "2"`, hookbridge.ErrProfile},
		{"a timeout as a fraction", `"hook_timeout_seconds": 30`, `"hook_timeout_seconds": 30.0`, hookbridge.ErrProfile},
		{"a timeout past its bound", `"hook_timeout_seconds": 30`, `"hook_timeout_seconds": 601`, hookbridge.ErrProfile},
		{"no event bound", `"max_event_bytes": 4096`, `"max_event_bytes": 0`, hookbridge.ErrProfile},
		{"an event bound past its cap", `"max_event_bytes": 4096`, `"max_event_bytes": 67108865`, hookbridge.ErrProfile},
		{"a pending way the format lacks", `"deny-with-reason"`, `"defer"`, hookbridge.ErrProfile},
		{"backed_by null", `"fail_closed": {"setting": "on_hook_failure=block", "min_version": "1.0.0", "backed_by": []}`, `"fail_closed": {"setting": "on_hook_failure=block", "min_version": "1.0.0", "backed_by": null}`, hookbridge.ErrProfile},
		{"a case id that is not a string", `"backed_by": ["pending"]`, `"backed_by": [7]`, hookbridge.ErrProfile},
		{"call_id as a string", `"call_id": {"value": true`, `"call_id": {"value": "true"`, hookbridge.ErrProfile},
		{"an unknown claim", `"page": "docs/reference/neutral.md"`, `"page": "docs/reference/neutral.md", "replace": {"value": "whole", "backed_by": []}`, hookbridge.ErrProfile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hookbridge.ParseProfile(edit(t, tc.old, tc.new))
			if !errors.Is(err, tc.want) {
				t.Fatalf("ParseProfile = %v, want %v", err, tc.want)
			}
			if errors.Is(tc.want, hookbridge.ErrProfileVersion) && errors.Is(err, hookbridge.ErrProfile) {
				t.Fatalf("another version read as a malformed profile: %v", err)
			}
		})
	}
}

func TestTheBoundsOfAProfileAreInclusive(t *testing.T) {
	for _, tc := range []struct{ old, new string }{
		{`"hook_timeout_seconds": 30`, `"hook_timeout_seconds": 600`},
		{`"max_event_bytes": 4096`, `"max_event_bytes": 67108864`},
		{`"block_exit_code": 2`, `"block_exit_code": 125`},
	} {
		if _, err := hookbridge.ParseProfile(edit(t, tc.old, tc.new)); err != nil {
			t.Errorf("%s refused: %v", tc.new, err)
		}
	}
}

// A profile is padded with white space after its object, which nothing else
// bounds, to land exactly on its 64 KiB bound and one byte past it.
func TestAProfileIsBoundedAt64KiB(t *testing.T) {
	raw, err := os.ReadFile(neutralProfile)
	if err != nil {
		t.Fatal(err)
	}
	at := append(raw, []byte(strings.Repeat(" ", 64<<10-len(raw)))...)
	over := append(slices.Clone(at), ' ')
	if _, err := hookbridge.ParseProfile(at); err != nil {
		t.Fatalf("a profile of exactly 64 KiB: %v", err)
	}
	if _, err := hookbridge.ParseProfile(over); !errors.Is(err, hookbridge.ErrProfile) {
		t.Fatalf("ParseProfile of one byte more = %v", err)
	}
	dir := t.TempDir()
	for name, body := range map[string][]byte{"at.json": at, "over.json": over} {
		if err := os.WriteFile(dir+"/"+name, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hookbridge.ReadProfileFile(dir + "/at.json"); err != nil {
		t.Fatalf("a file of exactly 64 KiB: %v", err)
	}
	if _, err := hookbridge.ReadProfileFile(dir + "/over.json"); !errors.Is(err, hookbridge.ErrProfile) {
		t.Fatalf("ReadProfileFile of one byte more = %v", err)
	}
}

func TestAnIDNoBuiltInProfileHasIsRefused(t *testing.T) {
	for _, id := range []string{"neutral", "../testdata/neutral", "", "Neutral"} {
		if _, err := hookbridge.LoadProfile(id); !errors.Is(err, hookbridge.ErrUnknownProfile) {
			t.Errorf("LoadProfile(%q) = %v, want ErrUnknownProfile", id, err)
		}
	}
}
