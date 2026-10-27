package hookbridge_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guardana/control/internal/hookbridge"
)

// The statuses the runtime acts on and the timeout it gives the hook are
// stated in the cases apart from the profile: a block status the runtime
// does not block on would let every denied call run.
func TestEachBuiltInProfileRepliesAsItsCasesSay(t *testing.T) {
	for _, s := range suites(t) {
		p := s.profile
		if p.Reply.BlockExitCode != s.BlockExitCode || p.Reply.ProblemExitCode != s.ProblemExitCode ||
			p.HookTimeout != time.Duration(s.HookTimeoutSeconds)*time.Second {
			t.Errorf("%s: the profile blocks with %d, reports a problem with %d and assumes %v; its cases say %d, %d and %ds",
				s.dir, p.Reply.BlockExitCode, p.Reply.ProblemExitCode, p.HookTimeout, s.BlockExitCode, s.ProblemExitCode, s.HookTimeoutSeconds)
		}
	}
}

// A completion is padded with a member no profile reads, ahead of all the
// others, to the bound its cases state and one byte past it.
func TestEachBuiltInProfileBoundsAnEventAsItsCasesSay(t *testing.T) {
	for _, s := range suites(t) {
		for _, m := range s.boundMisses(t) {
			t.Errorf("%s: %s", s.dir, m)
		}
	}
}

func (s *profileSuite) boundMisses(t *testing.T) []string {
	const pad = "padding"
	p := s.profile
	if p.MaxEventBytes != s.MaxEventBytes {
		return []string{fmt.Sprintf("the profile bounds an event at %d, its cases at %d", p.MaxEventBytes, s.MaxEventBytes)}
	}
	m := p.Members
	if slices.Contains([]string{m.Event, m.Tool, m.Input, m.CallID, m.SessionID, m.Interrupt}, pad) {
		return []string{"the profile reads the member this test pads with"}
	}
	raw := bytes.TrimRight(s.fixture(t, s.BoundFrom), "\n")
	head := `{"` + pad + `":"`
	fill := int(s.MaxEventBytes) - len(head) - len(`",`) - (len(raw) - 1)
	if len(raw) == 0 || raw[0] != '{' || fill < 0 {
		return []string{s.BoundFrom + " cannot be padded to the bound"}
	}
	at := []byte(head + strings.Repeat("x", fill) + `",` + string(raw[1:]))
	var miss []string
	ev, err := hookbridge.ReadEvent(p, bytes.NewReader(at))
	check(&miss, int64(len(at)) != s.MaxEventBytes || err != nil || string(ev.Input) != s.Cases[s.BoundFrom].Input,
		"an event of %d bytes: %v", len(at), err)
	over := append([]byte(head+"x"), at[len(head):]...)
	_, err = hookbridge.ReadEvent(p, bytes.NewReader(over))
	check(&miss, !errors.Is(err, hookbridge.ErrEventTooLarge), "one byte more = %v", err)
	return miss
}

// qualificationPrefix marks a claim's case as one of the profile's
// qualification against the real runtime rather than a fixture.
const qualificationPrefix = "qualification/"

// qualificationResults is what a results file of a profile's qualification
// holds that the claims are judged by.
type qualificationResults struct {
	Runtime        string `json:"runtime"`
	RuntimeVersion string `json:"runtime_version"`
	BridgeCommit   string `json:"bridge_commit"`
	TreeDirty      string `json:"tree_dirty"`
	Cases          []struct {
		ID      string `json:"id"`
		Verdict string `json:"verdict"`
	} `json:"cases"`
}

// positiveControls are the cases a results file must pass itself before any
// other pass it records counts: the bridge lets a call run and blocks one
// through the recorder, and a bridge that lets every call run is caught. A
// rerun of a few cases holds none of them, so it backs nothing.
var positiveControls = []string{"allow", "block", "control-allow-all"}

// passedOn reads the results files in dir's qualification directory, named
// for the runtime's version, and returns every case one of them records as
// passed, with its positive controls passed in the same file, and none as
// failed. A file from the stub runtime, for a version tested does not list,
// from a tree with changes or from no named commit is refused.
func passedOn(dir string, tested []string) (map[string]bool, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "qualification", "[0-9]*.json"))
	if err != nil {
		return nil, err
	}
	passed, failed := map[string]bool{}, map[string]bool{}
	for _, path := range paths {
		r, err := readResults(path, tested)
		if err != nil {
			return nil, err
		}
		here := map[string]bool{}
		for _, c := range r.Cases {
			switch c.Verdict {
			case "pass":
				here[c.ID] = true
			case "fail":
				failed[c.ID] = true
			}
		}
		if !slices.ContainsFunc(positiveControls, func(id string) bool { return !here[id] }) {
			maps.Copy(passed, here)
		}
	}
	for id := range failed {
		delete(passed, id)
	}
	return passed, nil
}

// readResults reads one results file, refusing one that holds no case, comes
// from the stub runtime, is for a version tested does not list, or ran a
// bridge built from a tree with changes or from no named commit.
func readResults(path string, tested []string) (qualificationResults, error) {
	var r qualificationResults
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a results file this package keeps
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, fmt.Errorf("%s: %w", path, err)
	}
	version, _, _ := strings.Cut(r.RuntimeVersion, " ")
	switch {
	case len(r.Cases) == 0:
		return r, fmt.Errorf("%s holds no cases", path)
	case r.Runtime == "" || r.Runtime == "stub":
		return r, fmt.Errorf("%s is not a run on the runtime", path)
	case !slices.Contains(tested, version):
		return r, fmt.Errorf("%s is for version %q, which the profile does not list as tested", path, version)
	case r.TreeDirty != "false":
		return r, fmt.Errorf("%s ran a bridge from a tree whose changes were %q, not none", path, r.TreeDirty)
	case !commitName.MatchString(r.BridgeCommit):
		return r, fmt.Errorf("%s names the bridge's commit as %q", path, r.BridgeCommit)
	}
	return r, nil
}

var commitName = regexp.MustCompile(`^[0-9a-f]{40}$`)

func passedOnTheRuntime(t *testing.T, dir string, tested []string) map[string]bool {
	t.Helper()
	passed, err := passedOn(dir, tested)
	if err != nil {
		t.Fatal(err)
	}
	return passed
}

// A case backs a claim only when a run on the runtime, for a version the
// profile lists as tested, of a clean tree at a named commit, passed it beside
// its positive controls and no such run failed it.
func TestOnlyACasePassedOnATestedRuntimeBacksAClaim(t *testing.T) {
	write := func(t *testing.T, dir, name, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, "qualification"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "qualification", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const (
		commit   = `"bridge_commit":"0123456789abcdef0123456789abcdef01234567"`
		head     = `{"runtime":"rt","runtime_version":"1.2.3 (Runtime)",` + commit + `,"tree_dirty":"false","cases":`
		controls = `{"id":"allow","verdict":"pass"},{"id":"block","verdict":"pass"},{"id":"control-allow-all","verdict":"pass"},`
	)
	dir := t.TempDir()
	write(t, dir, "1.2.3.json", head+`[`+controls+`{"id":"a","verdict":"pass"},{"id":"b","verdict":"pass"},{"id":"c","verdict":"unknown"}]}`)
	write(t, dir, "1.2.3-rerun.json", head+`[`+controls+`{"id":"b","verdict":"fail"},{"id":"c","verdict":"pass"}]}`)
	write(t, dir, "1.2.3-few.json", head+`[{"id":"allow","verdict":"pass"},{"id":"block","verdict":"pass"},{"id":"d","verdict":"pass"}]}`)
	write(t, dir, "settings.json", `{"hooks":{}}`)
	passed, err := passedOn(dir, []string{"1.2.3"})
	want := map[string]bool{"allow": true, "block": true, "control-allow-all": true, "a": true, "c": true}
	if err != nil || !maps.Equal(passed, want) {
		t.Fatalf("passed %v, %v; want %v: b failed on a rerun, d passed where control-allow-all did not", passed, err, want)
	}
	for name, body := range map[string]string{
		"a stub run":            `{"runtime":"stub","runtime_version":"1.2.3",` + commit + `,"tree_dirty":"false","cases":[{"id":"a","verdict":"pass"}]}`,
		"an untested version":   `{"runtime":"rt","runtime_version":"9.9.9 (Runtime)",` + commit + `,"tree_dirty":"false","cases":[{"id":"a","verdict":"pass"}]}`,
		"no runtime":            `{"runtime_version":"1.2.3",` + commit + `,"tree_dirty":"false","cases":[{"id":"a","verdict":"pass"}]}`,
		"no cases":              head + `[]}`,
		"a file that is not it": `not json`,
		"a tree with changes":   `{"runtime":"rt","runtime_version":"1.2.3",` + commit + `,"tree_dirty":"true","cases":[` + controls + `{"id":"a","verdict":"pass"}]}`,
		"changes not known":     `{"runtime":"rt","runtime_version":"1.2.3",` + commit + `,"tree_dirty":"unknown","cases":[` + controls + `{"id":"a","verdict":"pass"}]}`,
		"no tree state":         `{"runtime":"rt","runtime_version":"1.2.3",` + commit + `,"cases":[` + controls + `{"id":"a","verdict":"pass"}]}`,
		"no commit":             `{"runtime":"rt","runtime_version":"1.2.3","bridge_commit":"unknown","tree_dirty":"false","cases":[` + controls + `{"id":"a","verdict":"pass"}]}`,
	} {
		dir := t.TempDir()
		write(t, dir, "1.2.3.json", body)
		if passed, err := passedOn(dir, []string{"1.2.3"}); err == nil {
			t.Errorf("%s: passed %v, want a refusal", name, passed)
		}
	}
}

// unbacked returns every case id the claims name that is neither a fixture
// of the profile's directory nor, after qualificationPrefix, a case its
// qualification passed on the runtime.
func unbacked(dir string, c hookbridge.Claims, passed map[string]bool) []string {
	ids := append([]string{}, c.Runtime.BackedBy...)
	ids = append(ids, c.FailClosed.BackedBy...)
	ids = append(ids, c.Pending.BackedBy...)
	ids = append(ids, c.CallID.BackedBy...)
	ids = append(ids, c.ToolsSeen.BackedBy...)
	for _, b := range c.Bypasses {
		ids = append(ids, b.BackedBy...)
	}
	var missing []string
	for _, id := range ids {
		if q, ok := strings.CutPrefix(id, qualificationPrefix); ok {
			if !passed[q] {
				missing = append(missing, id)
			}
			continue
		}
		_, err := os.Stat(filepath.Join(dir, "fixtures", id+".json"))
		if strings.ContainsAny(id, `/.`) || err != nil {
			missing = append(missing, id)
		}
	}
	return missing
}

func TestEveryClaimOfABuiltInProfileIsBackedByACase(t *testing.T) {
	paths, err := filepath.Glob("profiles/*/profile.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no built-in profile: %v", err)
	}
	for _, path := range paths {
		dir := filepath.Dir(path)
		p, err := hookbridge.LoadProfile(filepath.Base(dir))
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if missing := unbacked(dir, p.Claims, passedOnTheRuntime(t, dir, p.Claims.Runtime.TestedVersions)); len(missing) != 0 {
			t.Errorf("%s: claims name cases that do not exist or did not pass: %v", dir, missing)
		}
	}
}

// The first case id of each built-in profile's claims is replaced by one
// that names no fixture, by a path to one that does, and by a qualification
// case that no results file records as passed; a passed one is backed.
func TestAClaimNamingNoFixtureIsCaught(t *testing.T) {
	for _, s := range suites(t) {
		passed := passedOnTheRuntime(t, s.dir, s.profile.Claims.Runtime.TestedVersions)
		raw, err := os.ReadFile(filepath.Join(s.dir, "profile.json"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(`"`+qualificationPrefix)) && len(passed) == 0 {
			t.Fatalf("%s: claims cite the qualification, and no case of it passed", s.dir)
		}
		const member = `"backed_by": ["`
		at := bytes.Index(raw, []byte(member))
		if at < 0 {
			t.Fatalf("%s: no claim names a case", s.dir)
		}
		start := at + len(member)
		end := start + bytes.IndexByte(raw[start:], '"')
		doctor := func(id string) hookbridge.Claims {
			p, err := hookbridge.ParseProfile(append(append(bytes.Clone(raw[:start]), id...), raw[end:]...))
			if err != nil {
				t.Fatal(err)
			}
			return p.Claims
		}
		plantedClaims(t, s.dir, string(raw[start:end]), doctor, passed)
	}
}

// plantedClaims checks unbacked against claims whose first case id doctor
// replaces: an absent case, a path to a real fixture and an absent
// qualification case are each reported alone; a passed qualification case is
// backed, and unbacked when nothing passed.
func plantedClaims(t *testing.T, dir, first string, doctor func(string) hookbridge.Claims, passed map[string]bool) {
	t.Helper()
	for _, id := range []string{"absent-case", "../fixtures/" + first, qualificationPrefix + "absent-case"} {
		if missing := unbacked(dir, doctor(id), passed); len(missing) != 1 || missing[0] != id {
			t.Errorf("%s: a claim backed by %q: unbacked %v", dir, id, missing)
		}
	}
	for name := range passed {
		id := qualificationPrefix + name
		if missing := unbacked(dir, doctor(id), passed); len(missing) != 0 {
			t.Errorf("%s: a claim backed by the passed %q: unbacked %v", dir, id, missing)
		}
		if missing := unbacked(dir, doctor(id), map[string]bool{}); !slices.Contains(missing, id) {
			t.Errorf("%s: a claim backed by %q, which passed nowhere: unbacked %v", dir, id, missing)
		}
		break
	}
}
