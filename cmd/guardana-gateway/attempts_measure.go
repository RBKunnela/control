package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/guardana/control/internal/attempts"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/files"
	"github.com/guardana/control/internal/gatewayconfig"
)

// maxMeasuredBytes bounds a file or binary this run takes a digest of.
const maxMeasuredBytes = 512 << 20

// demoConfig is the demo's configuration as a plane of in would resolve
// it, under a layer of keys drawn for that and dropped and a state directory
// nothing creates, as dev checks it before it starts a plane.
func demoConfig(in devInputs) (*gatewayconfig.Config, error) {
	bundleKey, err := newKey()
	if err != nil {
		return nil, err
	}
	defer clear(bundleKey)
	freshnessKey, err := newKey()
	if err != nil {
		return nil, err
	}
	defer clear(freshnessKey)
	const unbound = "127.0.0.1:0"
	silent := ""
	if in.silent {
		silent = unbound
	}
	keys := devKeys{bundle: publicHalf(bundleKey), freshness: publicHalf(freshnessKey)}
	dir := filepath.Join(os.TempDir(), brand.Gateway+"-attempts-"+rand.Text())
	socket := filepath.Join(os.TempDir(), collectDirPrefix+strings.Repeat("0", maxTempSuffix), collectSocket)
	return resolveDemo(in.config, newLayer(devState{dir: dir}, keys, unbound, unbound, socket, newToken(), silent).over(in.mode))
}

// readDemo resolves the demo's configuration under every plane's settings,
// so a plane the demo cannot make is refused before any starts, and takes
// from it the tools it declares and the victims it runs.
func (set *attemptSet) readDemo() error {
	var cfg *gatewayconfig.Config
	for _, p := range set.m.Planes {
		c, err := demoConfig(set.inputs(p))
		if err != nil {
			return fmt.Errorf("demo %s under plane %s: %w", set.m.Demo, p.ID, err)
		}
		cfg = c
	}
	set.servers = map[string]string{}
	for _, o := range cfg.Overrides {
		if server, seen := set.servers[o.Tool]; seen && server != o.Upstream {
			set.servers[o.Tool] = ""
			continue
		}
		set.servers[o.Tool] = o.Upstream
		set.declared = append(set.declared, o.Upstream+"/"+o.Tool)
	}
	slices.Sort(set.declared)
	victims := map[string]bool{}
	for _, up := range cfg.Upstreams {
		set.upstreams = append(set.upstreams, up.Name)
		if up.Command == "" {
			continue
		}
		path, err := exec.LookPath(cfg.Resolve(up.Command))
		if err != nil {
			return fmt.Errorf("the victim %s: %w", up.Name, err)
		}
		if path, err = filepath.Abs(path); err != nil {
			return err
		}
		victims[path] = true
	}
	for _, v := range slices.Sorted(maps.Keys(victims)) {
		set.binaries = append(set.binaries, attempts.FileDigest{Role: "victim", Path: v})
	}
	return nil
}

// measure takes the digest of every file the manifest names and of every
// binary the run runs: this one, the approver's and each victim.
func (set *attemptSet) measure() error {
	for _, p := range set.m.Files() {
		raw, err := files.ReadRegular(set.path(p), maxMeasuredBytes, 0)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		set.files = append(set.files, attempts.FileDigest{Path: p, SHA256: attempts.Digest(raw)})
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot locate this executable: %w", err)
	}
	set.binaries = append([]attempts.FileDigest{{Role: "gateway", Path: self}, {Role: "control", Path: set.control.path}}, set.binaries...)
	set.binaries, err = digests(set.binaries)
	return err
}

// digests is each file of in with the digest it has now.
func digests(in []attempts.FileDigest) ([]attempts.FileDigest, error) {
	out := slices.Clone(in)
	for i := range out {
		raw, err := files.ReadRegular(out[i].Path, maxMeasuredBytes, 0)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", out[i].Path, err)
		}
		out[i].SHA256 = attempts.Digest(raw)
	}
	return out, nil
}

// buildOf is what this binary's build information says of its commit. A
// build that records none, or records a modified tree, belongs to no commit.
func buildOf() attempts.Build {
	b := attempts.Build{}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return b
	}
	b.Go = info.GoVersion
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			b.Commit = s.Value
		case "vcs.modified":
			modified := s.Value == "true"
			b.Modified = &modified
		}
	}
	b.BelongsToCommit = b.Commit != "" && b.Modified != nil && !*b.Modified
	return b
}

func (set *attemptSet) header(manifest, state string, started time.Time) attempts.Header {
	h := attempts.NewHeader(set.m)
	h.Started, h.State = started.Format(time.RFC3339Nano), state
	h.Platform = runtime.GOOS + "/" + runtime.GOARCH
	h.Build = buildOf()
	h.Manifest = attempts.FileDigest{Path: manifest, SHA256: attempts.Digest(set.raw)}
	h.Files, h.Corpus = set.files, attempts.CorpusDigest(set.files)
	h.Binaries = set.binaries
	return h
}

// missingOf is what run r lacks: a journal that cannot be judged, a step
// not sent, an operator's action that did not run, a clean-up that failed.
func missingOf(r *attempts.Run) []string {
	var out []string
	for _, why := range r.JournalUnknown {
		out = append(out, "journal: "+why)
	}
	for _, s := range r.Steps {
		switch {
		case !r.Started:
		case s.Kind == "call" && !s.Sent:
			out = append(out, fmt.Sprintf("%s step %d not sent on %s: %s", r.Attempt, s.Step, r.Plane, s.NotSent))
		case s.Kind != "call" && !s.Ran:
			out = append(out, fmt.Sprintf("%s step %d did not run on %s: %s", r.Attempt, s.Step, r.Plane, s.NotRun))
		}
	}
	if r.Unfinished != "" {
		out = append(out, "unfinished: "+r.Unfinished)
	}
	return out
}

// summarize counts every run and judges whether the run is complete: not
// interrupted, every binary unchanged since the header, and one policy
// digest reported by every plane that started.
func (set *attemptSet) summarize(ctx context.Context, results []*attempts.RunResult, h attempts.Header,
	exercised map[string]bool, started time.Time) attempts.Summary {
	s := attempts.Summary{Line: "summary", Counts: attempts.Count(set.m, results), BelongsToCommit: h.Build.BelongsToCommit,
		Incomplete: []string{}}
	var digestsSeen, missing []string
	for _, res := range results {
		r := res.Run
		s.Runs.Selected++
		if r.Started {
			s.Runs.Started++
			digestsSeen = append(digestsSeen, r.PolicyDigest)
			if r.PolicyDigest == "" {
				s.Incomplete = append(s.Incomplete, "a plane reported no policy digest")
			}
		} else {
			s.Runs.NotRun++
			missing = append(missing, "not run: "+r.NotRun)
		}
		missing = append(missing, missingOf(r)...)
	}
	s.Runs.Attempts = len(set.m.Attempts)
	s.PolicyDigests = distinct(digestsSeen)
	if len(s.PolicyDigests) > 1 {
		s.Incomplete = append(s.Incomplete, "the planes reported more than one policy digest")
	}
	if ctx.Err() != nil {
		s.Incomplete = append(s.Incomplete, "interrupted")
	}
	after, err := digests(set.binaries)
	switch {
	case err != nil:
		s.Incomplete = append(s.Incomplete, "a binary could not be read after the run: "+err.Error())
	case !slices.Equal(after, set.binaries):
		s.Incomplete = append(s.Incomplete, "a binary changed during the run")
	}
	s.BinariesAfter = after
	s.Incomplete = distinct(s.Incomplete)
	s.Complete = len(s.Incomplete) == 0
	s.Exit = attempts.Exit(s.Complete, s.Counts)
	s.Scope = attempts.Scope{
		ToolsDeclared: set.declared, ToolsExercised: slices.Sorted(maps.Keys(exercised)),
		Sources: attempts.Sources, Unobserved: attempts.Unobserved, DevWiring: attempts.DevWiring, NotMeasured: attempts.NotMeasured,
		Window:  attempts.Window{From: started.Format(time.RFC3339Nano), To: time.Now().UTC().Format(time.RFC3339Nano)},
		Missing: distinct(missing), Model: set.m.Model, BrokenCopies: "not run",
	}
	if s.Scope.ToolsExercised == nil {
		s.Scope.ToolsExercised = []string{}
	}
	for _, p := range set.m.Planes {
		s.Scope.Planes = append(s.Scope.Planes, p.ID+" "+p.Mode+" "+string(p.Role)+" decision point "+p.DecisionPoint)
	}
	return s
}
