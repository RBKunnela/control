package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/guardana/control/internal/attempts"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/scenario"
)

// victimJournalVariable is the variable the demo's victims read, at their
// start, for the directory they append their journals to; demo.yaml passes
// it from the plane's environment to each victim.
const victimJournalVariable = "VICTIM_JOURNAL_DIR"

// runOne runs attempt a on a plane of configuration p, laid out under dir
// for this run alone with a journal directory of its own, sends every call
// step in order whatever the earlier answers were, stops the plane, and
// reads the victims' journals once the plane has let them go.
func (set *attemptSet) runOne(ctx context.Context, a attempts.Attempt, p attempts.Plane, rep int, dir string) *attempts.Run {
	s := set.scenarios[a.Scenario]
	run := &attempts.Run{Attempt: a.ID, Plane: p.ID, Repetition: rep, Journals: map[string]*attempts.Journal{}, JournalUnknown: map[string]string{}}
	for i, st := range s.Steps {
		run.Steps = append(run.Steps, set.stepOf(a, i, st))
	}
	if err := ctx.Err(); err != nil {
		run.NotRun = "interrupted before it started"
		return run
	}
	journals, log, err := layOut(dir)
	if err != nil {
		run.NotRun = err.Error()
		return run
	}
	defer func() { _ = log.Close() }()
	restore, err := setVictimJournal(journals)
	if err != nil {
		run.NotRun = err.Error()
		return run
	}
	defer restore()
	d, err := startDevPlane(ctx, set.inputs(p), filepath.Join(dir, "state"), log)
	if err != nil {
		run.NotRun = "its plane did not start: " + err.Error()
		return run
	}
	set.drive(ctx, d, s, p, run)
	stopped := ""
	select {
	case <-d.done:
		stopped = "its plane stopped while the attempt ran"
	default:
	}
	if _, err := d.halt(); err != nil && stopped == "" {
		stopped = "its plane did not stop cleanly, so its victims may not have exited: " + err.Error()
	}
	set.readJournals(run, journals, stopped)
	return run
}

// layOut makes the run's directory, its journal directory and its plane log.
func layOut(dir string) (string, *os.File, error) {
	journals := filepath.Join(dir, "journal")
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", nil, err
	}
	if err := os.Mkdir(journals, 0o700); err != nil {
		return "", nil, err
	}
	log, err := os.OpenFile(filepath.Join(dir, "plane.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a file in the directory this run made
	return journals, log, err
}

// readJournals reads each server's journal, or records why it cannot be
// judged: every one, when the plane did not stop as it should have.
func (set *attemptSet) readJournals(run *attempts.Run, journals, stopped string) {
	for _, server := range set.upstreams {
		if stopped != "" {
			run.JournalUnknown[server] = stopped
			continue
		}
		j, err := attempts.ReadJournal(filepath.Join(journals, server+".jsonl"))
		if err != nil {
			run.JournalUnknown[server] = err.Error()
			continue
		}
		run.Journals[server] = j
	}
}

// setVictimJournal points the victims a plane starts next at dir, and
// returns what puts the variable back as it was.
func setVictimJournal(dir string) (func(), error) {
	old, had := os.LookupEnv(victimJournalVariable)
	if err := os.Setenv(victimJournalVariable, dir); err != nil {
		return nil, err
	}
	return func() {
		if had {
			_ = os.Setenv(victimJournalVariable, old)
			return
		}
		_ = os.Unsetenv(victimJournalVariable)
	}, nil
}

// stepOf is step i of the scenario as the run starts it: labelled, with the
// server the demo declares for a call's tool and the answer the scenario
// expects, and not yet sent or run.
func (set *attemptSet) stepOf(a attempts.Attempt, i int, st scenario.Step) attempts.StepRun {
	l := a.LabelOf(i)
	sr := attempts.StepRun{Step: i, Label: l.Label, Effects: l.Effects, Kind: stepKind(st)}
	if c := st.Call; c != nil {
		sr.Tool, sr.Server = c.Tool, set.servers[c.Tool]
		sr.WantAnswer, sr.WantCodes = string(c.Answer.Kind), c.Answer.Codes
		sr.NotSent = "the attempt did not reach it"
	} else {
		sr.NotRun = "the attempt did not reach it"
	}
	return sr
}

// drive connects to the plane as the scenario runner does and tries every
// step in order. A plane that is not in the mode, or not as clear, the
// attempt starts from leaves the run not started.
func (set *attemptSet) drive(ctx context.Context, d *devPlane, s *scenario.Scenario, p attempts.Plane, run *attempts.Run) {
	target, err := targetOf(d.cfg)
	if err != nil {
		run.NotRun = err.Error()
		return
	}
	target.operatorKey, target.inbox = d.state.operatorKeyFile(), d.state.path(stateInbox)
	r := &runner{plane: target, control: set.control, timeout: defaultScenarioTimeout, http: &http.Client{}, out: io.Discard}
	h, err := r.serving(ctx)
	switch {
	case err != nil:
		run.NotRun = err.Error()
		return
	case h.mode != p.Mode:
		run.NotRun = fmt.Sprintf("the plane runs in %s, and its configuration names %s", h.mode, p.Mode)
		return
	case h.pauseState != pause.Clear.String() && h.pauseState != pause.Disabled.String():
		run.NotRun = "the plane's pause state is " + h.pauseState
		return
	}
	run.PolicyDigest = h.digest
	pl := &play{r: r, s: s, added: map[int]string{}, requests: make([]string, len(s.Steps)), answers: make([]answered, len(s.Steps))}
	client := sdk.NewClient(&sdk.Implementation{Name: brand.Gateway + "-attempts", Version: version}, nil)
	connect, cancel := context.WithTimeout(ctx, r.timeout)
	pl.session, err = client.Connect(connect, &sdk.StreamableClientTransport{Endpoint: target.mcpURL},
		&sdk.ClientSessionOptions{ProtocolVersion: target.protocol})
	cancel()
	if err != nil {
		run.NotRun = "connecting to the plane's listener: " + err.Error()
		return
	}
	run.Started = true
	for i, st := range s.Steps {
		sr := &run.Steps[i]
		if st.Call != nil {
			pl.send(ctx, i, st.Call, sr)
			continue
		}
		sr.NotRun = ""
		if err := pl.operate(ctx, i, st); err != nil {
			sr.NotRun = err.Error()
			continue
		}
		sr.Ran = true
	}
	if err := pl.finish(ctx); err != nil {
		run.Unfinished = err.Error()
	}
}

// send makes call step i whatever earlier answers were. A reference to an
// earlier output the run does not have leaves the step not sent.
func (p *play) send(ctx context.Context, i int, c *scenario.Call, sr *attempts.StepRun) {
	args, err := p.arguments(i, c)
	if err != nil {
		sr.NotSent = "input missing: " + err.Error()
		return
	}
	sr.NotSent = ""
	if sr.Args, err = attempts.ParseValue(args); err != nil {
		sr.NotSent = "the arguments cannot be compared with a journal: " + err.Error()
		return
	}
	call, cancel := context.WithTimeout(ctx, p.r.plane.callTimeout+p.r.timeout)
	res, callErr := p.session.CallTool(call, &sdk.CallToolParams{Name: c.Tool, Arguments: json.RawMessage(args)})
	cancel()
	sr.Sent = true
	a, err := classify(res, callErr)
	if err != nil {
		sr.AnswerUnknown = err.Error()
		return
	}
	p.answers[i] = a
	sr.Answer, sr.Codes = string(a.kind), slices.Clone(a.codes)
}

// operate runs operator step i through the approver's binary, as the
// scenario runner does.
func (p *play) operate(ctx context.Context, i int, st scenario.Step) error {
	switch {
	case st.Approve != nil:
		return p.answer(ctx, "approve", st.Approve)
	case st.Reject != nil:
		return p.answer(ctx, "reject", st.Reject)
	case st.Pause != nil:
		return p.pause(ctx, i, st.Pause)
	case st.Unpause != nil:
		return p.unpause(ctx, st.Unpause)
	}
	return errors.New("the step is neither a call nor an operator's action")
}
