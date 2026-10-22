package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/scenario"
)

// play is one scenario under way: the plane as it was before the first step,
// the requests the trail file held then, and what each step showed.
type play struct {
	r       *runner
	s       *scenario.Scenario
	session *sdk.ClientSession
	base    planeState
	before  map[string]bool
	// events is the distinct events the trail file held at its last read, and
	// lengths each trail's length then.
	events  int
	lengths map[trailScope]int
	// calls is the call steps made, each of which is one admission.
	calls uint64
	// requests and answers are per step, empty for a step that is no call.
	requests []string
	answers  []answered
	// added is the pause entry each pause step added and no unpause removed.
	added   map[int]string
	entries int
	named   bool
}

// start holds the plane to what the scenario starts from, waits for what the
// plane still has to ship, notes the requests the trail file holds and the
// counters every step is judged against, and connects.
func (p *play) start(ctx context.Context) error {
	h, err := p.r.serving(ctx)
	if err != nil {
		return err
	}
	want := p.s.Plane
	switch {
	case h.mode != want.Mode:
		return fmt.Errorf("the plane runs in %s, and the scenario is for %s", h.mode, want.Mode)
	case h.bundleID != want.BundleID:
		return fmt.Errorf("the plane serves bundle %s, and the scenario is for %s", h.bundleID, want.BundleID)
	case want.BundleDigest != "" && h.digest != want.BundleDigest:
		return fmt.Errorf("the plane serves bundle digest %s, and the scenario is for %s", h.digest, want.BundleDigest)
	case h.pauseState != pause.Clear.String() && h.pauseState != pause.Disabled.String():
		return fmt.Errorf("the plane's pause state is %s with %d entries, and a scenario starts with nothing paused", h.pauseState, h.entries)
	}
	if p.base, err = p.r.drained(ctx, h); err != nil {
		return err
	}
	read, err := readTrail(p.r.trail, true)
	if err != nil {
		return err
	}
	p.before, p.events, p.lengths = read.requests(), read.events, read.lengths()
	client := sdk.NewClient(&sdk.Implementation{Name: brand.Gateway + "-scenario", Version: version}, nil)
	connect, cancel := context.WithTimeout(ctx, p.r.timeout)
	defer cancel()
	p.session, err = client.Connect(connect, &sdk.StreamableClientTransport{Endpoint: p.r.plane.mcpURL},
		&sdk.ClientSessionOptions{ProtocolVersion: p.r.plane.protocol})
	if err != nil {
		return fmt.Errorf("connecting to the plane's listener: %w", err)
	}
	return nil
}

// step runs step i.
func (p *play) step(ctx context.Context, i int) ([]difference, error) {
	p.requests, p.answers = append(p.requests, ""), append(p.answers, answered{})
	st := p.s.Steps[i]
	switch {
	case st.Call != nil:
		return p.call(ctx, i, st.Call)
	case st.Approve != nil:
		return nil, p.answer(ctx, "approve", st.Approve)
	case st.Reject != nil:
		return nil, p.answer(ctx, "reject", st.Reject)
	case st.Pause != nil:
		return nil, p.pause(ctx, i, st.Pause)
	}
	return nil, p.unpause(ctx, st.Unpause)
}

func (p *play) call(ctx context.Context, i int, c *scenario.Call) ([]difference, error) {
	args, err := p.arguments(i, c)
	if err != nil {
		return nil, err
	}
	// Arguments canon cannot hash have no hash, and the recorded proposal is
	// held to that: a plane that recorded one differs on args.
	sentHash, hashErr := canon.ArgumentsHashV1(args)
	if hashErr != nil {
		sentHash = ""
	}
	h, err := p.r.serving(ctx)
	if err != nil {
		return nil, err
	}
	call, cancel := context.WithTimeout(ctx, p.r.plane.callTimeout+p.r.timeout)
	res, callErr := p.session.CallTool(call, &sdk.CallToolParams{Name: c.Tool, Arguments: json.RawMessage(args)})
	cancel()
	a, err := classify(res, callErr)
	if err != nil {
		return nil, err
	}
	trail, others, err := p.shipped(ctx, h, a.requestID)
	if err != nil {
		return nil, err
	}
	seen := callSeen{answer: a, trail: trail, others: others, request: requestOf(a.requestID, c.Trail.Request, p.requests[:i], p.before)}
	facts := planeFacts{mode: p.base.mode, digest: p.base.digest, fresh: p.calls == 1 && p.s.Run == scenario.RunFresh, sentHash: sentHash}
	diffs, err := judgeCall(i, c, seen, facts)
	p.requests[i], p.answers[i] = a.requestID, a
	return diffs, err
}

// arguments are call step i's arguments with the text of each earlier
// result put in. A reference to an answer that has no text cannot run, and
// says why.
func (p *play) arguments(i int, c *scenario.Call) ([]byte, error) {
	outputs := map[int]string{}
	var missing []string
	for k, a := range p.answers[:i] {
		switch {
		case a.kind == "":
		case a.noOutput == "":
			outputs[k] = a.output
		default:
			missing = append(missing, fmt.Sprintf("step[%d]: %s", k, a.noOutput))
		}
	}
	args, err := c.Arguments(outputs)
	if err != nil {
		return nil, fmt.Errorf("%w (%s)", err, strings.Join(missing, "; "))
	}
	return args, nil
}

// shipped waits until the plane has shipped what the call wrote, holds the
// plane to one admission per call step and the trail file to being the
// plane's, and returns the trail of request in link order and every other
// request whose trail grew since the last read. before is the plane as it was
// just before the call.
func (p *play) shipped(ctx context.Context, before planeState, request string) ([]*controlv1.Event, []string, error) {
	after, err := p.r.drained(ctx, p.base)
	if err != nil {
		return nil, nil, err
	}
	p.calls++
	if grew := after.admitted - p.base.admitted; grew != p.calls {
		return nil, nil, fmt.Errorf("the plane admitted %d call(s) since the scenario began and this runner made %d: another client is calling", grew, p.calls)
	}
	read, err := readTrail(p.r.trail, false)
	if err != nil {
		return nil, nil, err
	}
	if after.acknowledged > before.acknowledged && read.events == p.events {
		return nil, nil, fmt.Errorf("the plane shipped %d record(s) and the trail file %s holds none of them: it is not this plane's",
			after.acknowledged-before.acknowledged, p.r.trail)
	}
	others := read.grewBesides(p.lengths, request)
	p.events, p.lengths = read.events, read.lengths()
	trail, err := read.trail(request)
	if err != nil {
		return nil, nil, err
	}
	p.name(trail)
	return trail, others, nil
}

// name prints, once, the principal and agent the first proposal names, which
// is the identity the plane took from its listener.
func (p *play) name(trail []*controlv1.Event) {
	for _, ev := range trail {
		if env := ev.GetProposed(); !p.named && env != nil {
			p.named = true
			p.r.line(p.s, fmt.Sprintf("identity: principal %s, agent %s",
				oneLine(env.GetPrincipal().GetId()), oneLine(env.GetAgent().GetId())))
		}
	}
}

func (p *play) answer(ctx context.Context, verb string, a *scenario.Approval) error {
	if p.r.plane.approvals == "" {
		return errors.New("the plane keeps its holds in memory, where no approver outside it can answer them")
	}
	id := p.answers[a.Step].approvalID
	if id == "" {
		return fmt.Errorf("step[%d] was not answered with a pending approval", a.Step)
	}
	args := []string{"approvals", verb, "--approver-id", a.Approver}
	if a.Reason != "" {
		args = append(args, "--reason", a.Reason)
	}
	_, err := p.r.control.run(ctx, append(args, "--", p.r.plane.approvals, id)...)
	return err
}

// finish removes every pause entry the scenario added and no unpause removed,
// waits until the plane reads the file without them, and closes the session.
// An interrupt that ended ctx does not stop it: each run of the sibling is
// still bounded by the sibling's own timeout, and each wait by the runner's.
func (p *play) finish(ctx context.Context) error {
	ctx = context.WithoutCancel(ctx)
	var errs []error
	removed := false
	for _, step := range slices.Sorted(maps.Keys(p.added)) {
		if _, err := p.r.control.run(ctx, "pause", "remove", "--", p.r.plane.pauseFile, p.added[step]); err != nil {
			errs = append(errs, fmt.Errorf("the entry of step[%d]: %w", step, err))
			continue
		}
		delete(p.added, step)
		p.entries--
		removed = true
	}
	if removed && len(errs) == 0 {
		errs = append(errs, p.r.pauseRead(ctx, p.entries))
	}
	if p.session != nil {
		if err := p.session.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing the session: %w", err))
		}
	}
	return errors.Join(errs...)
}
