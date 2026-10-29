package gateway

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	controlv1 "github.com/guardana/control/api/gen/go/guardana/control/v1"
	"github.com/guardana/control/internal/core"
	"github.com/guardana/control/pkg/contract"
)

// flowTagPrefix is the run-context tag prefix under which the pipeline records
// the flow state a decision used (ADR-0021).
const flowTagPrefix = "flow.v1."

// reservedPrefix is what no producer's tag may start with, compared in ASCII
// case only: the flow tags of every version, however their ASCII letters are
// cased, so no producer can forge that record. A tag that only looks like one,
// with a letter from another script, is not under the prefix and is kept.
const reservedPrefix = "flow.v"

const (
	tagUntrusted   = flowTagPrefix + "untrusted="
	tagMaxRead     = flowTagPrefix + "max_read="
	tagReadUnknown = flowTagPrefix + "max_read=UNKNOWN"
	tagUncomputed  = flowTagPrefix + "state=uncomputed"
	tagRoot        = flowTagPrefix + "root="
)

// runKey names a run: the principal as the listener resolved it and the agent
// the listener names. A session, a connection and whatever a client sends
// never split a run, since each is the client's to redraw.
type runKey struct {
	tenant, kind, principal, agent string
}

// run is what one run took in so far: whether any of it was untrusted, and the
// highest sensitivity it read, which is UNSPECIFIED for good once it read
// something undeclared. The pipeline's lock guards both; id never changes.
type run struct {
	id        string
	untrusted bool
	maxRead   controlv1.Sensitivity
}

// flowKind is how a call stands toward a run. The zero value is the state
// nobody computed, with no run.
type flowKind int

const (
	flowUncomputed flowKind = iota
	// flowUnnamed: the call's local run was to be minted and the id source
	// gave it no name, so an execution would taint nothing its next call reads.
	flowUnnamed
	// flowLocal: a run of ADR-0021, kept in the pipeline's memory.
	flowLocal
	// flowOpened: a run the operator opened, whose root's state was read.
	flowOpened
	// flowUnavailable: the call needs an opened run and has none the plane
	// can vouch for, or its root's state could not be read.
	flowUnavailable
)

// flow is a call's view of its run, taken once when the call starts: the run
// its execution taints, and the state every decision of the call is made
// under.
type flow struct {
	kind   flowKind
	run    *run
	opened *OpenedRun
	// read is the opened root's state as the call read it, which a raise
	// compares with what the call's result brings in.
	read  RunState
	state contract.FlowState
}

func (f flow) runID() string {
	switch f.kind {
	case flowLocal:
		return f.run.id
	case flowOpened, flowUnavailable:
		if f.opened != nil {
			return f.opened.ID
		}
	}
	return ""
}

// tags renders the state as the run-context tags a recorded envelope carries;
// an opened run also names the root whose state was used.
func (f flow) tags() []string {
	switch f.kind {
	case flowLocal:
		return []string{
			tagUntrusted + strconv.FormatBool(f.state.UntrustedInfluence),
			readTag(f.state.MaxSensitivityRead),
		}
	case flowOpened:
		return []string{
			tagUntrusted + strconv.FormatBool(f.state.UntrustedInfluence),
			readTag(f.state.MaxSensitivityRead),
			tagRoot + f.opened.Root,
		}
	case flowUncomputed, flowUnnamed, flowUnavailable:
	}
	return []string{tagUncomputed}
}

// readTag names a reading by the contract's name without its prefix, as a
// policy spells a floor.
func readTag(s controlv1.Sensitivity) string {
	if !contract.ValidSensitivityFloor(s) {
		return tagReadUnknown
	}
	_, name, _ := strings.Cut(s.String(), "_")
	return tagMaxRead + name
}

func keyOf(env *controlv1.ActionEnvelope) (runKey, bool) {
	principal := env.GetPrincipal()
	if principal.GetId() == "" {
		return runKey{}, false
	}
	return runKey{
		tenant: principal.GetTenantId(), kind: principal.GetType(),
		principal: principal.GetId(), agent: env.GetAgent().GetId(),
	}, true
}

// flowOf takes the flow state of env's run, minting the run the first time its
// key is seen when mint is set. A call the pipeline cannot key, whose run it
// may not mint, or whose key would be past MaxRuns, gets the state nobody
// computed; so does a call whose run the id source cannot name, which is
// marked unnamed. Every one of them is counted.
func (p *Pipeline) flowOf(env *controlv1.ActionEnvelope, mint bool) flow {
	f := p.lookupRun(env, mint)
	if f.kind != flowLocal {
		p.uncomputed()
	}
	return f
}

func (p *Pipeline) uncomputed() {
	p.counts.add(func(s *Stats) *uint64 { return &s.FlowUncomputed })
}

func (p *Pipeline) lookupRun(env *controlv1.ActionEnvelope, mint bool) flow {
	key, ok := keyOf(env)
	if !ok {
		return flow{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.runs[key]
	if r == nil {
		if !mint || len(p.runs) >= p.cfg.MaxRuns {
			return flow{}
		}
		id := p.cfg.NewID()
		if id == "" {
			return flow{kind: flowUnnamed}
		}
		r = &run{id: id, maxRead: controlv1.Sensitivity_SENSITIVITY_PUBLIC}
		p.runs[key] = r
	}
	return flow{kind: flowLocal, run: r, state: contract.NewFlowState(r.untrusted, r.maxRead)}
}

// took records in f's run what a result brings in. The pipeline calls it when
// it hands an execution out, so every call whose arguments could carry that
// result is decided after it, and no closing and no evidence outcome can skip
// it.
func (p *Pipeline) took(f flow, trust controlv1.TrustZone, read controlv1.Sensitivity) {
	if f.kind != flowLocal {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if contract.IsUntrusted(trust) {
		f.run.untrusted = true
	}
	f.run.maxRead = joinRead(f.run.maxRead, read)
}

// joinRead is the higher of two readings. An unknown one, or one this build
// cannot place, leaves the run unknown for good: after a known INTERNAL and an
// undeclared read, INTERNAL would put a CONFIDENTIAL floor out of reach of
// data the run may hold, once an envelope carries a label.
func joinRead(current, read controlv1.Sensitivity) controlv1.Sensitivity {
	if !contract.ValidSensitivityFloor(current) || !contract.ValidSensitivityFloor(read) {
		return controlv1.Sensitivity_SENSITIVITY_UNSPECIFIED
	}
	return max(current, read)
}

// takeFlow takes the call's flow state and stamps it on a copy of its
// envelope, before anything decides the call. A call its producer forged a
// flow tag on reads no run. A call whose translation was refused mints none,
// since every mode blocks it, and neither does an unclassified one outside
// OBSERVE, the one mode that hands it out and so needs its run to take in
// what it returns.
func (c *call) takeFlow() {
	c.refuseFlowTags()
	switch {
	case c.forged:
		c.p.uncomputed()
	case c.p.cfg.Runs != nil || c.in.Run != nil:
		c.flow = c.p.openedFlow(c.ctx, c.in)
	default:
		t := translationOf(c.in)
		c.flow = c.p.flowOf(c.in.Envelope, t == translationComplete || t == translationUnclassified && c.p.cfg.Mode == modeObserve)
	}
	c.stampFlow()
}

// refuseFlowTags marks a call whose producer sent a tag under the reserved
// prefix forged, and refuses the first such tag when the call carries no
// refusal yet. An earlier refusal stays the call's alone, since the kernel
// codes a joined one by the first sentinel it finds and would name the tag
// instead.
func (c *call) refuseFlowTags() {
	for i, tag := range c.in.Envelope.GetContext().GetTags() {
		if isFlowTag(tag) {
			if c.in.Refusal == nil {
				c.in.Refusal = &contract.ValidationError{
					Field: "context.tags[" + strconv.Itoa(i) + "]",
					Err:   fmt.Errorf("%w: the %s prefix is the plane's own", contract.ErrInvalidValue, reservedPrefix),
				}
			}
			c.forged = true
			return
		}
	}
}

// stampFlow puts the call's flow state on a copy of its envelope as run-context
// tags, so ACTION_PROPOSED records the state its decision used. The copy keeps
// none of the producer's tags under the reserved prefix.
func (c *call) stampFlow() {
	env := c.in.Envelope
	if env == nil {
		return
	}
	out := proto.CloneOf(env)
	if out.Context == nil {
		out.Context = &controlv1.RunContext{}
	}
	out.Context.Tags = append(slices.DeleteFunc(out.Context.Tags, isFlowTag), c.flow.tags()...)
	c.in.Envelope = out
	// The kernel validates a classified envelope after the stamp and never an
	// unclassified one, so the stamped copy is held to the contract's bounds here.
	if translationOf(c.in) == translationUnclassified {
		if err := contract.ValidateUnclassified(out); err != nil {
			c.in.Refusal = err
		}
	}
}

// refuseFlow blocks, in every mode, a call whose producer sent a tag under the
// reserved prefix, whose record would otherwise carry a state the plane never
// computed. A forged call reaches the kernel with a refusal, the producer's
// own or the tag's, so no decision point is asked about it and the block keeps
// the code the kernel gave that refusal. A run the id source could not name,
// or an opened run the plane cannot vouch for or read, is one of the plane's
// own causes instead, named before any ask.
func (c *call) refuseFlow() {
	if c.action != core.Block && c.forged {
		c.decide(verdictIndeterminate, c.kernel.GetReasonCodes()...)
	}
}

// isFlowTag reports whether tag starts with the reserved prefix, ignoring
// ASCII case.
func isFlowTag(tag string) bool {
	if len(tag) < len(reservedPrefix) {
		return false
	}
	for i := range len(reservedPrefix) {
		b := tag[i]
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != reservedPrefix[i] {
			return false
		}
	}
	return true
}

// withoutFlowTags is a run context as a retry has to repeat it: the flow tags
// say what the run took in, which the fresh decision already weighs.
func withoutFlowTags(rc *controlv1.RunContext) *controlv1.RunContext {
	out := proto.CloneOf(orEmpty(rc))
	out.Tags = slices.DeleteFunc(out.Tags, isFlowTag)
	return out
}
