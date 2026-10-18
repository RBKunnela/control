package gateway

import (
	"maps"
	"sync"
)

// Stats is what the pipeline counted since New: what it blocked and why, what
// it held, what it let run, where the sink failed, what is open now, and
// whether it takes material calls at all.
type Stats struct {
	// Blocks counts blocks by the first reason code of the decision each
	// carries, the kernel's or the plane's own: one for each trail closed with
	// ACTION_BLOCKED, by the call it records, a resume, the sweep of an
	// expired hold or a reconciliation; one for each resume whose approval
	// expired while its ACTION_STARTED was appended, counted as
	// APPROVAL_EXPIRED, whose trail closes with ACTION_FAILED; one for each
	// call or resume whose block a refused record or journal write kept off
	// its trail; and one for each call refused before any trail was written,
	// because its request could not be named or its id was open. A sweep that cannot close a trail
	// counts it in HeldTrailsLeftOpen alone, and a call whose hold the sweep
	// or a resume took first is answered as blocked and not counted, since
	// the taker counts that trail.
	Blocks map[string]uint64
	// Pending counts admissions answered with a pending approval, first
	// requests and retries alike.
	Pending uint64
	// Executed counts admissions that were handed to execution.
	Executed uint64
	// SinkFailuresBeforeEffect counts appends that failed before anything
	// ran; each blocked the call it was recording, or let a read through
	// unrecorded under AllowReadsUnrecorded.
	SinkFailuresBeforeEffect uint64
	// SinkFailuresAfterEffect counts closing records that could not be
	// written; each halted the plane for material calls.
	SinkFailuresAfterEffect uint64
	// ReadsUnrecorded counts reads under AllowReadsUnrecorded whose trail the
	// sink refused an event of, once per read, whether the read then ran or
	// was blocked.
	ReadsUnrecorded uint64
	// SinkFailuresAbandoned counts closing records of abandoned executions
	// that could not be written. None halts the plane: nothing says the
	// effect happened, and each leaves its trail at ACTION_STARTED.
	SinkFailuresAbandoned uint64
	// Abandoned counts executions closed as abandoned, their record written
	// or not.
	Abandoned uint64
	// RunsHalted is the opened runs whose material calls are blocked until
	// restart because a caller reported bytes that were not the authorized
	// ones; at most MaxRuns, past which a report halts the plane.
	RunsHalted int
	// Mismatches counts closings whose sent bytes were not the authorized
	// ones, whatever the effect class of the call.
	Mismatches uint64
	// MultiUseRefused counts approvals the store held as multi-use, which
	// this plane left pending.
	MultiUseRefused uint64
	// StaleHandedOut counts calls OBSERVE let through whose decision's
	// policy was no longer current at hand-out, where ENFORCE would have
	// withheld them with POLICY_STALE.
	StaleHandedOut uint64
	// UnheldRecords counts records a store still keeps for a request this
	// plane does not hold and cannot prove was spent. Each one was held anew:
	// a store that cannot say an execution used a record never makes the
	// plane say so either.
	UnheldRecords uint64
	// JournalRefusals counts hold journal writes that failed. Each one
	// refused a hold, blocked an append past a request for approval, or left
	// an entry the plane could not forget.
	JournalRefusals uint64
	// HoldsClosed counts trails of holds lost to a restart that a
	// reconciliation closed.
	HoldsClosed uint64
	// HoldsUnmeasured counts journal entries a reconciliation could not
	// settle: left mid-close by an interrupted plane, unreadable, or whose
	// closing record could not be written. Each is one trail this plane
	// cannot speak for.
	HoldsUnmeasured uint64
	// HeldTrailsLeftOpen counts trails past a request for approval that a
	// refused record or journal write left open. Each keeps its request id
	// reserved until the plane restarts, and the next start's reconciliation
	// reports it where a journal kept its entry.
	HeldTrailsLeftOpen uint64
	// HoldJournal says whether this plane keeps a durable record of its own
	// holds. Without one, a hold lost to a restart is never closed.
	HoldJournal bool
	// ReconcileIncomplete says a reconciliation stopped at its bound or could
	// not read the journal, so what it reported is unmeasured, not done.
	ReconcileIncomplete bool
	// Open is the executions handed out and not yet closed or aborted.
	Open int
	// Held is the requests held for an approval whose approval has not
	// expired.
	Held int
	// FlowUncomputed counts calls decided with the flow state nobody
	// computed, because the pipeline could not key or name their run, their
	// key was past MaxRuns, they carried a refusal outside OBSERVE before
	// their principal had a run, or their producer sent a flow tag, and
	// calls blocked for want of an opened run the plane could vouch for; a
	// flow rule is undetermined for each of them.
	FlowUncomputed uint64
	// RunStateFailures counts reads and raises of an opened run's root state
	// that failed, each of which blocked its call.
	RunStateFailures uint64
	// Runs is the local runs the pipeline keeps a flow state for.
	Runs int
	// Asks is what the plane asked the external decision point and what came
	// back. decision_latency_us on a decision is the kernel's alone.
	Asks Asks
	// Halted says the plane takes no material call: MismatchHalted,
	// SinkHalted or both. A run halted on its own is counted in RunsHalted,
	// not here.
	Halted bool
	// MismatchHalted says an execution of any effect class ran with bytes
	// that were not authorized and the mismatch halted the plane rather than
	// one run. It stands until restart.
	MismatchHalted bool
	// SinkHalted says a closing record could not be written and no append
	// has succeeded since.
	SinkHalted bool
}

// Asks counts the pipeline's calls to its DecisionPoint's Ask, by what each
// came back as, and the time spent waiting on them. A call counts whether or
// not the decision point sent a request on: one it answers unavailable
// without sending, such as an envelope it cannot map or an ask over its own
// bound on asks in flight, counts in Made and Unavailable. With no decision
// point configured nothing is counted.
type Asks struct {
	// Made counts the calls to Ask; it is the sum of the six counts below.
	Made              uint64
	Allowed           uint64
	Denied            uint64
	DeniedObligations uint64
	TimedOut          uint64
	Unavailable       uint64
	AnswerRefused     uint64
	// Micros is the time spent waiting on the decision point over every ask,
	// in microseconds of the plane's clock.
	Micros uint64
}

// counters is the mutable half of Stats, under its own lock.
type counters struct {
	mu    sync.Mutex
	stats Stats
	// failures counts the appends that failed, so an append that started
	// before a failure and returned after it does not lift the halt that
	// failure raised.
	failures uint64
	// sinkHalt lifts when an append succeeds; mismatchHalt never does, and
	// neither does a run's entry in runHalts.
	sinkHalt, mismatchHalt bool
	runHalts               map[string]struct{}
}

func (c *counters) blocked(code string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stats.Blocks == nil {
		c.stats.Blocks = make(map[string]uint64)
	}
	c.stats.Blocks[code]++
}

// leftOpen counts a held trail left open with its request id reserved.
func (c *counters) leftOpen() {
	c.add(func(s *Stats) *uint64 { return &s.HeldTrailsLeftOpen })
}

func (c *counters) add(field func(*Stats) *uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	*field(&c.stats)++
}

// generation is the number of failed appends so far, read before an append and
// handed back to appended.
func (c *counters) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failures
}

// appended records an append that succeeded, which lifts a sink halt unless an
// append failed while this one was in flight.
func (c *counters) appended(gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failures == gen {
		c.sinkHalt = false
	}
}

// sinkFailed records an append that failed, after an effect when
// afterEffect, which halts the plane.
func (c *counters) sinkFailed(afterEffect bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	if afterEffect {
		c.stats.SinkFailuresAfterEffect++
		c.sinkHalt = true
		return
	}
	c.stats.SinkFailuresBeforeEffect++
}

// mismatched counts a mismatch and halts run, or the plane when run is empty
// or bound other runs are halted already.
func (c *counters) mismatched(run string, bound int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Mismatches++
	if _, halted := c.runHalts[run]; run == "" || (!halted && len(c.runHalts) >= bound) {
		c.mismatchHalt = true
		return
	}
	if c.runHalts == nil {
		c.runHalts = make(map[string]struct{})
	}
	c.runHalts[run] = struct{}{}
}

// sinkFailedAbandoning records a refused closing of an abandoned execution,
// which halts nothing.
func (c *counters) sinkFailedAbandoning() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	c.stats.SinkFailuresAbandoned++
}

// halts reports the two plane halts and whether run is halted on its own.
func (c *counters) halts(run string) (sink, mismatch, runHalt bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, runHalt = c.runHalts[run]
	return c.sinkHalt, c.mismatchHalt, run != "" && runHalt
}

func (c *counters) snapshot() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.stats
	out.Blocks = maps.Clone(c.stats.Blocks)
	out.MismatchHalted, out.SinkHalted = c.mismatchHalt, c.sinkHalt
	out.Halted = c.sinkHalt || c.mismatchHalt
	out.RunsHalted = len(c.runHalts)
	return out
}
