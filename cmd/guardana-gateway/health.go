package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	adaptermcp "github.com/guardana/control/adapters/mcp"
	"github.com/guardana/control/adapters/otel"
	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/gateway"
	"github.com/guardana/control/internal/metrics"
	"github.com/guardana/control/internal/pause"
	"github.com/guardana/control/internal/policywatch"
	"github.com/guardana/control/internal/reaction"
)

// healthAnswer is what GET /healthz says about the plane. It carries no
// configuration and no credential: the mode, the bundle it serves, what each
// seam counted, and whether the plane still takes material calls.
type healthAnswer struct {
	Status  string       `json:"status"`
	Mode    string       `json:"mode"`
	Adapter string       `json:"adapter"`
	UptimeS float64      `json:"uptime_seconds"`
	Halted  bool         `json:"halted"`
	Halt    haltAnswer   `json:"halt"`
	Bundle  bundleAnswer `json:"bundle"`
	// Policy is how the bundle stands against its freshness statement.
	Policy   policyAnswer   `json:"policy"`
	Pipeline map[string]any `json:"pipeline"`
	// Approvals is where a held request is kept, whether this plane keeps a
	// durable record of its own holds, and what its reconciliation settled.
	Approvals map[string]any `json:"approvals"`
	// Runs says whether runs are local or opened by the operator, and what
	// the listener refused and the pipeline could not read or raise.
	Runs map[string]any `json:"runs"`
	// Enforce is what an enforcement API listener's adapter counted, left
	// out on an MCP listener.
	Enforce  map[string]any `json:"enforce,omitempty"`
	Spool    map[string]any `json:"spool"`
	Exporter map[string]any `json:"exporter"`
	// Pause is the operator's pause state as a call admitted now would be
	// decided under it.
	Pause pauseAnswer `json:"pause"`
	// Stops is the stop state as a call admitted now would be decided
	// under it.
	Stops    stopsAnswer `json:"stops"`
	Problems []string    `json:"problems,omitempty"`
}

// pauseAnswer is the pause state without a reason in it: the state, how many
// entries are in force and whether one is global, the entries that pause
// only calls to names no upstream lists, how old the read is, why an unknown
// state is unknown, and what the reader counted.
type pauseAnswer struct {
	State   string `json:"state"`
	Cause   string `json:"cause,omitempty"`
	Entries int    `json:"entries"`
	Global  bool   `json:"global"`
	// UnlistedOnly names the entries of an upstream this plane does not have,
	// or of a tool its upstream does not list: each pauses only calls that
	// carry no provider, which are calls to names no upstream lists. On an
	// enforce_api plane it names the entries of a provider or a tool its tool
	// table lacks, which pause no call the plane runs.
	UnlistedOnly []string `json:"unlisted_only"`
	// AgeMS is left out where nothing was read: a plane with no pause file.
	AgeMS *int64 `json:"age_ms,omitempty"`
	// Polls is what the reader counted: its reads, the failed ones by cause
	// and the changes of the snapshot. It is left out where nothing reads.
	Polls map[string]any `json:"polls,omitempty"`
}

// haltAnswer names the plane's halts of ADR-0013 by what raised each. A
// mismatch that halted one opened run halts neither flag; RunsHalted counts
// it.
type haltAnswer struct {
	ExecutedArgsMismatch bool `json:"executed_args_mismatch"`
	EvidenceUnwritable   bool `json:"evidence_unwritable"`
}

// haltOf names the plane's halts in stats.
func haltOf(stats gateway.Stats) haltAnswer {
	return haltAnswer{
		ExecutedArgsMismatch: stats.MismatchHalted,
		EvidenceUnwritable:   stats.SinkHalted,
	}
}

type bundleAnswer struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Serial  int64  `json:"serial"`
	// ConfirmedAt is empty while no statement confirms the bundle.
	ConfirmedAt string `json:"confirmed_at,omitempty"`
}

// healthMux answers the plane's own state and what the product is called.
func (p *plane) healthMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", p.serveHealth)
	mux.HandleFunc("GET /metrics", p.serveMetrics)
	mux.HandleFunc("GET /brand", brandHandler(p.logger))
	return mux
}

// serveMetrics answers every statistic in the text exposition format. A spool
// that cannot answer is reported by a flag, with its metrics left out rather
// than written as zero; a reading the text cannot carry truthfully is 503
// with no body.
func (p *plane) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	body, err := p.metrics(p.pauseSource(), time.Now)
	if err != nil {
		p.logger.Warn("metrics cannot be reported", "err", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", metrics.ContentType)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		p.logger.Debug("answer not delivered", "err", err)
	}
}

// metrics reads every seam's statistics, the pause state from src before
// the clock, as health does.
func (p *plane) metrics(src gateway.PauseSource, clock func() time.Time) ([]byte, error) {
	snap := src.Current().At(clock())
	spoolStats, err := p.spool.Stats()
	if err != nil {
		p.logger.Warn("metrics: the spool cannot report", "err", err)
	}
	r := metrics.Reading{
		Pipeline:   p.pipeline.Stats(),
		PauseState: snap.State(), PauseEntries: len(snap.Entries()),
		Spool: spoolStats, SpoolBroken: err != nil,
		Exporter: p.exporter.Stats(), ExporterStopped: p.stopped.Load() != nil,
	}
	if p.adapter != nil {
		r.Adapter = p.adapter.Stats()
	}
	if p.enforce != nil {
		r.EnforceAPI, r.Enforce = true, metrics.EnforceOf(p.enforce.Stats())
	}
	if p.poller != nil {
		r.Pause = p.poller.Stats()
	}
	if p.stops != nil {
		r.Stops = p.stops.poller.Stats()
	}
	r.PolicyFreshness, _, r.PolicySecondsLeft = p.freshness(p.holder.Current(), clock())
	if p.policy != nil && p.policy.refresher != nil {
		r.Policy = metrics.RefreshOf(p.policy.refresher.Stats())
		r.PolicySecondsSincePoll = int64(p.policy.refresher.SincePoll() / time.Second)
	}
	return metrics.Render(r)
}

func (p *plane) serveHealth(w http.ResponseWriter, _ *http.Request) {
	answer, ok := p.health(p.pauseSource(), time.Now)
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, p.logger, status, answer)
}

// health reads every seam's counters, the pause and stop states before the
// clock, as a call takes them. ok is false when the plane takes no material
// call, either halt of ADR-0013 or a spool that cannot answer, and when it
// takes no call at all because its pause or stop state is unknown. An
// operator's pause and a stop are not problems; a policy that is not
// confirmed is degraded, since every mode but OBSERVE blocks material calls
// under it and a restart does not fix it, and so is a stop list past nine
// tenths of a bound.
func (p *plane) health(src gateway.PauseSource, clock func() time.Time) (healthAnswer, bool) {
	snap := src.Current()
	stops := p.stopSource().Current()
	now := clock()
	stats := p.pipeline.Stats()
	// The spool before the exporter: the exporter counts a release only once
	// the spool made it, so in this order a released spool never shows with
	// its records uncounted.
	spoolStats, spoolErr := p.spool.Stats()
	answer := healthAnswer{
		Status:    "ok",
		Mode:      p.cfg.ModeName,
		Adapter:   p.seam().Name(),
		UptimeS:   now.Sub(p.started).Seconds(),
		Halted:    stats.Halted,
		Halt:      haltOf(stats),
		Approvals: approvalCounters(p.cfg.Approvals.Provider, stats),
		Exporter:  exporterCounters(p.exporter.Stats()),
	}
	if p.enforce != nil {
		es := p.enforce.Stats()
		answer.Pipeline, answer.Enforce = pipelineOnly(stats), enforceCounters(es)
		answer.Runs = map[string]any{"kind": "opened", "refused_at_request": es.RunsRefused, "state_failures": stats.RunStateFailures}
	} else {
		answer.Pipeline = pipelineCounters(stats, p.adapter.Stats())
		answer.Runs = runCounters(p.runsDir != nil, stats, p.adapter.Stats())
	}
	policySnap := p.holder.Current()
	if policySnap != nil {
		ref := policySnap.Ref()
		answer.Bundle = bundleAnswer{
			ID: ref.GetBundleId(), Version: ref.GetVersion(), Digest: ref.GetDigest(),
			Serial: policySnap.Serial(),
		}
		if !policySnap.ConfirmedAt().IsZero() {
			answer.Bundle.ConfirmedAt = policySnap.ConfirmedAt().UTC().Format(time.RFC3339)
		}
	} else {
		answer.Problems = append(answer.Problems, "no policy bundle is installed")
	}
	answer.Pause = p.pauseAnswer(snap.At(now), now)
	if answer.Pause.State == pause.Unknown.String() {
		answer.Problems = append(answer.Problems,
			"pause: the pause state is unknown ("+answer.Pause.Cause+"), so every call is blocked")
	}
	answer.Stops = p.stopsAnswer(stops, now)
	if answer.Stops.State == reaction.Unknown.String() {
		answer.Problems = append(answer.Problems,
			"stops: the stop state is unknown ("+answer.Stops.Cause+"), so every call is blocked")
	}
	if reason := p.stopped.Load(); reason != nil {
		answer.Exporter["stopped"] = (*reason).Error()
	}
	if spoolErr != nil {
		answer.Problems = append(answer.Problems, "spool: "+spoolErr.Error())
	} else {
		answer.Spool = map[string]any{
			"segments": spoolStats.Segments, "bytes": spoolStats.Bytes,
			"unacknowledged": spoolStats.Unacknowledged, "reserved": spoolStats.Reserved,
			"open_trails": spoolStats.OpenTrails, "quarantined_records": spoolStats.QuarantinedRecords,
			"quarantined_bytes": spoolStats.QuarantinedBytes, "truncated": spoolStats.Truncated,
			"oldest_segment": spoolStats.Oldest.Segment, "oldest_offset": spoolStats.Oldest.Offset,
		}
	}
	answer.Policy = p.policyAnswer(policySnap, now)
	switch {
	case answer.Halted || len(answer.Problems) > 0:
		answer.Status = "halted"
		return answer, false
	case answer.Policy.Freshness != policywatch.Confirmed.String() || answer.Stops.Degraded:
		// Not a problem that halts: a restart cannot confirm a policy or
		// empty a list, and the plane still answers what it blocks and why.
		answer.Status = "degraded"
	}
	return answer, true
}

// pauseAnswer is snap, the pause state a call admitted at now would take.
func (p *plane) pauseAnswer(snap pause.Snapshot, now time.Time) pauseAnswer {
	entries := snap.Entries()
	out := pauseAnswer{
		State: snap.State().String(), Entries: len(entries), Global: hasGlobal(entries), UnlistedOnly: []string{},
	}
	for _, e := range p.strayEntries(entries) {
		out.UnlistedOnly = append(out.UnlistedOnly, e.id)
	}
	if snap.State() == pause.Unknown {
		out.Cause = string(snap.Cause())
	}
	if !snap.ReadAt().IsZero() {
		age := now.Sub(snap.ReadAt()).Milliseconds()
		out.AgeMS = &age
	}
	if p.poller != nil {
		stats := p.poller.Stats()
		failed := make(map[string]uint64, len(stats.Failed))
		for cause, n := range stats.Failed {
			failed[string(cause)] = n
		}
		out.Polls = map[string]any{"made": stats.Polls, "failed": failed, "changes": stats.Changes}
	}
	return out
}

// pipelineCounters is the pipeline's counters and the MCP adapter's beside
// them.
func pipelineCounters(s gateway.Stats, adapter adaptermcp.Stats) map[string]any {
	out := pipelineOnly(s)
	out["admitted"], out["blocked"], out["sent"] = adapter.Admitted, adapter.Blocked, adapter.Sent
	out["close_failures"], out["refresh_failures"] = adapter.CloseFailures, adapter.RefreshFailures
	return out
}

// pipelineOnly is what the pipeline counted, whatever adapter it serves:
// executions abandoned and runs halted on a reported mismatch among them.
func pipelineOnly(s gateway.Stats) map[string]any {
	return map[string]any{
		"blocks": s.Blocks, "pending": s.Pending, "executed": s.Executed,
		"sink_failures_before_effect": s.SinkFailuresBeforeEffect,
		"sink_failures_after_effect":  s.SinkFailuresAfterEffect,
		"sink_failures_abandoned":     s.SinkFailuresAbandoned,
		"reads_unrecorded":            s.ReadsUnrecorded, "mismatches": s.Mismatches,
		"multi_use_refused": s.MultiUseRefused, "stale_handed_out": s.StaleHandedOut, "open": s.Open, "held": s.Held,
		"abandoned": s.Abandoned, "runs_halted": s.RunsHalted,
		"runs": s.Runs, "flow_uncomputed": s.FlowUncomputed,
		"asks": askCounters(s.Asks),
	}
}

// runCounters says where the plane's runs come from. Local runs live in
// memory, so a new process starts clean; opened runs are counted where the
// listener refused a token, by cause, and where a root's state failed.
func runCounters(opened bool, s gateway.Stats, adapter adaptermcp.Stats) map[string]any {
	if !opened {
		return map[string]any{"kind": "local", "kept": s.Runs}
	}
	return map[string]any{
		"kind":               "opened",
		"refused_at_request": adapter.RunsRefusedAtRequest,
		"refused_at_message": adapter.RunsRefusedAtMessage,
		"state_failures":     s.RunStateFailures,
	}
}

// askCounters is what the plane asked the external decision point, by what
// each ask came back as, and the time spent waiting on it.
func askCounters(a gateway.Asks) map[string]any {
	return map[string]any{
		"made": a.Made, "allowed": a.Allowed, "denied": a.Denied,
		"denied_obligations": a.DeniedObligations, "timed_out": a.TimedOut,
		"unavailable": a.Unavailable, "answer_refused": a.AnswerRefused, "wait_us": a.Micros,
	}
}

// approvalCounters is what an operator needs about the holds: the store a held
// request is kept in, whether a hold lost to a restart is closed at all, and
// whether the last reconciliation read every entry. An incomplete pass is
// reported and never stops the plane from serving (ADR-0016).
func approvalCounters(provider string, s gateway.Stats) map[string]any {
	out := map[string]any{
		"provider": provider, "hold_journal": s.HoldJournal,
		"reconcile_incomplete": s.ReconcileIncomplete,
		"holds_closed":         s.HoldsClosed, "holds_unmeasured": s.HoldsUnmeasured,
		"unheld_records": s.UnheldRecords, "journal_refusals": s.JournalRefusals,
		"held_trails_left_open": s.HeldTrailsLeftOpen,
	}
	if !s.HoldJournal {
		out["limits"] = []string{"a hold this plane loses to a restart is never closed: no hold journal is configured"}
	}
	return out
}

func exporterCounters(s otel.Stats) map[string]any {
	return map[string]any{
		"acknowledged": s.Acknowledged, "quarantined": s.Quarantined,
		"partial_rejected": s.PartialRejected, "refused": s.Refused, "retries": s.Retries,
		"retried_transport": s.RetriedTransport, "retried_redirect": s.RetriedRedirect,
		"retried_auth": s.RetriedAuth, "retried_throttled": s.RetriedThrottled,
		"retried_server": s.RetriedServer, "retried_answer": s.RetriedAnswer,
		"retried_status": s.RetriedStatus,
	}
}

// brandHandler answers what the product is called, which is what the brand
// package holds and nothing a configuration can change.
func brandHandler(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, logger, http.StatusOK, map[string]string{
			"name": brand.Name, "slug": brand.Slug, "command": brand.Gateway,
			"version": version, "proto_package": brand.ProtoPackage, "otel_namespace": brand.OTelNamespace,
		})
	}
}

// writeJSON answers one document. A write that fails has nobody left to tell:
// the status line is already sent, so the error goes to the log.
func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, body any) {
	raw, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "cannot encode the answer", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(append(raw, '\n')); err != nil {
		logger.Debug("answer not delivered", "err", err)
	}
}
