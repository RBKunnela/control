---
title: Delivery backlog
summary: Planned work ordered by user value, with dependencies and observable acceptance checks.
type: project
covers: [pkg/**, cmd/**, adapters/**, internal/**, examples/**]
---

# Delivery backlog

All tasks below are `planned`, including verification tasks. They name work to
do, not capabilities to claim. [status.md](status.md) is the implementation
inventory; [ROADMAP.md](../ROADMAP.md) owns milestone order. Architectural changes
need accepted records before implementation. An owner and an issue can be added
when a task is picked up; no task is assigned by this document. A delivered
task leaves this page, and status.md records what it built.

This backlog covers roadmap work, not every session note. Keep stable task identifiers when work moves to an
issue. Completion requires code, documentation and the applicable checks.

## Entry gate and trust work

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B00 | Establish a reproducible baseline | none | Full `make quality` and CI on the exact candidate commit pass; platform, tool versions, skips and failures are recorded. A partial target run cannot satisfy this task |

## Milestone 1: one useful local project

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B06 | Connect an existing MCP setup | none | Copyable client/server instructions and a local profile work with an independently maintained server. Classification remains operator-owned; missing classification and unsupported methods are visible. At least three new users attempt the guide; time and help are recorded |
| B23 | Preview and apply an existing MCP configuration | B06 | A supported client configuration is read into an explicit change plan, with paths outside the gateway named. Dry-run writes nothing and starts no server; apply is explicit, preserves unrelated settings and makes an owner-only backup. A second apply is a no-op; undo refuses intervening edits. Verification shows a live allowed and refused or held call, policy version, reported result, coverage gaps and the next operator step in a readable local report linked to its source records. Malformed files, links, concurrent edits and credentials in output have adversarial cases. Measure setup with three users |

## Milestone 2: integrations without a fork

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B11 | Ship Python and one runtime integration | none | The Python client and the hook bridge with one built-in profile run externally ([ADR-0051](adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md), [ADR-0056](adr/0056-a-coding-runtimes-hooks-reach-the-plane-through-one-bridge.md)); the profile's qualification is B24. What remains is one framework integration an adopter selects, passing the client conformance cases, with its covered and bypassing tool paths published |
| B24 | Qualify one coding-agent hook integration | none | The built-in profile runs against a pinned release of its runtime: a call blocked with no effect, a pending approval resumed, a wanted rewrite denied, the input that ran compared, the plane down, the hook timing out, crashing and printing garbage, hooks disabled, two concurrent resumes, and two mutant bridges caught. The results are recorded beside the profile and back its page's claims. A hook decides a call and is never an enforcement point ([ADR-0056](adr/0056-a-coding-runtimes-hooks-reach-the-plane-through-one-bridge.md)); missing identity, disabled hooks, timeouts, malformed answers, unsupported obligations, cancellation and concurrent resumes never silently become authorization |
| B25 | Review changes to tool definitions | B00 | Compare an operator-reviewed manifest with a newly observed one, name changed fields and old/new fingerprints, and export a bounded report with source and observation time. Reuse the existing classification refusal. Description, schema, metadata, removed and ambiguous tools, and a silent or unavailable source have cases. Review never repins a definition or signs a policy; unchanged definitions do not attest unchanged server code |
| B27 | Compare and simulate a candidate policy | B00 | A report names both policy digests, input provenance and per-case before/after verdicts, obligations and missing facts. Reuse the kernel's evaluation; publish denominators and unknowns. Cases cover broadened effects/resources, rule conflict, absent arguments or flow context, missing historic policy, gaps and changed definitions. Simulation sends no tool call, consumes no approval and cannot activate a policy |
| B21 | Add sensors independent of the agent | ADR-0040 | An importer reads an egress proxy's access log under a descriptor marked independent, and a second reads process events from the host the agent runs on; a connection is attributed to a run only as well as the proxy identifies its caller, and an unattributed one stays unknown. The coverage map shows an egress destination the plane never decided on |
| B12 | Publish the port contracts and add TypeScript | B11 for the enforcement client | Sensor, detector, reaction and notifier contracts are published with conformance suites of input and expected output files any language runs, once two consumers have used each. An external detector or notifier built from them alone passes its suite. Queue bounds, lag and failures are visible and cannot affect authorization. TypeScript passes the same client fixtures. A Go seam is promoted only with its own ADR and two consumers; nothing is loaded into a plane at run time |

LangGraph and the OpenAI Agents SDK are framework candidates for what remains
of B11. A second coding runtime waits until adopters name one. Transport
retries may not replay a material tool execution.
Custom policy-provider work preserves ADR-0017's veto-only semantics.

The [adoption and incident requirements](adoption-and-incident-workflows.md)
define B23–B27. They extend these milestones without changing their order;
runtime adapters and any new data contracts need their own accepted records.

The existing event wire format is reused where it suffices. A query response
or delivery wrapper has its own version; do not quietly add unknown fields to
a strict v1 decoder. OTLP logs and traces need separate, tested destination
mappings.

## Milestone 3: a small team

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B13 | Authenticate operators and scope authority | none | Reader/operator/admin capabilities are receiver-enforced; approval authority comes from authentication. Cross-project reads and operations are refused; a pause or a stop names its actual run, agent or principal scope, and only an authenticated author may sign a reaction route. Two users and overlapping runs pass adversarial tests. MCP upstream credentials remain separate from inbound credentials |
| B14 | Add retention and recovery | none | Rotation, disk budget, cursor expiry, duplicates, interrupted export and backup/restore are tested for evidence and observations. A restored process cannot reuse spent approval authority or forget its rollback floor. Read-only inspection cannot mutate recovery state without saying so |
| B26 | Review findings and export an incident package | B13, B14 | A separate review log records scoped author, time, reason and revision for open/in-review/closed and disposition changes without changing the finding's verdict. Grouped occurrences retain source finding ids, rule versions, tenant/project and run references. Reopening, cross-project access, concurrent edits, export gaps and hostile text have cases. A metadata-only package joins the findings, decisions, approvals, policy/procedure digests, coverage and actual reaction results, marks missing inputs, and is read by an external consumer. Closing a case neither lifts a stop nor grants an approval |
| B28 | Run continuous supervision and authorized reaction | B12, B13, B14, B21 | An operator-configured service follows versioned evidence and observation exports with durable cursors, checks procedures and delivers findings through bounded queues. Source silence, export gaps, sampling, lag and unreadable inputs remain visible and never look like completed work. Restart and replay do not duplicate an authority-bearing reaction. Every stop uses the existing confirmed-finding bar and a signed, scoped, expiring route; unknown or observation-only findings cannot stop a run. Tests exercise concurrent runs, source outage, partial exports, expired authority, replay and notifier failure. A notifier failure cannot grant authority or change a verdict; no reaction cancels an effect already running |

## Milestone 4: a fleet and wider protocols

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B16 | Add fleet operations and protocol breadth from demand | B13, B14 | Independent deployments demonstrate need; design covers tenant isolation, signed distribution, authenticated APIs and tested recovery. New HTTP/A2A adapters pass conformance. HA and additional stores have reproducible benchmarks before scale claims |

## Adoption checkpoints

Targets are hypotheses, not reported achievements: first demo value in ten
minutes; three new users completing onboarding; two custom evidence consumers;
one external framework integration; one small team running overlapping tasks. Measure,
each with its denominator and test setup: the time from a release download to
a user's first protected action of their own; the share of declared paths
enforced, observed and unknown; the time from a deviation to its finding, to
its alert's delivery and to the next action stopped; false alarms per run; the
share of runs with complete evidence; the hours an outside author needs to
build a sensor that passes its suite. Record failures and assistance as well
as time. Prioritize observed blockers before adding frameworks or a detector
catalogue. Do not collect adoption telemetry from installations: use voluntary
sessions and feedback, consistent with the no-phone-home decision.
