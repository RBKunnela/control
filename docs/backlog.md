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

A task that publishes a measured result publishes its scope beside it: what
was declared and how much of it was exercised (tools, paths, planes, sources),
the channels nobody observed, the time window, and the inputs that were missing
or cut short. An unobserved channel earns no claim, and a result with a missing
input is incomplete, never complete.

## Entry gate and trust work

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B00 | Publish each release's baseline | none | The cold gate of the release commit and CI on it pass, and the release notes name the platform, the tool versions, the expected skips and any failure. A partial target run cannot satisfy this task |

## Milestone 1: one useful local project

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B06 | Trial the connect guide with three new users | none | At least three new users attempt [connect an existing MCP setup](guides/connect-an-existing-mcp-setup.md) on a server of their own; their time, errors and the help they needed are recorded and published, with each blocker they hit fixed or listed |
| B23 | Preview and apply an existing MCP configuration | none | A supported client configuration is read into an explicit change plan, with paths outside the gateway named. Dry-run writes nothing and starts no server; apply is explicit, preserves unrelated settings and makes an owner-only backup. A second apply is a no-op; undo refuses intervening edits. Verification shows a live allowed and refused or held call, policy version, reported result, coverage gaps and the next operator step in a readable local report linked to its source records. Malformed files, links, concurrent edits and credentials in output have adversarial cases. Measure setup with three users |

## Milestone 2: integrations without a fork

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B21 | Attribute an egress proxy's connections to runs | none | A connection the egress access-log importer reads ([ADR-0069](adr/0069-an-egress-proxys-access-log-is-an-independent-sensor-on-a-kind-neutral-descriptor.md)) names a run only as well as the proxy identifies its caller, and an unattributed one stays unknown; `supervise` reads such a source for the runs its connections name |
| B35 | Add a process sensor independent of the agent | none | A second importer reads process events from the agent's host, under a source descriptor marked independent |
| B12 | Publish the port contracts and add TypeScript | none | Sensor, detector, reaction and notifier contracts are published with conformance suites of input and expected output files any language runs, once two consumers have used each. An outside program can write an observation and a finding that names its detector, whose signed descriptor states the highest source class it may claim; an unknown, expired or wrongly signed detector cannot stop a run. A detector's default rule pack is a versioned document whose digest each finding records. An external detector or notifier built from them alone passes its suite. Queue bounds, lag and failures are visible and cannot affect authorization. TypeScript passes the same client fixtures. A Go seam is promoted only with its own ADR and two consumers; nothing is loaded into a plane at run time |
| B25 | Review changes to tool definitions | none | Compare an operator-reviewed manifest with a newly observed one, name changed fields and old/new fingerprints, and export a bounded report with source and observation time. Reuse the existing classification refusal. Description, schema, metadata, removed and ambiguous tools, and a silent or unavailable source have cases. Review never repins a definition or signs a policy; unchanged definitions do not attest unchanged server code |
| B27 | Compare and simulate a candidate policy | none | A report names both policy digests, input provenance and per-case before/after verdicts, obligations and missing facts. Reuse the kernel's evaluation; publish denominators and unknowns. Cases cover broadened effects/resources, rule conflict, absent arguments or flow context, missing historic policy, gaps and changed definitions. Simulation sends no tool call, consumes no approval and cannot activate a policy. Cases labelled attack or legitimate by someone other than the policy's author are counted by label and by verdict change, and every result is marked simulated |
| B37 | Measure controlled attempts and the cost to legitimate work | none | A manifest fixed before the run names the attempts and how they were chosen, the repetitions, the corpus digest, the model and its settings or "no model", the permissions, the tool definitions, the policy and procedure digests, and what counts as each named effect. The report counts the attempts selected, started and not run. For each named effect it counts the attempts in which the effect was observed, verified absent or unknown; effects are checked at the victim, not read from the plane's verdicts, with positive and negative controls. A labelled set of legitimate operations is reported as completed, held, blocked and unknown over its own count. The first set is scripted against the demo's victim; nothing in it enters the authorization path |
| B36 | Put the remaining decisions about authority behind ports | none | Each decision in [ADR-0066](adr/0066-each-decision-about-authority-is-a-port.md) without a port gets one, its current behaviour as the default, with a closed kind selector, an unavailable state that blocks, bounds, and conformance cases with negative controls: the end user's identity, the policy language, the policy source, the signer, the signature algorithm (its own record first: the v1 bundle names Ed25519), the detector descriptor and the evidence export. `scripts/ports.txt` lists each |
| B11 | Ship one framework integration | none | One framework integration an adopter selects is maintained here against the framework's independently maintained release, passes the client conformance cases of [ADR-0051](adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md) at a pinned version, and has its covered and bypassing tool paths published |

The order is the table's ([ADR-0064](adr/0064-milestone-two-starts-with-an-independent-sensor.md)):
the sensor contract B12 publishes needs a second kind of sensor, and B28
needs both. The process sensor is B35. The egress sensor itself is built
([status](status.md)); B21 adds attribution, so each connection stays
unknown until then. B35 comes later. B25, B27, B36 and B37 block
nothing and go beside them.
LangGraph and the OpenAI Agents SDK are framework candidates for what remains
of B11. A second coding runtime waits until adopters name one. Transport
retries may not replay a material tool execution.
Custom policy-provider work preserves ADR-0017's veto-only semantics.

The [adoption and incident requirements](adoption-and-incident-workflows.md)
define B23 and B25–B27. They extend these milestones without changing their order;
runtime adapters and any new data contracts need their own accepted records.

The existing event wire format is reused where it suffices. A query response
or delivery wrapper has its own version; do not quietly add unknown fields to
a strict v1 decoder. OTLP logs and traces need separate, tested destination
mappings.

## Milestone 3: a small team

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B13 | Authenticate operators and scope authority | none | Under `approvals.authority: signed`, each receiver enforces operate and admin from the signed roster ([ADR-0071](adr/0071-operators-are-named-by-a-signed-roster.md), [ADR-0073](adr/0073-an-approval-counts-only-as-the-plane-judges-it.md)). Reads are checked by peer uid against `health.socket_uid` on the health socket and by file modes; the roster's `read` grant is reserved. A client's `Run-Token`, `Authorization` and `Cookie` reach no MCP upstream, and the paths that need a second account are tested under real accounts in a CI job declared required ([ADR-0081](adr/0081-tests-that-need-a-second-account-run-in-a-required-job.md)). Open: reads and operations of another project are refused at every receiver, not only at the signed ones [contracts.md](contracts.md#signed-files-and-their-project-checks) lists. Each receiver judges a project under the same tenant: answers and pauses take `tenant_id`, runs and stops the listener's. A stop names its actual agent or principal scope. Two operators with overlapping runs pass adversarial tests |
| B14 | Add retention and recovery | none | Rotation, disk budget, cursor expiry, duplicates, interrupted export and backup/restore are tested for evidence and observations. A restored process cannot reuse spent approval authority. Read-only inspection cannot mutate recovery state without saying so. The findings and observation logs take the RecordLog port, which then moves to its consumer with a read interface, a kind selector, its bounds and its diagnostics ([ADR-0072](adr/0072-the-collector-keeps-bounded-segments-of-one-project-behind-a-credential.md)) |
| B26 | Review findings and export an incident package | B13, B14 | A separate review log records scoped author, time, reason and revision for open/in-review/closed and disposition changes without changing the finding's verdict. Grouped occurrences retain source finding ids, rule versions, tenant/project and run references. Reopening, cross-project access, concurrent edits, export gaps and hostile text have cases. A metadata-only package joins the findings, decisions, approvals, policy/procedure digests, coverage and actual reaction results, marks missing inputs, and is read by an external consumer. Closing a case neither lifts a stop nor grants an approval |
| B38 | Show an approver the exact action they approve | B13 | The review of a held call shows its principal, agent, delegation, resource, destination, consequential arguments and bounds, policy reasons and expiry from the held request, bound to its action digest, and names what was redacted or is unavailable. A redacted argument preview is shown only under an explicit setting, off by default. A changed, swapped or stale review, another project's call and hostile text are refused or marked in tests. At least three approvers new to the project explain each case's effect, target and bounds before deciding, over appropriate, inappropriate and under-informed cases; a fixed rubric scores the explanations, and the scores are published with the number of participants and cases. A click or the time spent on the page is not evidence of an informed decision |
| B28 | Run continuous supervision and authorized reaction | B12, B13, B14, B21, B35 | An operator-configured service follows versioned evidence and observation exports with durable cursors, checks procedures and delivers findings through bounded queues. Source silence, export gaps, sampling, lag and unreadable inputs remain visible and never look like completed work. Restart and replay do not duplicate an authority-bearing reaction. Every stop uses the existing confirmed-finding bar and a signed, scoped, expiring route; unknown or observation-only findings cannot stop a run. Tests exercise concurrent runs, source outage, partial exports, expired authority, replay and notifier failure. A notifier failure cannot grant authority or change a verdict; no reaction cancels an effect already running |

## Release bar for 1.0

Each task here is one item of [ROADMAP.md's release bar](../ROADMAP.md#release-bar-for-10).
The coding runtime's hooks (qualified) and B11 are the two integrations.

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B29 | Make the evidence trail tamper-evident | none | Each event carries a hash link to the one before it in its trail and the plane signs checkpoints over the trails under a key apart from the policy's; a verifier any language can run reports a removed, reordered, altered or appended record and a checkpoint that is missing, stale or signed by another key, with adversarial cases for each and a page stating what the claim covers and what it does not |
| B30 | Maintain a second digest implementation | none | A TypeScript implementation of `digest_v1`, the arguments hash and the approval binding passes every golden and refusal vector of `testdata/digest/` in CI, beside the Go one, and any result that differs from a vector's expected one fails the run |
| B31 | Decide the v1 contracts and their migration | B12, B21, B35 | The observation and finding contracts are promoted to v1 by their own records or excluded from 1.0 in one; every versioned format of [versions.md](reference/versions.md) states its compatibility and migration rule, and fixtures show an upgrade read and an unsupported major refused for each |
| B32 | Test isolation, offline use and recovery | B13, B14 | Cross-run, cross-tenant and cross-account attempts are refused in tests; the release archives' supported workflows run with external networking unavailable and fail visibly where a configured service is needed; crash points in the spool, the journals, the floors and the runs directory recover without reusing spent authority |
| B33 | Publish sustained performance | none | A reproducible workload with stated concurrency, duration and conditions runs on a quiet dedicated machine; its tail latency to p99.9, errors and export lag are published with the hardware named, and earlier results are kept beside it. A direct run with the same permissions and upstream work is measured with it; completed calls' latency is reported apart from approval waits, blocked answers, errors and timeouts, and no percentile is published without the samples it needs |
| B34 | Get an outside review and exercise disclosure | none | An independent reviewer, found through a free route, reviews the threat model and the trust boundaries and rebuilds one integration from the public pages; the report is published with each finding fixed or recorded as a limit. One report is taken through the disclosure process end to end and its timings recorded |

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
