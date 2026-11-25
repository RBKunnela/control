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
| B06 | Trial the connect guide with three new users | none | At least three new users attempt [connect an existing MCP setup](guides/connect-an-existing-mcp-setup.md) on a server of their own; their time, errors and the help they needed are recorded and published, with each blocker they hit fixed or listed. 1.0 bar: `not met` while no new user takes part; an automated reader's attempt is B43's, labelled simulated with "human participants: 0", and never counts here |
| B23 | Preview and apply an existing MCP configuration | none | Discovery reads the MCP configurations of the supported agent clients on one machine into an inventory; it writes nothing, starts no agent and prints no credential. Tables of the supported clients, and of the paths that bypass the gateway, are published. A supported client configuration is read into an explicit change plan, with paths outside the gateway named. Dry-run writes nothing and starts no server; apply is explicit, preserves unrelated settings and makes an owner-only backup. A second apply is a no-op; undo refuses intervening edits. Verification shows a live allowed and refused or held call, policy version, reported result, coverage gaps and the next operator step in a readable local report linked to its source records. Malformed files, links, concurrent edits and credentials in output have adversarial cases. Setup is measured with three new users. 1.0 bar: `not met` for that measure while no new user takes part |

## Milestone 2: integrations without a fork

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B21 | Attribute an egress proxy's connections to runs | none | A connection the egress access-log importer reads ([ADR-0069](adr/0069-an-egress-proxys-access-log-is-an-independent-sensor-on-a-kind-neutral-descriptor.md)) names a run only as well as the proxy identifies its caller, and an unattributed one stays unknown; `supervise` reads such a source for the runs its connections name |
| B35 | Add a process sensor independent of the agent | none | A second importer reads process events from the agent's host, under a source descriptor marked independent |
| B12 | Publish the port contracts and add TypeScript | none | Sensor, detector, reaction and notifier contracts are published with conformance suites of input and expected output files any language runs, once two consumers have used each. An outside program can write an observation and a finding that names its detector, whose signed descriptor states the highest source class it may claim; an unknown, expired or wrongly signed detector cannot stop a run. A detector's default rule pack is a versioned document whose digest each finding records. An external detector or notifier built from them alone passes its suite. Queue bounds, lag and failures are visible and cannot affect authorization. A held call can be announced through a notifier, a webhook first, then the chat or mail integrations adopters ask for; the notice carries the action digest, the expiry and a link to the held call's existing review, the `console` page or the `approvals list` command, and a notifier's credential grants no approval authority. Replay, spoofing, redaction and delivery failure have cases. TypeScript passes the same client fixtures. A Go seam is promoted only with its own ADR and two consumers; nothing is loaded into a plane at run time |
| B25 | Review changes to tool definitions | none | Compare an operator-reviewed manifest with a newly observed one, name changed fields and old/new fingerprints, and export a bounded report with source and observation time. Reuse the existing classification refusal. Description, schema, metadata, removed and ambiguous tools, and a silent or unavailable source have cases. Review never repins a definition or signs a policy; unchanged definitions do not attest unchanged server code |
| B37 | Measure model-driven attempts and their cost to legitimate work | none | Attempts driven by a model run as a lab job outside CI, from an `attempt-manifest` that names the model and its settings, against the demo's victim, and write the same `attempt-report` with its counts, controls and scope. The scripted set is built ([status](status.md#controlled-attempts)); nothing in either enters the authorization path |
| B36 | Put the remaining decisions about authority behind ports | none | Each decision in [ADR-0066](adr/0066-each-decision-about-authority-is-a-port.md) without a port gets one, its current behaviour as the default, with a closed kind selector, an unavailable state that blocks, bounds, and conformance cases with negative controls: the end user's identity, the policy language, the policy source, the signer, the signature algorithm (its own record first: the v1 bundle names Ed25519), the detector descriptor and the evidence export. `scripts/ports.txt` lists each. The policy language port evaluates a bounded, deterministic condition language with resource limits and explain output, in which a missing fact stays unknown and deny overrides allow; the language and its version are signed with the policy, and a dependency it needs has its record first |
| B40 | Map the controls to the published agentic and LLM risk lists | none | Each list is cited at a pinned edition. Per risk, the page names the control that addresses it and the test that exercises that control, the known bypasses and the gaps, and links B37's results where they apply. A risk with no exercised control is a gap, and no protection percentage is published |
| B44 | Refuse calls outside a declared scope, and flag egress outside it | B21 for the egress half | This is an authorization path: a record of its own first. A scope fixed and signed before a run starts names the hosts, networks, environments and effect classes the run may reach, and a configuration may require one for every run. The gateway reads the target destination and resource from the argument the tool's classification names. If the target cannot be read, the gateway refuses the call. It reads no other argument. A call outside the scope is blocked with its reason and recorded. If the egress sensor attributes a connection outside the scope to a run (B21), that is a confirmed finding, and a signed route can stop later calls in that run; the connection itself is not refused. An unattributed connection stays unknown. B37 adds an attempt that leaves the scope, checked at the victim with positive and negative controls. A run, a child run, a reconnect or a restart cannot widen or reset its scope. No model, and no reading of an argument's meaning beyond the named target, takes part in these decisions |
| B11 | Ship one framework integration | none | One framework integration, chosen by the maintainer with the reasons published, is maintained here against the framework's independently maintained release, passes the client conformance cases of [ADR-0051](adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md) at a pinned version, and has its covered and bypassing tool paths published. 1.0 bar: `own evidence` for the integration qualified against that release. An adopter choosing the framework stays a target after 1.0, as adoption by outside teams does: 1.0 bar: `not met` for that choice while no adopter makes it |

The order is the table's ([ADR-0064](adr/0064-milestone-two-starts-with-an-independent-sensor.md)):
the sensor contract B12 publishes needs a second kind of sensor, and B28
needs both. The process sensor is B35. The egress sensor itself is built
([status](status.md)); B21 adds attribution, so each connection stays
unknown until then. B35 comes later. B25, B36, B37, B40 and B44 block
nothing and go beside them. No task here, or later, adds a model that
approves, takes justification text as authority, decides by pattern
heuristics, or keeps a security control out of the open build
([ADR-0009](adr/0009-open-core-boundary.md)).
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
| B13 | Authenticate operators and scope authority | none | Under `approvals.authority: signed`, each receiver enforces operate and admin from the signed roster ([ADR-0071](adr/0071-operators-are-named-by-a-signed-roster.md), [ADR-0073](adr/0073-an-approval-counts-only-as-the-plane-judges-it.md)). Reads are checked by peer uid against `health.socket_uid` on the health socket and by file modes; the roster's `read` grant is reserved. A client's `Run-Token`, `Authorization` and `Cookie` reach no MCP upstream, and the paths that need a second account are tested under real accounts in a CI job declared required ([ADR-0081](adr/0081-tests-that-need-a-second-account-run-in-a-required-job.md)). A signed plane serves one tenant: a configuration whose `listener.principal.tenant_id` differs from `tenant_id` is refused at load ([ADR-0082](adr/0082-a-signed-document-names-its-plane-and-a-signed-plane-serves-one-tenant.md)), and a signed route may stop a finding's agent or principal, matched against the identity the listener's configuration names ([ADR-0083](adr/0083-a-finding-may-stop-an-agent-or-a-principal.md)). Open: reads and operations of another project are refused at every receiver, not only at the signed ones [contracts.md](contracts.md#signed-files-and-their-project-checks) lists. Under `directory` and `memory`, each receiver judges a project under the same tenant: answers and pauses take `tenant_id`, runs and stops the listener's. A stop of an agent or a principal exists outside `signed` and matches an authenticated end user, which needs a listener authenticator no configuration wires. Two operators with overlapping runs pass adversarial tests |
| B14 | Add retention and recovery | none | Rotation, disk budget, cursor expiry, duplicates, interrupted export and backup/restore are tested for evidence and observations. A restored process cannot reuse spent approval authority. Read-only inspection cannot mutate recovery state without saying so. The findings and observation logs take the RecordLog port, which then moves to its consumer with a read interface, a kind selector, its bounds and its diagnostics ([ADR-0072](adr/0072-the-collector-keeps-bounded-segments-of-one-project-behind-a-credential.md)) |
| B26 | Review findings and export an incident package | B13, B14 | A separate review log records scoped author, time, reason and revision for open/in-review/closed and disposition changes without changing the finding's verdict. Grouped occurrences retain source finding ids, rule versions, tenant/project and run references. Reopening, cross-project access, concurrent edits, export gaps and hostile text have cases. A metadata-only package joins the findings, decisions, approvals, policy/procedure digests, coverage and actual reaction results, marks missing inputs, and is read by an external consumer. Closing a case neither lifts a stop nor grants an approval. Evidence presets are versioned mappings from a named requirement to the records that bear on it, exported with their sources, missing inputs and scope and read by an external consumer; a preset never states a compliance verdict |
| B38 | Show an approver the exact action they approve | B12, B13 | The review of a held call shows its principal, agent, delegation, resource, destination, consequential arguments and bounds, policy reasons and expiry from the held request, bound to its action digest, and names what was redacted or is unavailable. A redacted argument preview is shown only under an explicit setting, off by default. A changed, swapped or stale review, another project's call and hostile text are refused or marked in tests. A held call's notice (B12) links to this review in place of the existing one, and following the link approves nothing. Scripted operator and approver personas exercise the review over appropriate, inappropriate and under-informed cases. 1.0 bar: `own evidence` for that functional half. At least three approvers new to the project explain each case's effect, target and bounds before deciding, over the same cases; a fixed rubric scores the explanations, and the scores are published with the number of participants and cases. 1.0 bar: `not met` for the explanations while no new approver takes part; a persona's answers are simulated, with "human participants: 0". A click or the time spent on the page is not evidence of an informed decision |
| B39 | A run drawn as a graph, with a rule editor beside it | B13, B26 | Starting from the static page `supervise --view` draws today ([run view](reference/run-view.md)), a local page draws one run's steps, decisions, findings and stops as a graph from the evidence and findings exports, marks missing and uncertain steps as such, and shows, for a selected step, the rule that decided it. A rule changed in the editor becomes a policy document that the existing commands test and sign before any plane takes it; the page itself grants and signs nothing. Cross-project access, hostile text in tool names and arguments, and a stale export have cases |
| B41 | Require more than one operator for an approval | B13 | This is an authorization path: changing the v1 approval semantics needs a record of its own first. A call configured for it runs only after distinct roster operators approve the same action digest and bundle before expiry; one rejection wins. Revocation, replay, restart and concurrent spend have cases |
| B28 | Run continuous supervision and authorized reaction | B12, B13, B14, B21, B35 | An operator-configured service follows versioned evidence and observation exports with durable cursors, checks procedures and delivers findings through bounded queues. Source silence, export gaps, sampling, lag and unreadable inputs remain visible and never look like completed work. Restart and replay do not duplicate an authority-bearing reaction. Every stop uses the existing confirmed-finding bar and a signed, scoped, expiring route; unknown or observation-only findings cannot stop a run. Tests exercise concurrent runs, source outage, partial exports, expired authority, replay and notifier failure. A notifier failure cannot grant authority or change a verdict; no reaction cancels an effect already running |
| B45 | Name each event's plane, so a time comparison can confirm | none | Under a later version of the evidence contract, each event and export line names the plane that stamped it, bound so that an export cannot claim another plane's events. A deadline or a retry whose two events one plane stamped may then be `CONFIRMED` and may stop again, under a new rule version and its own record; events of two planes, or of a plane not named, stay `SUSPECTED` at most ([ADR-0088](adr/0088-a-verdict-that-compares-two-events-times-is-at-most-suspected.md)) |

## Release bar for 1.0

Each task here is one item of [ROADMAP.md's release bar](../ROADMAP.md#release-bar-for-10).
The coding runtime's hooks (qualified) and B11 are the two integrations.
Every task the bar names carries its disposition in its acceptance, `own
evidence` or `not met`, as
[ADR-0085](adr/0085-the-1-0-bar-is-met-by-own-evidence-and-what-needs-outside-people-stays-not-met.md)
decides; B06, B11, B23 and B38 carry theirs in their own milestones. What needs
people from outside the project stays `not met`, and the 1.0 release notes and
the status page say so. Own evidence comes from runs whose manifest is fixed
before they start, with failed and cancelled runs kept, effects checked at the
victim with positive and negative controls, and each named security check
run against a deliberately broken copy of the code it guards, which it has to
catch. A result belongs to one commit; a fix to what it
measured voids it, and each release candidate reruns the programme.

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B29 | Make the evidence trail tamper-evident | none | Each event carries a hash link to the one before it in its trail and the plane signs checkpoints over the trails under a key apart from the policy's; a verifier any language can run reports a removed, reordered, altered or appended record and a checkpoint that is missing, stale or signed by another key, with adversarial cases for each and a page stating what the claim covers and what it does not. 1.0 bar: `own evidence` |
| B30 | Maintain a second digest implementation | none | A TypeScript implementation of `digest_v1`, the arguments hash and the approval binding passes every golden and refusal vector of `testdata/digest/` in CI, beside the Go one, and any result that differs from a vector's expected one fails the run. 1.0 bar: `own evidence` |
| B31 | Decide the v1 contracts and their migration | B12, B21, B35 | The observation and finding contracts are promoted to v1 by their own records or excluded from 1.0 in one; every versioned format of [versions.md](reference/versions.md) states its compatibility and migration rule, and fixtures show an upgrade read and an unsupported major refused for each. 1.0 bar: `own evidence` |
| B32 | Test isolation, offline use and recovery | B13, B14 | Cross-run, cross-tenant and cross-account attempts are refused in tests; the release archives' supported workflows run with external networking unavailable and fail visibly where a configured service is needed; crash points in the spool, the journals, the floors and the runs directory recover without reusing spent authority. 1.0 bar: `own evidence` |
| B33 | Publish sustained performance | none | A reproducible workload with stated concurrency, duration and conditions runs on a quiet dedicated machine; its tail latency to p99.9, errors and export lag are published with the hardware named, and earlier results are kept beside it. A direct run with the same permissions and upstream work is measured with it; completed calls' latency is reported apart from approval waits, blocked answers, errors and timeouts, and no percentile is published without the samples it needs. Each release adds these figures to [Benchmarks](reference/benchmarks.md), with the fsync settings named and decision-point waits reported apart, and keeps the raw results. 1.0 bar: `own evidence` |
| B34 | Get an outside review and exercise disclosure | none | An independent reviewer, found through a free route, reviews the threat model and the trust boundaries and rebuilds one integration from the public pages; the report is published with each finding fixed or recorded as a limit. One report is taken through the disclosure process end to end and its timings recorded. 1.0 bar: `not met` for the independent review while no outside reviewer takes part. 1.0 bar: `own evidence` for passes over the threat model and the trust boundaries by other reviewers of the project's choosing, each named as not independent and published with its findings fixed or recorded as a limit, and for a rehearsal that takes a synthetic defect through the disclosure process end to end with its timings recorded |
| B43 | Rebuild from the public pages alone | none | An automated reader with no session history builds the documented workflows, and one consumer of the published contracts, on a clean machine from the public pages alone. Every intervention is logged and published with the result; an attempt that needed one is assisted and is not an unassisted pass. The result is labelled simulated, with "human participants: 0". 1.0 bar: `own evidence` |

## Milestone 4: a fleet and wider protocols

| ID | Work | Depends on | Acceptance |
| --- | --- | --- | --- |
| B16 | Add fleet operations and protocol breadth from demand | B13, B14 | It starts as a read-only inventory of planes: each plane's project, version, last contact, declared paths and gaps. An emergency pause sent to several planes reports each plane's acknowledgement, or unknown where none came. Beyond that, independent deployments demonstrate need; design covers tenant isolation, signed distribution, authenticated APIs and tested recovery. New HTTP/A2A adapters pass conformance. HA and additional stores have reproducible benchmarks before scale claims |
| B42 | Record usage and cost as observations | none | Usage is recorded as observations attributed to their source, priced at dated prices. Usage whose attribution is unknown, and usage with no price, stay visible as such. Usage and cost are never an input to a permission decision |

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
