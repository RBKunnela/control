---
title: Adoption and incident workflows
summary: Planned acceptance requirements for MCP setup, coding hooks, tool-definition review, policy simulation and incident review.
type: project
covers: [adapters/**, cmd/**, internal/gateway/**, internal/gatewayconfig/**, internal/policy/**, internal/supervise/**, internal/findinglog/**, internal/coverage/**, examples/**]
---

# Adoption and incident workflows

Status: `planned`. These requirements define backlog B23 and B25–B27 and the
bar for a further coding runtime's hooks; they do not describe commands or
contracts available today. [status.md](status.md)
is the implementation inventory, [the backlog](backlog.md) holds acceptance
checks, and [ROADMAP.md](../ROADMAP.md) owns milestone order. The delivery
decision is proposed in [ADR-0050](adr/0050-adoption-workflows-preserve-authority-and-evidence.md).
Each implementation that introduces a format, an adapter or authority needs
its own accepted design record before code.

The first users are engineers connecting a tool to an agent and operators
investigating a run. Each workflow must answer: what path was covered, what
action was permitted or refused, which policy made that decision, what the
tool actually reported, and what remains unknown. A content detector's score
is never a substitute for structured authorization.

## B23 Preview an existing MCP setup

Read one documented client's existing configuration and produce a change
plan. The plan names each file and server affected, the old and new route,
the selected mode and identity assumptions, and paths that remain outside the
gateway, including built-in tools. Credential values, environment values and
tool content must not appear in the preview or logs.

A dry-run writes no configuration and starts no upstream process. It reports
unsupported configuration shapes and unreadable files explicitly. Applying
the plan requires an explicit operator action, an owner-only backup, a check
that the input has not changed and a bounded atomic write. Preserve unrelated
settings. A second application makes no further change. Undo compares the
current file with the applied output and refuses an intervening user edit
rather than replacing it.

Installation never infers authority from a tool description, sets an enforcing
mode silently, repins a classification, widens an environment allowlist or
starts a server discovered in a file. The operator classifies tools and names
the mode, as [ADR-0013](adr/0013-mcp-interception-approvals-and-modes.md) and
[ADR-0032](adr/0032-the-enforcement-mode-has-no-default.md) require. Verification
after apply names a live allowed call, a refused or held material call and
their evidence; reading configuration alone cannot establish enforcement.

The first local report uses those source records to explain the proposed
action, policy version, decision, known or uncertain tool result and the next
operator step. It names coverage gaps and identity assumptions beside the
outcome. An engineer can follow the record identifiers into the existing
exports; an operator can see what needs review or a separate authorized
reaction. Measure whether new users can explain that result, as well as
whether they finish setup.

Acceptance includes malformed files, symbolic links, unsafe ownership,
concurrent edits, repeated apply, interrupted writes, undo after user edits
and credentials in failure text. Three voluntary onboarding sessions record
time, assistance, failures and the first controlled action on the user's own
setup. A successful install is not counted as that first action.

## Qualify a coding runtime's hooks

One runtime's hooks are built and qualified; [status.md](status.md) says how
far. A second runtime waits until adopters name one, and meets these
requirements. Pin the runtime and hook protocol versions and
publish a table for each event: proposed or already completed, enforcement
or observation, identity source, rewritten-argument support, approval/resume
support, deadlines, failure behavior and known bypasses.

A pre-action hook decides a call and is never an enforcement point: the
runtime, not the plane, runs it, and no hook hands over bytes, so what it can
show is that the value that ran is the one authorized
([ADR-0056](adr/0056-a-coding-runtimes-hooks-reach-the-plane-through-one-bridge.md)).
Calling an evaluation endpoint and discarding its answer is not enforcement.
If a hook cannot apply a required obligation, it refuses the action in an
enforcing mode. If it cannot resume an approval safely, it declares that
limitation and never turns pending into allow. Completion and failure hooks
are sensors: they cannot prevent an effect that already happened. Evaluate
tools that spawn processes separately; intercepting their launch does not
establish coverage of every child effect.

Identity and run binding are receiver-owned. A session or trace id supplied
by the agent correlates records and grants nothing. Material actions fail
closed on unavailable policy or required evidence unless an explicit risk
setting says otherwise. A runtime that proceeds on a timeout cannot be
labelled an enforcing boundary for that path. Disabled hooks and missing
post-action reports remain a coverage gap or an unknown result. No uncertain
material execution is automatically replayed.

Conformance covers block-before-effect, changed arguments, unknown
obligations, absent and forged run identity, missing hooks, malformed replies,
service outage, timeout before and after a possible effect, cancellation and
two concurrent resumes of one approval. Publish the bypass tests with the
integration. The design uses the enforcement API's admission and completion
([ADR-0051](adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md)) and
[ADR-0039](adr/0039-many-channels-into-one-core.md)'s ports; an
OpenAI-compatible model proxy alone does not cover local tool execution.

## B25 Review tool-definition changes

Compare the operator-reviewed definition with the newly observed definition.
The bounded report names the upstream, tool, old and new fingerprints,
changed fields, observation time, source and classification state. Cover
descriptions, input and output schemas, annotations and metadata, plus added,
removed and ambiguous tools. Any claim about a server package, certificate
or executable needs a separately obtained source; a definition fingerprint
does not attest the implementation behind it.

The gateway already refuses a refreshed definition whose fingerprint no
longer matches its override, outside `OBSERVE`. This task adds a review
workflow to that behavior. It does not add a semantic detector or presume
every wording change is malicious. A silent server, a missing notification
or a failed refresh is reported with the last observation and its limits;
the report cannot guarantee the server disclosed a change.

Reviewing the diff never approves an action, rewrites an override or signs a
policy. The operator explicitly reclassifies and tests any replacement.
Acceptance includes each changed field, removed tools, name collision,
unreadable definitions, withheld credentials, an unavailable source and an
unchanged definition behind which test server behavior changes. The last
case demonstrates the limit instead of claiming supply-chain protection.

## B27 Compare and simulate a candidate policy

Compare current and candidate policy documents, then evaluate explicit cases
through the kernel's own evaluator. The report names both document digests,
the evaluation semantics, the source of each input and the before/after
verdict, reasons, obligations and missing facts. Surface newly permitted
effects and resources, changed approval requirements, undeclared facts and
conflicting rules. Never resolve a conflict by inventing a second precedence
order.

Historical evidence usually contains hashes rather than arguments. A hash
cannot reconstruct them. A comparison based on exports must mark any
argument-dependent, flow-dependent or freshness-dependent result unknown
when the input needed for it is absent. An operator-supplied fixture can
support a result only with its origin and assumptions stated. Report the
number evaluated, changed and unknown, with their denominators; do not call
partially reconstructable runs a complete replay.

Simulation sends no tool call, consumes no approval, publishes no bundle and
activates no policy. Model or heuristic suggestions are drafts requiring
operator review, tests and signing. Acceptance covers effect/resource
broadening, conflict, unsupported versions, gaps, duplicate records, absent
arguments or flow context, missing historic policy and changed tool
definitions. The current `policy explain` and `policy test` remain the
starting point; policy rollout and shadow evaluation of live traffic need
separate designs.

## B26 Review findings and export an incident package

Start with a consumer of the existing findings export. Group related
occurrences without replacing their source records. A group key includes
tenant, project, rule id and rule version plus an explicitly defined bounded
signature; preserve every source finding id and run reference. Repeated
delivery cannot create a second occurrence. Unknown or truncated references
remain visible, and an event count, occurrence count and case count are
distinct measures.

Keep four independent states:

| State | What it means | What may change it |
| --- | --- | --- |
| Finding verdict | Whether cited inputs support the finding: confirmed, suspected or indeterminate | A new deterministic evaluation, with its provenance |
| Review state and disposition | Open, in review or closed; an operator may record confirmed issue, false positive or accepted risk as a separate disposition | A scoped, authenticated review action |
| Notification delivery | Whether an alert reached its configured recipient | A delivery acknowledgement |
| Reaction result | A scoped stop, its expiry or a lift, or a failed/unknown reaction | The separately authorized reaction path |

A review is an append-only record with author, time, reason, previous revision
and subject id. Concurrent updates cannot silently overwrite each other.
Closing or dismissing a case cannot alter the finding's verdict, authorize a
call, consume an approval, lift a stop or retune a policy. New evidence can
reopen a case and retains its history. Cross-project grouping, reads and
updates are refused. This depends on B13's authentication and B14's recovery;
the CLI's current configured principal is not proof of a reviewer identity.

Export a bounded, versioned incident package with finding and review records;
the relevant action, decision, approval and result references; policy and
procedure ids, versions and digests; source trust and correlation basis;
coverage gaps; and reaction attempts and results. Include only available
metadata by default. A missing policy body, missing segment, silent source or
unconfirmed delivery is named, never reconstructed as fact. No prompts, tool
content or hidden reasoning are added for the convenience of investigation.

A consumer can read the package independently, check references and report
missing inputs. Export resumes with stable identifiers and explicit gaps.
Ordering or a digest of a package alone is not tamper evidence; hash links and
signed checkpoints require their own implementation. Acceptance includes
duplicate delivery, later occurrences after closure, reopening, conflicting
review revisions, cross-project access, lost inputs, hostile text, bounds
and a failed reaction that must not be displayed as a successful stop.

## Delivery and communication

B23 belongs to first value. B25 and B27 belong to integrations; B26
belongs to a small team. Existing trust, API, identity and retention work
remain prerequisites. No schedule or SLA is implied.

Describe a capability with its consequence, covered path, enforcing mode,
failure behavior and a runnable example. Use exact-action approval, a changed
tool definition and a denied refund retried another way as current examples.
Describe the coding-runtime hooks only as far as their qualification and
failure gaps go, and keep incident review out of claims about what runs today. Measure gateway overhead separately from end-to-end policy/evidence
latency, with workload, platform, concurrency, percentile and failures named.
Do not claim universal agent coverage, autonomous real-time supervision,
tamper-evident evidence or regulatory compliance from these requirements.

Reversible PII tokenization, a vault, model-based content classifiers and
automatic policy tuning are outside this delivery scope. A later proposal
needs an adopter's data flow, trust direction, transform/approval binding,
failure semantics and privacy design; it cannot silently add raw content
capture or a model to default authorization.
