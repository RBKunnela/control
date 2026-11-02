# ADR-0047: A procedure states its exceptions, resources and children

Status: accepted
Date: 2026-10-07

Builds on [ADR-0016](0016-approval-providers-and-the-lost-hold.md),
[ADR-0034](0034-a-run-the-operator-opens-has-an-identity-of-its-own.md),
[ADR-0039](0039-many-channels-into-one-core.md),
[ADR-0045](0045-one-run-is-supervised-against-its-procedure.md) and
[ADR-0046](0046-a-finding-stops-one-run-through-a-signed-route.md). Amends
ADR-0045 on the procedure's schema, the rules and a run's children, and
ADR-0046 on what may stop and on a child run.

Amended: a report that names a source in doubt (`sources_in_doubt`: a
`--source` not read, never heard or silent) is schema `"0.2"` whatever its
procedure's schema. Under `0.1` a report keeps `"0.1"` only while every source
was read and heard in time; that is new beside what the Decision and the
Consequences below say
([supervision](../reference/supervision.md#the-finding-record-and-its-log)).

## Context

Milestone 2 asks the supervisor to report a procedure's exceptions and the
attempts to use a resource or permission the run does not hold, a denied
action retried in another form included. ADR-0045's procedure (schema `0.1`)
has steps, an order, extra tools, six rules, a denial count and a deadline.
It has no exceptions, an approved call reads as a planned one, and nothing
reads the `resource` every proposed action carries. `REPEATED_DENIAL` counts
denials of one tool; nothing links a denial to a later call in another form.
A child run cannot be supervised, and `Eligible` refuses to stop one, so an
agent that acts from a child is out of reach of both.

Three constraints shape the answer. Every signed route names a procedure by
digest and a rule by id and version, and a finding's id hashes the rule's
version, so a change that alters what an existing rule finds in an unchanged
document re-ids findings and voids routes. Anything the agent can cause, such
as a failed step or a denial's reason, must not grant it an exception from a
rule that can stop it. And the maintainer asked that what stops a run, and
how children are judged, stay the operator's configuration, with room for
programs of their own.

## Decision

**Schema `0.2` beside `0.1`.** A `0.1` document reads as before, with the same
digest, rules and findings. `0.2` adds `bindings`, a `binds` member on steps
and on `allow` entries, `exceptions` and `children`, all required, each list
with a stated bound. A tool in two bindings, a `binds` naming no binding and an
exception on a rule that refuses one are refused.

**A version per rule.** A rule's `rule_version` is the version of its code;
what a document configures is named by the document's digest. The rules that
may stop keep `"1"`, so a route signed under 0.9 still names what it named.
`STEP_OUT_OF_ORDER` and `CONTINUED_AFTER_FAILURE` are `"2"`: an order between
two proposals of one instant, or with a time missing, cannot be told, and a
place in an export never tells it, since a plane ships several batches at a
time; before, a tie within one export was told by that place. One table in
`internal/supervise` holds each rule's id, version, whether it can be
`CONFIRMED`, whether it may stop a run, and the schemas that know it. Under
`0.1` a report lists the six rules and a record keeps schema `"0.1"`.

**Which run a finding names, and on whose evidence.** Always a run from a
plane event's `run_id`, never a run an observation claims, and that run is
part of the anchor under `0.2`. A finding is `CONFIRMED` only on the named
run's own plane events; one that needs another run's event is `SUSPECTED` at
most. The one exception is a retry by a descendant of the denied run, which is
the denied run acting through its own subtree. So no run's calls can confirm a
finding against another run, and no run can get another one stopped.

- A rule about one call names the run that made it.
- `REPEATED_DENIAL` under `0.2`: a run whose own denials of one tool reach
  `max_denials` gets a confirmed finding; when only the tree's denials reach
  it, each run that made a denial at or after that point gets a suspected one.
- `DEADLINE_EXCEEDED` under `0.2`: each run with an event past the deadline
  gets a finding on its own first such event. The deadline is measured from
  the tree's first event, which may be another run's; it gives only the start,
  no run can move it, and the finding still rests on the late run's own event,
  so it can be confirmed.
- A rule about the procedure as a whole (a skipped step, the order, carrying
  on after a failure) names the supervised run; none of these is ever
  `CONFIRMED`, and a rule the table marks as never confirmed is capped where
  the record is made, whatever the rule computed.

**Bindings and `RESOURCE_OUTSIDE_RUN`.** `bindings` names each binding with the
`resource_type` it holds. A step or allowed tool with `binds: <name>` belongs
to it. The rule fires when the calls of one binding, across the run or its
tree and whatever their outcome, carry more than one distinct resource,
compared as exact bytes of type, id, resource tenant and environment. No call
fixes the binding, so the agent's first choice does not decide what the run
holds, and a denied probe of another id counts. One finding is raised per run
that called the binding; its anchor is the binding and that run. It is
`CONFIRMED` when that run's own calls, in trails not in doubt, carry two
distinct ids; `SUSPECTED` when the two ids need another run's call; `INDETERMINATE` when one id is seen beside calls with none or of
another type; the rule is not checked, with the reason, when no call carries an
id. Ids are not normalised: `"042"` and `"42"` are two resources, and an agent
that spells one id two ways through two tools is caught only by a binding that
holds both tools.

**A denied action retried, in three rules.** A denial is the policy's, read
from the decision's own reason codes: never a plane block, `RUN_STOPPED`, or a
refusal of an approval. After it, across the run or its tree:

- `DENIED_ACTION_RETRIED_ARGUMENTS`: the same tool and upstream with another
  arguments hash;
- `DENIED_ACTION_RETRIED_RESOURCE`: another tool or upstream on the same
  non-empty resource, where a read after the denial of anything but a read
  does not count;
- `DENIED_ACTION_RETRIED_AROUND`: a source's report of the denied tool, by a
  name its step or entry lists, that no plane call joins; `SUSPECTED` at most,
  `INDETERMINATE` with no event time or a join in doubt, and not checked while
  any source is silent, never heard or not read. A span walk that runs out of
  steps leaves this rule and `STEP_OUTSIDE_PROCEDURE` not checked, with their
  findings kept.

A retry whose trail holds an approved decision of the approvals store is not
one. "After" is decided by the plane's own event times within the export both
events were read from, never by their place in it: a plane ships several
batches at a time, so a later batch can be listed first. A later time there
is `CONFIRMED`, the same time or none `INDETERMINATE`; across exports, whose
clocks may differ, `SUSPECTED`; passing a redundant export changes nothing. A
variant proposed before the denial was decided is not a retry;
`REPEATED_DENIAL` is the backstop. Each finding names the retry's run, and its
anchor is the denied request and that run; a retry by any run but the denied
one or its descendant is `SUSPECTED` at most. Each run's retries of a denial
are found on that run's own calls by indexed lookups, with no budget one run
can spend for another, so further retries of one denial keep the id, a new
denial gives a new one, and after a lift or an expiry a new denial followed by
a retry stops again. A corrected argument after a refusal cannot be told from
evasion; whether `_ARGUMENTS` stops a run is the route's choice.

**Exceptions and `EXCEPTION_TAKEN`.** Each exception has an `id`, the one rule
it waives, the step or tool it covers and one condition: `approval: granted`
(an `APPROVAL_DECIDED` approved in that call's trail), `step_failed: <step>`
(that step's `ACTION_FAILED`) or `reason: <code>` (a reason code of that
call's policy decision). A condition is met, not met or unknown. Unknown takes
no waiver and raises the finding the rule would raise, at most
`INDETERMINATE` while the evidence can still arrive: a held approval confirms
nothing until it is refused or expires. Exceptions may waive
`STEP_OUTSIDE_PROCEDURE` (only on `approval: granted`, since it may stop),
`REQUIRED_STEP_SKIPPED`, `STEP_OUT_OF_ORDER` and `CONTINUED_AFTER_FAILURE`;
any other rule refuses one in `0.2`. A waiver taken raises `EXCEPTION_TAKEN`
with the severity and escalation the procedure gives it and a verdict no
stronger than the finding it waived; it never stops a run and is never
waived. An approval is what the approvals store records (ADR-0016); this
record does not prove that its approver was a person rather than an account
with write access to that store.

**What may stop.** `REPEATED_DENIAL`, `STEP_OUTSIDE_PROCEDURE`,
`DEADLINE_EXCEEDED`, `RESOURCE_OUTSIDE_RUN`, `DENIED_ACTION_RETRIED_ARGUMENTS`
and `DENIED_ACTION_RETRIED_RESOURCE`, each at its rule version. One table of these
ids and versions lives in `internal/reaction`, held equal to supervise's by a
test. Verifying a route refuses one that names another rule or version, so
`route sign`, `react`, the plane, doctor and the `stops` commands all refuse it
whole, and the stop-list writer refuses it even from an unsigned route: a route
signed by any other means cannot widen the set. The
route still chooses which of these stop and for how long.

**Bounded findings.** A finding's verdict is decided over all its evidence;
then it cites at most a fixed number of references, the doubtful ones first,
and states how many it left out in `refs_left_out`, so its record fits the
log's line bound whatever the run did. A finding 0.9 could write is unchanged; one past the
bound, which 0.9 refused with the whole write, is now written.

**Children.** `children` is `inherit` or `separate`; a reader refuses another
value.

- `inherit`: `--run` must be a root. The tree is every record whose `Root` is
  it, read by that filter and bounded by the tree's own size, not the runs
  directory's, at a bound whose report still fits the log's line. A tree past
  it is refused loudly; whoever may open runs can make a tree that large. Supervise refuses a tree past its bound, a member of another
  tenant and a parent chain that does not reach the root. The tree counts as
  closed when every member is.
- `separate`: any opened run, its own calls only; the report lists the
  children it did not judge, each of which can be supervised on its own.

**A child can be stopped.** `Eligible` admits an open, unexpired child of the
finding's tenant. A stop still names one run, matched exactly by the plane: a
child's stop leaves its parent and siblings running, and a root's leaves its
children running.

**Contracts.** `guardana.control.finding.v1alpha1` gains `EventRef.run_id`,
`FindingRecord.refs_left_out` and the run tree in the report; a record that
carries any of them is schema `"0.2"`. A
reader of 0.9 refuses such a line by name, as invariant 3 asks.

**Room for programs of the operator's own.** Supervise's rule ids match
`^[A-Z][A-Z0-9_]*$`. A later route kind may carry a structured `detector`
member, absent meaning supervise; no detector is named inside a rule id. The
run tree and each reference's run are in the record, so an outside program can
judge children its own way. Not decided here: a detector registry, a stop from
an outside detector's finding, a stop of a whole tree.

## Security / compatibility impact

No verdict changes and no language model is read (invariants 1 and 2): every
rule is a function of the exports and logs given. A stop still needs a
deterministic, confirmed finding, a signed route that names its rule, and an
eligible run; the rules that may stop are one table, checked where a route is
signed, where `react` loads it and where a plane loads it. The agent can induce
failures and reasons, so neither waives a rule that may stop; a held approval
and a condition not yet known never confirm (invariant 4). A finding names the
run whose event it rests on, so a child cannot push a stop onto its parent.
Under `0.1` the confirmed findings are unchanged. Two changes in the same
release move only findings below `CONFIRMED`: each span walk is bounded on its
own and in total (an observation once in doubt may join), and one liveness
function filters reports by tenant and project as coverage does (a source may
turn silent). A changed verdict is a new log record and so a second alert.
Stopping a child widens what a route reaches to one run the operator opened
under another; a whole tree is still out of reach, and an orchestrator can
open a new child after one is stopped, which the rules judge again. Under
`inherit` a threshold counted only over the tree, with no run reaching it
alone, suspects the runs that took part and stops none; runs that share their
denials stay below a stop, which the alert names. The tree as a whole is not
stopped.

## Alternatives considered

- **Replace `0.1`.** Voids every signed route.
- **Optional members in `0.1`.** One version naming two documents, and a 0.9
  reader refuses them.
- **One version bump for all rules.** Re-ids every finding and voids routes.
- **The first call fixes a binding.** The agent chooses what the run holds,
  and a tool outside the binding reaches any id.
- **A grant on the run record (`runs open --resource`).** Truer to "the run
  holds", but changes ADR-0034's record and asks the operator for ids up front.
- **One retry rule with the form in its anchor.** A route takes all forms or
  none.
- **Anchor a retry on the denied tool.** After a lift or an expiry the agent
  retries freely, since the list already names the finding.
- **Tree rules name the root.** The stop lands on the orchestrator while the
  child that acted runs on, or on nothing when the root is closed.
- **Exceptions as alternative step sequences.** More expressive, a larger
  format and evaluator; later, if named waivers prove short.
- **Rule ids namespaced by detector.** Packs two names into one string, which
  the envelope's own action name already forbids.

## Consequences

An operator who keeps `0.1` documents sees findings past the old line bound
written, and nothing else new. A `0.2` document names its resources,
exceptions and child mode, and its routes are signed again, its digest being
new. A retry of a corrected call may raise `_ARGUMENTS`; the route decides
whether that stops. Every run of a tree that called a binding holding two ids
is named, the one that used the right id included; a route that cannot
accept that leaves `RESOURCE_OUTSIDE_RUN` out. A child the operator opens can
now be stopped on its own.

## Validation

- A corpus of `0.1` inputs gives byte-identical `CONFIRMED` findings before and
  after; other differences only where a join was cut, a source was silent, or
  a finding passed the old bound.
- Ids 42 then 43 under one binding fire, and 43 then 42 with the same ids; a
  denied first call counts; two ids beside calls with none stay `CONFIRMED`; one
  id beside calls with none is `INDETERMINATE`; no id is "not checked"; `"042"`
  and `"42"` through two tools of one binding fire.
- Each retry form fires on its own input and on none of the others; an
  approved retry, a pause block, `RUN_STOPPED` and a variant sent before the
  denial do not; two exports give `SUSPECTED`, a redundant third changes
  nothing; after a lift, a new denial and a retry stop again.
- Under `inherit`: a denial in the root and a retry in its child confirm the
  child; a denial in child A and a retry in its sibling B, or in the root, are
  `SUSPECTED` on the retrying run; 42 and 43 in one run confirm it, 42 in A
  and 43 in B suspect both; a closed child's three denials and the root's
  later ones give the root a finding of its own; each run past the deadline
  gets its own; a root closed with an open child keeps the tree open; a tree
  past its bound, another tenant and a chain that misses the root are
  refused; a report at the bound is written; 1 001 runs of other tenants do
  not refuse a small tree.
- 1 025 denials of one tool and then a retry still give a retry finding; a
  closed child's 4 096 denials and calls leave another run's own retry
  confirmed; a call proposed before a denial but listed after it is no retry.
- A child's confirmed finding stops the child's next call and neither its
  parent's nor a sibling's, on a live plane.
- An exception with an approval waives and raises `EXCEPTION_TAKEN`; a held
  approval gives `INDETERMINATE`, then a refusal confirms; `step_failed` on
  `STEP_OUTSIDE_PROCEDURE` and any exception on `RESOURCE_OUTSIDE_RUN` are
  refused. A table test runs every rule that may stop against every condition
  the agent can induce.
- A route naming `EXCEPTION_TAKEN`, `_AROUND`, a rule never confirmed or an
  unknown id is refused by `route sign`, by `react` and at plane start, also
  when signed directly with the route key; a mutant that admits one fails.
- Ten thousand denials give one finding line under the bound, written, in
  linear time; a doubtful reference past the bound keeps the finding
  `INDETERMINATE`.
- A 0.9 reader refuses a `"0.2"` record by name; `buf breaking` passes on
  `finding/v1alpha1` and holds v1.
