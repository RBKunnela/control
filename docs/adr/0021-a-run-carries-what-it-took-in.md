# ADR-0021: The plane keeps what each run took in, so a flow rule can fire

Status: accepted
Date: 2026-09-24

Builds on [ADR-0011](0011-contract-corrections-before-publication.md),
[ADR-0012](0012-policy-kernel-semantics.md) and
[ADR-0017](0017-an-external-decision-point-can-veto.md).
Amends [ADR-0013](0013-mcp-interception-approvals-and-modes.md) on what a retry
has to equal to resume a held request.

Amended by [ADR-0034](0034-a-run-the-operator-opens-has-an-identity-of-its-own.md):
a run the operator opens, with a token, has an identity and a durable state of
its own, and a plane without a runs directory keeps the runs this record
defines.

## Context

The contract's toxic-flow predicate answers whether a call moves data read
under untrusted influence, at or above a floor, to a destination that is not
trusted, and the policy format reads it as `when.flow.toxicAtLeast`. It needs a
`FlowState` that the receiver computes and never decodes from a producer.
Nothing computes one. The gateway hands the kernel the zero value, which the
predicate refuses, so every flow rule is undetermined through the gateway, and
the threat the foundation puts first, untrusted input carried to an external
sink, cannot fire.

Three facts shape any tracker here. The MCP adapter sets no data label on an
envelope, and cannot: what a call carries is the model's text. The manifest's
`trust_zone` says where a call sends data, not what its result contains, and a
server trusted as a destination can return text an attacker wrote. And every
boundary a client can draw, a session, a connection, a `_meta` value, is the
client's to redraw: a client that initializes again gets a new session while
the model keeps its context. The MCP library offers no public hook when a
session ends, and a listener with no idle timeout never closes one.

## Decision

**A run is the listener and its authenticated principal, on every transport.**
The pipeline keys a run by the principal the listener resolved (its tenant,
type and id) and the agent the listener names, and mints the run's id the first
time it sees that key. With no authenticator, which is every listener in this
build, that is one run per plane process. A session, a connection and `_meta`
never split a run: each is drawn by the client, and none resets what the model
saw. A restart ends every run. The run's id is written as `Event.run_id` on
every event of its trails. The envelope's `context.run_id` stays what the
producer sent, empty through MCP, and never selects a run. No session id is
recorded: on a listener that authenticates nobody it works as a bearer
credential.

**What a tool returns is declared apart from where a call sends.** An override
gains `returns.trust`, the trust zone of what the tool's results contain, and
`returns.sensitivity`, the highest sensitivity they can hold. Both are
restrictive when absent: no `returns.trust` is untrusted, as an unspecified
zone is, and no `returns.sensitivity` is unknown. `trust_zone` keeps its one
meaning, the destination. The adapter hands both to the pipeline beside the
envelope, in fields whose zero values are the restrictive answers, and never
sets `data.sensitivities` from either. A declared `PUBLIC` result copied into
an envelope's labels would turn the predicate's unknown into a known part below
the floor, and let a call through while the model holds whatever the user gave
it.

**The pipeline keeps the state.** Per run, two values: `untrusted`, false at
the start, and `max_read`, `PUBLIC` at the start. When the pipeline hands an
execution out, under its own lock and before it returns, it sets `untrusted` if
the call's result is not declared trusted, and raises `max_read` to the call's
declared result sensitivity; an undeclared sensitivity makes `max_read` unknown
for the rest of the run, and so does a sensitivity outside the scale this build
names. Unknown absorbs because it is the only reading that
stays sound once an envelope carries a label: after a known `INTERNAL` result
and an undeclared one, a run read as `INTERNAL` would put a `CONFIDENTIAL`
floor out of reach of data the run may hold. Every execution counts, a read
that runs unrecorded under the risk setting and one the adapter later aborts
included. A result reaches the model only after its execution was handed out,
so no call whose arguments could carry that result is decided before the
update, and no adapter call or evidence outcome sits between an effect and its
taint. `Admission.Flow` goes: the pipeline alone computes the state.

**A call reads its run's state once.** It takes the state when it starts, with
the policy snapshot, and uses it for every decision it makes, the second one on
the rewrite path included. A call whose principal cannot be keyed, or whose key
is past `flow.max_runs`, is decided with the state nobody computed, which the
predicate refuses: its flow rules are undetermined, and it is counted. A call
the pipeline can key but whose run it cannot name, because the id source gave
nothing, is blocked with `EVIDENCE_UNAVAILABLE` in every mode, since running it
would taint no run. A call handed in with a refusal mints no run and reads the
one its principal has, except under `OBSERVE`, where it runs and so has to
taint. The kernel's own checks come after the mint, so an envelope handed in
unchecked and refused there still takes its principal's run; the MCP adapter
checks every envelope before it hands it in. `flow.max_runs` is 64 by default;
`/healthz` reports the runs and the calls decided uncomputed, and `doctor` each
override's declared results. No run is evicted, because dropping one would wash
its taint. `Preview` always uses the state nobody computed, because a list is
cached per principal and outlives any state; a tool a flow rule governs is
listed as decided per call, as before.

**The trail says which state a decision used.** Before it decides, the pipeline
stamps the state on a copy of the envelope as run-context tags under a
versioned prefix that names no product: `flow.v1.untrusted=` `true` or `false`
with `flow.v1.max_read=` a sensitivity name or `UNKNOWN`, or
`flow.v1.state=uncomputed`. `ACTION_PROPOSED` records that copy. An envelope
whose producer already sent a tag whose ASCII-lower-cased form begins `flow.v`
is blocked by the plane, in every mode, `OBSERVE` included, with
`INVALID_FIELD_VALUE`, or with the code of a refusal the call already carried,
and what is recorded is a copy with every such tag removed and
`flow.v1.state=uncomputed` stamped, so no producer can forge the state a trail
shows. A decision point asked about the call is asked about the stamped
envelope; mapping version 1 sends no run context, so the question is the same.
The tags sit outside the digest and the binding, as the whole run context does,
and the matcher reads no run context, so the kernel stays deterministic: the
tags are a function of the `Flow` input it already takes.

**A retry resumes on its decision, not on the flow.** ADR-0013 resumes a held
request only for a retry equal to it on the data labels and the run context.
That comparison now leaves out the tags under the flow prefix. The retry's
fresh decision already reads the run's current state and has to equal the held
one in verdict, rule ids, obligations and digest, so a flow that matters stops
the resume, and a flow that does not cannot starve the approval of an agent
that kept working. `docs/contracts.md` says so where it states what a retry
must equal.

**What a flow rule means through MCP.** An MCP call carries no data label, so
once a run has taken in anything untrusted, a `DENY` rule on
`flow.toxicAtLeast` blocks every call of that run to an untrusted destination:
a `DENY` with the rule's reason when the run is known to have read at or above
the floor, `INDETERMINATE` otherwise. The floor chooses between the two and
does not change what runs. The concept page and the demo show both in one run:
after the untrusted read and before anything sensitive, an innocent call to an
untrusted destination blocked as undetermined; after the sensitive read, the
toxic flow denied, as every call to an untrusted destination then is.

## Security / compatibility impact

No frozen wire contract moves: `tags` is a repeated string whose content the
contract leaves to the producer, the digest and the binding exclude the run
context, and `Event.run_id` gets its first producer. `docs/contracts.md` gains
the tag vocabulary and the narrowed retry rule, a contract statement changed
with this record. A `FlowState` is now computed from validated envelopes and
from the operator's declared classification of results, and the page and the
type's comment say so.

The state over-restricts and never under-restricts within what the plane sees:
concurrent sessions of one principal share their taint, and a plane with a flow
rule blocks every untrusted destination after its first untrusted result until
it restarts. Nothing here grants: the state can only make a flow rule match or
leave it undetermined.

## Alternatives considered

- **A run per session, per stdio connection or per stateless listener, its id
  minted by the adapter.** A client that initializes again washes its taint;
  with no session-end hook the state leaks, and any client can fill the bound
  by opening sessions.
- **A run id from `_meta`.** The client's claim, with the same washing.
- **The update at `Close`.** Exact for calls running side by side, and sound
  only while every adapter closes every delivered result and the update comes
  before any evidence outcome.
- **The destination's zone read as the source of influence.** It misses a
  trusted server returning an attacker's text, and trusting a partner as a
  destination would also trust everything it returns.
- **The state as a field of `Decision`.** A wire change that every strict 1.0
  reader refuses.
- **No run state.** Every flow rule undetermined: honest, and the demo's toxic
  flow could only ever read `INDETERMINATE`.

## Consequences

A bundle's flow rules decide through the gateway for the first time. An
operator declares `returns.trust` and `returns.sensitivity` for each tool that
should not taint its run as untrusted and unknown. A plane with a flow rule
turns strict after its first untrusted result, until it restarts, so a scenario
that needs a clean run needs a fresh plane. Each recorded proposal carries two
short tags more.

## Declared limits

- A run starts clean. The user's prompt, tools that do not pass through this
  plane and the tools' own descriptions are not tracked: the state is a lower
  bound on what the model saw, and it means something only when every tool
  sits behind the plane.
- Without a runs directory: one run per plane until a listener
  authenticates, and a restart ends it. On stdio the plane ends with its
  client's connection, so there a run lasts one connection, and a client that
  connects again starts a new plane and a clean run.
- With one (ADR-0034): a run is one the operator opened, and its root's state
  outlives the process. Data two runs exchange outside a declared parent, such
  as two siblings an orchestrator bridges, is not seen; and a run closed after
  its call passed the listener still runs that call.
- A resource read and a prompt carry no declared result: each makes its run
  untrusted and its reading unknown for the rest of the run, and no key says
  otherwise.
- Once a run has read an undeclared sensitivity, a floor answers undetermined
  where the truth may be a denial. Both block; the evidence is weaker. The exact
  state, a known maximum beside the fact that an unknown was read, is a
  `pkg/contract` change for a record of its own.
- The stamped tags share the envelope's bound on tags with the producer's own;
  an envelope already at the bound is refused.
- Notifications and requests an upstream sends are not tracked as influence.

Amended in 0.19: `prompts/list` and `resources/list`, like the tools'
descriptions, are listings that leave a run's flow state clean. What a listed
prompt or resource says reaches the model untracked until a `prompts/get` or a
`resources/read` of it.

## Validation

The exit criteria of the change that brings this record:

- A key past the bound, and a call the pipeline cannot key, reach the kernel
  with the state nobody computed, and a flow rule is undetermined, never false.
- Two stateful sessions of one principal, a stateless listener, and a client's
  own session header under the library's debug setting all share one run; a
  session opened again keeps the taint.
- Taint at hand-out: a call admitted while an earlier one is still running sees
  the earlier one's taint, and an adapter that never closes and a sink that
  refuses every closing record still leave the run tainted.
- A property over random sequences of declared and undeclared results and every
  floor: the state never answers "not toxic" where the true maximum reaches the
  floor, and the non-absorbing mutant fails it once a label is present.
- `trust_zone: PARTNER` with no `returns.trust` taints; a trusted
  `returns.trust` relaxes no destination.
- The adapter sets no `data.sensitivities`, over every override combination.
- Resume: a held request, a call in between that changes the flow, an approval
  and a retry: it resumes when the fresh decision equals the held one, and is
  held anew when a flow rule now matches.
- Tags: a producer's tag under the prefix is refused; the stamped tags pass
  chain validation and the JSONL codec; the determinism property gives the same
  verdicts, rules and codes with and without them.
- `Preview` in a tainted run answers what it answers in a clean one.
- End to end, in one run: after an untrusted read, an innocent untrusted call
  blocked `INDETERMINATE`; after a sensitive read, the toxic flow denied with
  `TOXIC_FLOW_SENSITIVE_TO_EXTERNAL`; and no event carrying the session id.
