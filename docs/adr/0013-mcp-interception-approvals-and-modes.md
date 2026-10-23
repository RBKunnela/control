# ADR-0013: The MCP gateway intercepts a call before it happens

Status: accepted
Date: 2026-09-19

Builds on [ADR-0004](0004-evidence-and-privacy-defaults.md),
[ADR-0005](0005-canonical-action-digest.md),
[ADR-0007](0007-repository-layout-and-dependency-rule.md),
[ADR-0009](0009-open-core-boundary.md),
[ADR-0011](0011-contract-corrections-before-publication.md) and
[ADR-0012](0012-policy-kernel-semantics.md).

Amended by [ADR-0051](0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md):
the adapter's `Block` capability is a three-valued `Enforcement`, `None`,
`Cooperative` or `Inline`; the MCP adapter is `Inline`, and an adapter whose
caller enforces the decision is `Cooperative`.

Amended by [ADR-0055](0055-a-call-is-handed-out-only-while-its-policy-stands.md): a call, a resumed one included,
is handed out only while the bundle its decision stood on is still installed
and fresh, and a resume judges this before it consumes its approval.

Amended to state the translation the adapter makes of the two methods that are
not tool calls: a `resources/read` and a `prompts/get` are effect `READ`, of
resource type `mcp.resource` or `mcp.prompt` named by the URI or the prompt's
name, served by the plane's one upstream; no override classifies them, and with
more than one upstream they are unclassified.

Amended by [ADR-0016](0016-approval-providers-and-the-lost-hold.md): a hold the
plane loses to a restart is closed from the plane's own hold journal rather than
left open, and a store record the plane no longer holds is resolved as not
resumed instead of spent by the next matching call.

Amended by [ADR-0021](0021-a-run-carries-what-it-took-in.md): the comparison a
retry must pass to resume a held request leaves out the run-context tags under
the flow prefix, since the retry's fresh decision already weighs the run's
flow.

Amended by [ADR-0022](0022-scenarios-are-data.md): only `<ns>/answer` marks an
answer the gateway made. Every `tools/call` answer also carries the request and
decision ids of the trail it belongs to, under the same namespace, and those
two keys mark nothing.

Amended by [ADR-0027](0027-expiry-at-hand-out-and-an-unreadable-lost-hold.md):
an approval's expiry is judged again by the plane's clock right before the
resumed call is handed out, and a call whose approval expired by then is not
sent, with the approval spent. The block answered for an expiry found after
`ACTION_STARTED` carries a decision id that no record on its trail holds.

Amended by [ADR-0032](0032-the-enforcement-mode-has-no-default.md): `mode` has
no default; a configuration that names none is refused at load.

Amended in 0.5.0-alpha: the fields of a `tools/call` block and pending state
travel in the result's `_meta` under the namespace and never as structured
content. A client checks structured content against the schema a tool listed,
perhaps in an earlier listing, which those fields never meet, so the
structured content below is no longer on any answer.

Amended in 0.6.0-alpha: the gateway's cache of shaped lists is also keyed by
the bundle digest, so a list shaped under one bundle is never served under
another.

Amended by [ADR-0042](0042-an-answer-that-quotes-a-configured-credential-is-withheld.md):
an upstream's answer, wire error or listed item that quotes a credential the
plane sends reaches the agent as a fixed answer of the plane's, never with the
upstream's message, data or content, and such a tool definition is never
classified or listed.

Amended by [ADR-0034](0034-a-run-the-operator-opens-has-an-identity-of-its-own.md):
a retry resumes a held request only from the run that was held; a retry from
another opened run is held anew.

Amended by [ADR-0059](0059-a-tools-classification-is-one-type-checked-when-it-loads.md): an override's
classification is one type with the enforcement API's, checked once when the
configuration loads and again by `mcp.New`; one no envelope could carry is
refused there, in every mode.

## Context

The kernel decides and nothing calls it. The first protocol target is the Model
Context Protocol, and its two live revisions are different protocols. `2026-07-28`
has no sessions and no handshake: every request carries its own protocol version,
client identity and capabilities in `_meta`, a POST carries `Mcp-Method` and
`Mcp-Name` headers that must agree with the body, every result says whether it
is complete or needs input, and long-running work moved out of the core into a
Tasks extension a client has to declare. `2025-11-25` keeps sessions, the
`initialize` handshake and server-initiated requests. A gateway has to serve
both, and it has to make one decision that governs both what an agent is shown
(`tools/list`) and what it may do (`tools/call`).

What is decided here rests on a spike: an in-process client, gateway and server
built on `github.com/modelcontextprotocol/go-sdk` v1.8.0, the reference
implementation of both revisions, run on stateless HTTP (`2026-07-28`), on
sessions (`2025-11-25`) and in memory. The Validation section states what it
showed and what it did not. The frozen contract already fixes two things a
gateway design could get wrong: the mode never changes what the matcher decides,
and an approval is honoured only in the trail of the request it was requested
for, the held call.

## Decision

**The pipeline is protocol-neutral and lives in `internal/gateway`; everything
MCP lives in `adapters/mcp`.** `internal/gateway` takes an `ActionEnvelope` and
the proposed arguments, runs the kernel, the approval check, the mode and the
evidence trail, and hands back what to do; it imports no protocol library and
nothing under `adapters/`, and a test refuses the import. `adapters/mcp` is the
listener toward the agent, the client toward each upstream, the router, the
translator from a call to an envelope, the manifest and the shape of every
answer the agent sees; it imports `internal/gateway` and is the only tree that
imports the protocol library. One dependency, one direction, which is the
layout rule of ADR-0007 and the engine with its extensions around it.

**The pipeline answers, it does not fail.** `Admit(ctx, Admission)` returns a
`Disposition` and no error, as `core.Decide` returns a decision and no error:
whatever the pipeline cannot do is a block that names its cause. The zero value
of a `Disposition` blocks, and a pipeline built with no kernel answers
`INDETERMINATE` with `POLICY_UNAVAILABLE` and blocks, so there is one
fail-closed answer and no stub that invents a second. `Close` takes the bytes
that were sent and the result, checks the executed digest and writes the
closing record; `Abort` closes an execution the adapter did not send, and its
closing record says the comparison did not run and names the cause: its own
check before the send found other bytes, an obligation it applies refused the
call, no upstream of its serves the call, or its protocol cannot express what
was authorized. Each cause is recorded as the reason code that names it, so a
record says the bytes disagreed only when they did. `Preview` decides a call as
`Admit` would, the kernel and then the mode, and records, holds and executes
nothing; it is what list shaping asks. The plane checks every identifier it
relies on: its id source is probed at start, a handle already open is refused,
and a request whose id has an open trail is refused before anything is written,
because two trails under one id would interleave.

**The adapter seam is internal, and an adapter declares what it can do.**
`internal/gateway.Adapter` names itself and declares capabilities: observe a
request, observe a result, block, bind an end user, see a delegation, see
resource identifiers, and the obligations it applies, by name, from which the
kernel's applicable set is derived. A table maps every declared enforcement
mode to the capabilities it needs, `UNSPECIFIED` is refused as configuration,
and the gateway refuses to start when the configured mode needs a capability
the adapter does not declare, or when an adapter declares that it binds an end
user without declaring that its listener authenticates one. Both are the
adapter's declarations, because the adapter owns the listener; neither is a
configuration key an operator can set. A refusal at start is the alternative to
an adapter that observes while the operator believes it enforces. Each declared
capability has a conformance test that exercises it against an in-process
upstream, because a declared capability no test exercises is a documented
capability that does not exist. The seam is not `pkg/adapter`: a public package
with one consumer in the tree is a compatibility promise made to nobody, and
ADR-0009 already says the pluggable seams are internal until a separate
decision promotes one. The extension model of the foundation is kept in every
other respect. A declared API version is not part of it: for an extension
compiled into the binary the compiler is the check that fails loudly, and
ADR-0007 forbids the run-time loading that would give a version string
something to guard.

**The interception is one receiving middleware on the agent-facing server.** It
answers `tools/list`, `tools/call`, `resources/read` and `prompts/get` itself and
forwards what the pipeline allows through the upstream client. It registers no
tools of its own. What upstream serves is the manifest: the upstream's
`tools/list` plus the operator's overrides, each entry keyed by a fingerprint
over the whole definition, name, description, input and output schema and
annotations, computed through `internal/canon`, so that a tool whose definition
changed in any part the model reads is a different tool until the operator
classifies it again. A call to a tool the manifest does not hold blocks with
`ACTION_UNCLASSIFIED`, and `tools/list` under `hide` omits such a tool. A
manifest entry says where in the arguments the resource identifier is read
from, as a bounded pointer; that is translation, and no pattern is matched.

**The verdict is made in one place, from the body.** `Mcp-Method` and `Mcp-Name`
route: they pick the upstream and skip what can never be a call. They never
grant and never refuse, and a header that disagrees with the body is the
library's `-32020`. A refusal made from the headers alone cannot echo the
request id, and a client reads a response without one as a broken transport and
closes its session; the spike watched that happen.

**One evaluation drives both enforcement points.** The policy that decides a
`tools/call` also shapes `tools/list` for the same principal, and shaping only
subtracts: `list_shaping` is `none`, `annotate` or `hide`, and `none` under
`OBSERVE` and `SHADOW`. `hide` subtracts what the policy denies and what the
manifest does not classify, and nothing else: a call whose resource is read
from its arguments cannot be decided before those arguments exist, so such a
tool stays in the list and `annotate` marks it as decided per call. A shaped
list carries `cacheScope: "private"` and the operator's `ttlMs`, set by the
gateway itself, because the library's cache hook does not run for an answer the
middleware made, and the gateway's own cache of shaped lists is keyed by the
end-user identity, stamped with the manifest's generation and bounded. The
library offers no way to tell an agent that the list changed while the gateway
registers no tools of its own, so the listener declares that it does not, and
an agent refreshes when the cache's `ttlMs` runs out.

**The bytes sent upstream are the bytes that were authorized.** Obligations
that rewrite arguments are applied first: `redact_fields` removes every
top-level member whose name folds to a named field under the fold canon uses
for duplicate keys, and `cap_amount` lowers the named integer. When a rewrite
changes the bytes, the kernel is asked again about the authorized call, the
proposed envelope with its arguments hash set to the rewritten bytes, against
the same snapshot, and that second decision is the one recorded, bound and
compared, so the decision's, the approval's and the executed digests are one
action digest, as the contract says they are. No rule reads argument values, so
the second decision repeats the first unless the clock moved between them;
either way it is enforced as it is, and the plane refuses to execute on it if
its own obligations would not produce exactly those bytes. The adapter digests
what it is about to send and refuses to send on a mismatch. The disposition an
adapter hands back after the call carries a handle the pipeline minted, and the
closing check recomputes the canonical action digest of the bytes that were
sent and compares it with the recorded decision's, resolving everything from
the pipeline's own record of that handle and never from the disposition's
fields; a disposition the pipeline did not mint is refused, and the closing
record carries the pipeline's own request and execution identifiers. A mismatch
found after the effect is recorded with `EXECUTED_ARGS_MISMATCH`, counted, and
stops the plane from taking material calls until it is restarted, whichever
call's mismatch it was; a closing record the sink refuses stops them until an
append succeeds again (ADR-0014).

**A pending approval never holds the wire, and the held call is resumed.**
`REQUIRE_APPROVAL` returns at once, on every revision, as a tool result with
`isError: true` and structured content `{reason_code: "APPROVAL_PENDING",
approval_id, action_digest, expires_at, retry_after}`, so the model sees it and
can retry. What the gateway holds is not the connection but the request: the
pending record keeps the held call, its `request_id`, its envelope, its binding
and where its trail stands. A retry that matches the binding and equals the
held envelope on the data labels and the run context, the two fields the digest
leaves out that a retry can carry (a fresh request id and fresh timestamps are
what every retry has), is that request again: no new `ACTION_PROPOSED` is
written, `APPROVAL_DECIDED` and then `ACTION_STARTED` go on the held trail, and
the kernel decides again first: the held request resumes only if that decision
equals the held one in verdict, rule identifiers, obligations and digest,
because a trail has room for one decision, and a retry decided otherwise is
held anew as a request of its own, which records its decision; a delegation
that expired or a bundle that went stale in between is a block the kernel makes
before any of this; the approval satisfies the kernel's `REQUIRE_APPROVAL`, or
the `APPROVE` mode's hold on an allowed call, and nothing else: never a `DENY`
and never an `INDETERMINATE`. A retry that differs in one of those fields is a
new request and gets a new pending approval, which is what ADR-0011 means by a
call submitted again. Two requests that differ only in those fields share a
binding, so the store holds every request under a binding and the pipeline
picks the one the retry equals. An approval marked multi-use is refused by this
enforcement point, which consumes once, until a record says otherwise.
Consumption is one compare-and-swap in an approval store whose zero value
approves nothing; a consumed approval is consumed even when the upstream call
then fails, because the effect may have happened, and that failure is a new
request. The next identical call after a consumed approval is
`APPROVAL_ALREADY_USED`. The pipeline holds the request itself: what it minted,
the approval, the envelope, the decision, the binding, the expiry and where the
trail stands, are its own record, and a store answers whether an approver said
yes, nothing more. An approval executes the held request only when the store's
answer matches that record field by field, approval, request, action digest and
bundle, carries an approver, is approved, expires no later than the plane
minted it to and after now, and is not multi-use; the flip from held to running
is one step under the plane's own lock. Because the record is the plane's, a
hold does not survive a restart: a store record from before it resumes nothing,
is spent when a matching call arrives, and that call is held anew. A request
the store cannot hold, or a store that cannot answer, blocks with the plane's
`EVIDENCE_UNAVAILABLE` and every record written; a window the plane opened and
cannot keep is closed with `APPROVAL_EXPIRED` before the block, since the chain
lets nothing else follow a request for approval. The plane holds at most
`MaxHeld` requests and keeps at most `MaxOpen` executions open; past either
bound a call blocks with `EVIDENCE_UNAVAILABLE`. A hold nobody answered is
dropped at its expiry, and the plane closes its trail first, `APPROVAL_EXPIRED`
and then `ACTION_BLOCKED`, before it frees the request id, so no later call can
write a second trail under that id. Under the risk setting that lets a read run
unrecorded, a call whose trail is unrecorded is never held. Who may approve,
and how, is `planned` with the approval providers; this record fixes what the
gateway does with a pending state and with an approved one.

**Neither the Tasks extension nor elicitation carries an approval.** The Tasks
extension is the spec's own shape for long-running work, and it is not used: the
library does not implement it, and its client decodes a `resultType: "task"`
result as a complete, empty, successful call, which is the worst failure for a
pending approval. The extension also forbids returning a task to a client that
did not declare it. Elicitation (`input_required`) is the interactive path
only, for a non-material effect with a user present, and is `planned` with the
approval providers; through this library it needs a registered handler per
tool, which this shape does not have.

**Enforcement modes live in the gateway, after the decision.** The kernel stays
`ENFORCE` only (ADR-0012) and decides every call, in every mode. The mode is
gateway configuration applied to what is done, with each mode meaning exactly
what `common.proto` says, and the kernel's decision is recorded untouched in
`POLICY_DECIDED` whatever the mode did with it. When the block is the
enforcement point's own, under `LOCKDOWN`, on an argument mismatch, on a
consumed approval, on an unclassified action or on evidence that cannot be
written, `ACTION_BLOCKED` carries a decision the enforcement point minted, with
`pdp_type` naming it and the block's code as its reason, and the event's
`enforcement_mode` says which mode the plane was in. Under `LOCKDOWN` every
material call is blocked that way whatever the kernel decided, and a read is
enforced as under `ENFORCE` with fail-open reads off, which the pipeline does
by building its kernel with the setting off, so no reason code is ever read to
decide. `APPROVE` turns an allowed material call into the pending state above
and never relieves a `DENY` or an `INDETERMINATE`. An unclassified call is
blocked in every mode but `OBSERVE`, which lets every call proceed, because
`OBSERVE` is how an operator learns which tools exist before classifying them.
A mode never reaches an extension: the adapter translates, the sink writes, the
policy holder serves a bundle, and none of them knows the mode.

**Three reason codes join the registry**, each emitted by the enforcement point
and never by the kernel or the matcher, which the tests that hold each deciding
package to its own literals pin, the kernel's, the matcher's and the delegation
package's: `LOCKDOWN`, with `DENY`; `EVIDENCE_UNAVAILABLE`, with
`INDETERMINATE`, when the record a decision needs could not be written
(ADR-0014); and `ACTION_UNCLASSIFIED`, with `INDETERMINATE`, when the manifest
holds no entry for the operation a call names and so no effect class can be
given.

**Both revisions, keyed by the negotiated one.** A listener is stateless or
stateful. A stateless listener serves `2026-07-28`; a stateful one serves
`2025-11-25` and older and answers a `2026-07-28` request with `-32022` and the
versions it supports, so a client renegotiates instead of losing the
connection. The negotiated revision keys the compatibility table: where
identity comes from (each request's `_meta` on `2026-07-28`, the session on
`2025-11-25`), which headers exist, what a result may carry. The coverage
matrix, in the adapter's page `docs/integrations/mcp.md` when that page lands,
states per revision and per transport what the gateway enforces.

**A policy outcome the model can read.** A block, a pending approval and an
argument mismatch on a `tools/call` are tool results with `isError: true`,
which the model reads. A `resources/read` and a `prompts/get` have no such
field, so there the same answers are JSON-RPC errors carrying the same
structured data, with codes the gateway allocates outside `-32768..-32000`,
which the protocol reserves, and away from `-31001`, which the library uses
privately: `-31100` for a block and `-31101` for a pending approval. Upstream
wire errors pass through with their own code. Every answer the gateway makes
itself carries a marker under the product's namespace in its `_meta` or in the
error's data, and the gateway strips that namespace from everything an upstream
sends, so an upstream cannot answer as the gateway.

**Identity comes from the listener, never from the client's claim.** The agent
identity an envelope carries, `agent.id`, which the digest covers and a policy
may read, comes from the listener's authentication context or from the
operator's configuration of that listener. `_meta.clientInfo` is what a client
says about itself; it is recorded as a run-context tag and never lands in a
field the digest covers, so two clients with one credential and two names
produce one digest. The agent's credential stops at the gateway: the upstream
client authenticates as the gateway. On stdio there is no authentication
context, and the principal is the one the operator configured for that upstream.

**The gateway supplies the clock, the kernel owns none.** The kernel and the
approval check read the clock the gateway hands them, and a reading of zero,
which would pass every expiry, is refused where it is read.

**The dependency.** `github.com/modelcontextprotocol/go-sdk` v1.8.0 is imported
by `adapters/mcp` and by nothing else; ADR-0007 is unchanged. It sits in the
request path, so a version bump is read, not merged on a green gate. Its
licence, in the module, is Apache-2.0 with contributions not yet relicensed
staying MIT; its row in `docs/dependencies.md` lands with the first import.

## Security / compatibility impact

Every path fails closed and says why: a tool outside the manifest, a policy the
kernel cannot use, evidence that cannot be written (ADR-0014) and a capability
the adapter lacks all block, and each block names its cause in a decision the
reader can tell from the kernel's. Tool annotations (`readOnlyHint`,
`destructiveHint` and the rest) are declared by the party the gateway polices;
they enter the manifest as hints the operator can override and never grant or
deny on their own (invariant 2). The approval binding stays exactly what
ADR-0005 and ADR-0011 make it: one digest, one bundle, one held request,
consumed once.

The wire contract does not change, and the public Go surface does not change.
The structured content of a pending result is MCP-side and carries the
registry's reason code; the three new codes are a registry change and not a
contract change.

Identity on `2026-07-28` is per request and is only as strong as the listener's
authentication; an adapter whose listener authenticates nobody cannot bind an
end user, and the gateway refuses that pairing at start rather than binding a
claim.

## Alternatives considered

- **Protocol code in `internal/gateway`, with an interceptor over a call type
  of its own.** The call type would be the library's request under another
  name, the two trees would need each other's types, and a second protocol
  would have to pull the pipeline out again. ADR-0007 already says where
  protocol code lives.
- **A public `pkg/adapter` now.** It would honour the list in ADR-0007 today
  and settle the shape before a second adapter shows what is common; ADR-0009
  says a seam is promoted by its own decision.
- **Registering the upstream's tools on the gateway as handlers.** It duplicates
  upstream state, has to replay `tools/list_changed`, and answers for a tool the
  gateway has not yet mirrored with an unknown-tool error of its own. It is the
  one shape that can emit a spec-correct `input_required` result through this
  library, so it is the route to elicitation when that path is built.
- **A digest-bound retry: any call with the approved digest executes.** It is
  the model ADR-0011 rejected, it would let a retry with different labels or
  context run under an approval given for other ones, and its trail would show
  an execution with no approval event in it.
- **Holding the call until an approver answers.** Stateless mode forbids the
  server-initiated request it would need, and every client has a timeout that
  turns a slow approval into a failed call and a retry the approver never sees.
- **The Tasks extension.** Not implemented by the library, and a task result
  decodes as a successful empty call.
- **Refusing from the headers without reading the body.** It cannot echo the
  request id and tears down the client's session.
- **`LOCKDOWN` without running the kernel.** It would save nothing and lose what
  policy would have said; and a code appended to the kernel's own decision
  would make the same request decide differently under two modes.
- **Modes in the kernel.** A kernel that decides differently under different
  modes breaks the determinism ADR-0012 promises and the contract's own rule that
  the mode never changes what is decided.
- **A JSON-RPC intermediary without the library.** Two revisions' worth of
  transport, negotiation and header rules to reimplement and keep in step; the
  library is the reference implementation of both.

## Consequences

An operator chooses stateless or stateful per listener, and a mixed fleet runs
two. The gateway owns its list cache and stamps its own identity on what it
answers; forwarded results keep the upstream's. A `DENY` for an obligation the
gateway cannot apply still cannot name the obligation on the wire, which is a
`v1.1` field. The elicitation path and the approval providers wait for the
approvals work; the pending state and its one-shot consumption do not. A second
adapter is what promotes the seam to `pkg/adapter`.

## Validation

The spike: a go-sdk client, gateway and server in one process, 23 tests with 59
runs, all passing under the race detector, on stateless HTTP negotiating
`2026-07-28`, on sessions negotiating `2025-11-25`, and in memory. It showed: an
allowed call reaching upstream once with the agent's exact bytes; a denied call
answered as an `isError` result with the upstream never called; a rewrite
reaching upstream with the capped value and equal digests; the pending state,
the retry still pending, the granted retry executing once and the next refused;
`Mcp-Method` and `Mcp-Name` on upstream POSTs on `2026-07-28` and absent on
`2025-11-25`; a header-only refusal closing the client's session and one that
echoes the id keeping it; the library's `-32020` on a mismatch; `cacheScope:
"private"` on the wire from the middleware and the upstream client caching a
private list regardless; a listener pinned to `2025-11-25` answering `-32022`
and the client falling back; a task result decoding as an empty success. Seven
mutants of the gateway each turned a test red. The spike keyed its grant on the
digest alone and told clients apart by `clientInfo`; both are what this record
rejects, and the tests below are what replace them.

Shown since, by the adapter's and the suite's own tests: two clients with one
credential and two `clientInfo` names giving one digest; stdio end to end with
the configured principal; a tool two upstreams share refused and routed again
when one drops it; `tools/list_changed` refreshing the manifest and a changed
fingerprint blocking; the mode table over every enum value with its refusals at
start; a held request resumed and its trail validating; a retry that differs in
a digest-excluded field held anew; a rewrite decided, bound and closed as one
action digest; a store that lies about an approval refused on every field.
Still not shown: `resources/read` and `prompts/get` end to end as reads, which
have unit coverage only; a trail resumed across a process restart, which a hold
does not survive; and any client other than the library's own, which the
coverage matrix says. What the spike showed about the library and no test in
this tree pins, a `resultType: "task"` result decoding as an empty success
among it, is the spike's own log and is marked as such where it is used.