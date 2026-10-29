# ADR-0051: A tool outside MCP is admitted, completed and aborted through an enforcement API

Status: accepted
Date: 2026-10-10

Builds on [ADR-0013](0013-mcp-interception-approvals-and-modes.md),
[ADR-0016](0016-approval-providers-and-the-lost-hold.md),
[ADR-0021](0021-a-run-carries-what-it-took-in.md),
[ADR-0034](0034-a-run-the-operator-opens-has-an-identity-of-its-own.md) and
[ADR-0039](0039-many-channels-into-one-core.md). It is the record
[ADR-0026](0026-first-value-and-external-extension-paths.md) asks for before an
enforcement API is built. Amends ADR-0013's adapter capabilities and
[ADR-0041](0041-coverage-per-declared-path.md)'s coverage table. Amended by
[ADR-0054](0054-the-enforcement-receiver-holds-a-lock-beside-its-socket.md):
the receiver holds a lock beside its socket for as long as it listens.

Amended by [ADR-0056](0056-a-coding-runtimes-hooks-reach-the-plane-through-one-bridge.md): a client that cannot carry a
rewrite, such as a coding runtime's hook, aborts it and denies the call.

Amended by [ADR-0059](0059-a-tools-classification-is-one-type-checked-when-it-loads.md): a tool's
classification is one type with an MCP override's, and a tool whose name,
provider or classification no envelope could carry is refused when the
configuration loads and by `enforce.New`.

Amended by [ADR-0067](0067-the-pipeline-refuses-what-an-adapter-could-not-translate.md): the pipeline, not the adapter,
refuses a translation it could not take and rewritten bytes that name another
resource than the one decided on; strength is an enum whose zero is `None`,
read from the protocol a call names.

## Context

The pipeline in `internal/gateway` is protocol-neutral. `Admit` decides an
envelope with its argument bytes and answers with a disposition: block, hold
for approval, or execute exactly the authorized bytes under an execution id.
`Close` digests the bytes that were sent against the authorized envelope and
writes the closing record; `Abort` records that nothing was sent. The MCP
adapter is its only caller, in the same process, and it builds every envelope
from the operator's manifest: the effect class, the resource and the trust of
a tool come from an override pinned to the tool's definition, never from the
agent.

A tool written in Python inside an agent framework cannot call that pipeline.
Milestone 2 needs a language-neutral way for such a tool to ask before it acts
and to report what it did, so that one policy, one approval store and one
evidence trail cover it as they cover an MCP call. The caller is another
process on the other side of a socket, and three things the in-process adapter
gets for free stop being true:

- The caller can lose an answer, retry, crash between the decision and the
  effect, or time out after an effect may have happened.
- The caller names itself. Nothing it puts in a request is evidence of who it
  is, which run it serves or what its call does.
- The caller can ignore the answer. The plane holds neither the tool's
  credential nor its connection, so a decision returned to a cooperating
  client does not prove the client enforced it.

## Decision

**One adapter, three operations, one unstable contract.** `adapters/enforce`
serves HTTP/1.1 with JSON bodies on a Unix domain socket and nowhere else. The
plane creates the socket with mode 0600 in a directory it owns and checks both
when it binds; a loopback address is refused, since any local account can
reach one. It is a listener kind of `guardana-gateway` beside the MCP kinds,
and one plane serves one adapter, so policy, mode, approvals, runs, pause and
stops are configured as they are today. The operations are
`POST /enforce/v1alpha1/admit`, `/complete` and `/abort`. The messages are a
new package, `guardana.control.enforce.v1alpha1`, in `api/proto`. They reuse
the v1 `Decision` and `Obligation` and add no field to any v1 message. The JSON
is the protobuf JSON mapping, decoded strictly: an unknown field, a body past
its bound or a path naming another version is refused with an error body,
never ignored. Every enum's zero value is `UNSPECIFIED`, and a client reads an
admit outcome it does not know, or `UNSPECIFIED`, as a block. The package is
added to `buf.yaml`'s unstable list and to the configuration
`scripts/proto-breaking-probe.sh` pins, so `buf breaking` keeps examining v1.

**The receiver builds the envelope.** An admit request carries a tool name,
the proposed argument bytes as a base64 `bytes` field so that no JSON library
reorders or reformats them, an optional W3C trace context and an optional
request key. It carries no envelope, no effect, no resource, no identity and
no run. The receiver builds the envelope from the run (below) and from the
listener's tool table, in which the operator gives each tool its effect class,
provider, resource type, the pointer the resource id is read from, the
destination's trust zone and the trust and sensitivity of what it returns, as
an MCP override does. A tool the table does not name is unclassified and
blocked with `ACTION_UNCLASSIFIED`. The plane never sees the tool's
definition, so no fingerprint binds a classification to one: a changed tool
behind an unchanged name keeps its classification, and the record says so.
The trace context is recorded as a claimed correlation, which stops nothing
(ADR-0039).

**An admit answer is one of three outcomes.** `EXECUTE` carries the
authorized argument bytes, the decision, the obligations the client honours
and an execution handle with its expiry. `BLOCK` carries the decision with its
reason codes; the client sends nothing. `PENDING` carries the approval id, the
action digest, the approval's expiry and how long to wait before resuming.
`INDETERMINATE` is answered as `BLOCK`. The client sends exactly the
authorized bytes, which differ from what it proposed when a rewriting
obligation applied, and an `EXECUTE` without them is aborted. It compares
bytes, never a digest: no client computes the canonical digest until a second
implementation passes the golden files in `testdata/digest/`. An obligation
type the client does not know is a reason to abort, never to execute. This
adapter applies no obligation of its own, so the kernel denies a call that
needs one beyond the pipeline's rewriting, as it does for MCP.

**The adapter declares that it cooperates.** The adapter seam's `Block`
capability becomes a three-valued `Enforcement`: `None`, the zero value, for
an adapter that cannot keep a call from its effect; `Cooperative`, for one
that hands a decision to a caller that enforces it; and `Inline`, for one that
holds the path to the effect, as the MCP adapter holds the upstream
connection. `ENFORCE`, `APPROVE` and `LOCKDOWN` need at least `Cooperative`,
so a plane over this adapter decides, holds and records in those modes and
says what it is. The coverage map reports every path a `Cooperative` plane
serves as `decided, not enforced`, with a basis that names the cooperating
client, in every mode; only an `Inline` plane can report `enforced`. A tool
that verified a receiver-signed grant for the exact authorized bytes would
make the tool the enforcement point; that needs a record of its own.

**A handle is opaque, scoped and expiring.** A handle is 128 bits from the
operating system's random source, minted by the adapter and never derived
from request data. It is bound to the run the receiver resolved for the admit
and expires after the listener's execution lifetime, which is required,
bounded and has no default. `complete` and `abort` resolve it only under the
same run token. A handle that is unknown, expired, belongs to another run or
was never minted gets one answer, `HANDLE_UNKNOWN`, which reveals nothing about
other runs. A spent handle answers its own run, until it expires, with how it
ended: `RECORDED`, `RECORD_FAILED`, `UNRECORDED` (a read the operator let run
unrecorded) or `ABANDONED`. Only `RECORDED` says the closing record landed.
These and the contract's other refusals (`DUPLICATE_REQUEST`, a malformed
body) are error codes of the contract, answered before anything is written;
reason codes stay on decisions and closing records.

**Complete records what happened; an uncertain effect stays uncertain.** A
`complete` carries the handle, the bytes that were sent, a status (success,
failure, timeout, cancelled or unknown), the start and end times, a result
hash and a side-effect confirmation, and nothing else; the receiver builds the
v1 result from them. It closes the execution as `Close` does: it digests the
sent bytes under the authorized envelope and records a mismatch as
`EXECUTED_ARGS_MISMATCH`. Over this adapter a mismatch blocks the material
calls of that run until restart and no other run's, since the bytes are a
client's report and a plane-wide halt would let any token holder stop every
run. A mismatch shows a cooperating client's fault; a defecting client reports
the authorized bytes and is not caught by it. A status of timeout or unknown
is recorded as it is, with `retryable` false: the client could not tell
whether the effect happened. The receiver never retries anything, and the
reference client never sends an action again after a handle was issued. A new
attempt is a new admit, decided anew, and an approval spent on the first
attempt is not spent again.

**Abort records that nothing was sent.** An `abort` names one of three
causes, each an existing `Abort` cause recorded as its registry code: the
client's byte comparison failed, an obligation it cannot apply, or it gave up
before sending, cancelled or unable to reach the tool. A client that cannot
tell whether the bytes left completes with unknown, never aborts, since an
abort is a claim that no effect happened.

**An abandoned execution is closed as unknown.** A handle neither completed
nor aborted by its expiry is closed by the receiver: `ACTION_FAILED` with
status unknown and the new reason code `EXECUTION_ABANDONED`, never success and
never blocked, because the receiver cannot know whether the client acted. A
ticker beside the plane's other readers calls the adapter's sweep, which reads
the plane's clock and closes what expired through a new `Pipeline.Abandon`,
bounded per pass. A graceful stop closes every open execution as abandoned
before the spool drains. Only a crash leaves a trail at `ACTION_STARTED`,
which today's readers show as open; journalling open executions across a
restart is left to B14, as a lost hold is closed, never resumed, under
ADR-0016. The evidence report shows a timeout or unknown closing as
uncertain, not failed. supervise reads every `ACTION_FAILED` as failed;
changing that changes the output of its rules, so it waits for its own record
and version.

**Duplicate requests get no second authorization.** There is no idempotent
replay of an `EXECUTE` answer: two callers holding one handle could both act on
it. The receiver mints every request id, so the pipeline's refusal of a request
id with an open trail never applies here. A client may send a request key of
at most 64 characters from `[A-Za-z0-9._-]`, which the adapter reserves
atomically before `Admit` and never writes to a log, a label or the evidence.
A second admit with the key of an execution still open in the same run is
refused with `DUPLICATE_REQUEST` before anything is written, and the first
keeps its handle. Without a key, or once the first execution closed, an admit
is a new request. A client that lost an admit answer never holds its handle:
that execution is abandoned and closed as unknown, and its retry is decided
anew. If the lost admit resumed an approval, the approval is spent and the
retry is told so, which fails closed.

**Pending and resume use the existing hold.** A `PENDING` answer leaves the
request held as an MCP hold is (ADR-0013), in the run that asked (ADR-0034).
The approver decides out of band with `guardana-control approvals approve`.
The client resumes by sending the same tool and bytes in the same run after
the wait it was given. The pipeline resumes a hold whose binding, data labels
and run context match and whose fresh decision has the same verdict, digest,
rules and obligations; a policy reload that changes any of them holds the call
anew. It consumes the approval through the approval store's compare-and-swap,
once: of two concurrent resumes one gets `EXECUTE` and the other is refused
`APPROVAL_ALREADY_USED`. The client never presents an approval, so an approval
is never a token a client can replay. A resume after the hold expired is held
anew with a new `PENDING`; the expired hold's trail gets `APPROVAL_EXPIRED`
from the sweep.

**The receiver owns the scope.** Every request presents a run token
(ADR-0034) in the `Run-Token` header, compared once, in constant time, with the
hash in the run record. The tenant, principal and agent of the call are the
run record's, which must equal the listener's configured identity, as on an
MCP listener without an authenticator. A request with no token, an unknown
one, or one for a closed or expired run is refused with 401 before its body is
decoded, writes no trail and is counted by cause. The token is an
operator-issued capability for one run: whoever holds it acts as that run, and
the socket's owner and mode limit who can present one. Authenticated
operators and principals of their own are B13's.

**Conformance is files.** `testdata/enforce/` holds the contract's cases as
input and expected output files any language can run. `receiver/<case>/`
holds the setup (policy, mode, run, a scripted clock), the exchange (each
request and the answer it must get, with matchers for minted values) and the
event kinds and codes the trail must hold. `client/<case>/` holds scripted
receiver answers and what a client must do about each: whether the tool is
reached, the bytes it sends, the abort cause or the completion status.
`cases.json` lists every case with the contract version and the negative
control that must fail it. A Go test runs both directories against the adapter
and an in-repository reference client; a client in another language runs
`client/` against its own file-driven receiver. The cases: block before send,
rewritten bytes, pending then resume, two concurrent resumes, an unknown and
an unspecified outcome, an unknown obligation, a timeout before and after a
possible effect, cancellation, completion, a duplicate request key, an
abandoned handle, an expired, foreign and spent handle, a missing and a
foreign run token, an unclassified tool, an unknown field and an unknown
version.

## Security / compatibility impact

No model, pattern or client claim enters the decision: the kernel decides an
envelope the receiver built from the operator's classification and the run it
resolved. Every failure the adapter cannot resolve blocks: an unreadable
request, a run that does not resolve, a sink that refuses the trail, a
pipeline past its bound on open executions, an outcome a client does not
know. An approval binds the exact action digest and is consumed once; a
handle is single use. A non-idempotent effect is never retried by the receiver
or by the reference client.

The adapter is not a security boundary, and its coverage never says
`enforced`. A client can ignore any answer, send other bytes than it reports,
or report an effect that did not happen; the plane records what it was told.
A stolen run token acts as that run until the run closes or expires. The
classification is the operator's, by tool name, with no binding to what the
tool does.

Argument bytes reach the plane over the socket, as an MCP call's do; capture
stays off by default, the result travels as a status and a hash, and hidden
reasoning is never sent. The v1 contracts, the digest and its goldens and the
reason-code numbers already assigned do not change; one code is appended. The
MCP adapter declares `Inline` where it declared `Block`, which changes no
behaviour. The listener needs a Unix socket, so this adapter runs on the
platforms the releases ship, Linux and macOS.

## Alternatives considered

- The client sends a v1 envelope and the receiver overwrites the fields that
  carry authority: every v1 field added later would be a hole, and the client
  would still choose data labels and delegation the policy reads.
- An observe-only adapter: honest and simplest, but no approval and no hold
  for a Python tool, which is what milestone 2 is for.
- gRPC, or Connect: typed clients for free, but a new dependency in the
  request path and a toolchain a Python user installs before a single call;
  JSON over HTTP needs neither, and the contract stays protobuf.
- Replaying an `EXECUTE` answer to a duplicate admit: lets a client that lost
  the answer go on, but hands one authorization to two callers when the
  duplicate was a second worker, not a retry.
- An approval token the client presents on resume: a bearer approval can be
  copied to another run or process; the store's binding cannot.
- A caller credential of its own, mTLS or the socket's peer credentials:
  stronger answers to "who calls", each a new store or platform code; the run
  token already binds a run to a principal and an agent through a record the
  operator wrote, and B13 will add an authenticator for every listener.
- A plane-wide halt on a reported mismatch, as for MCP: one client could stop
  every run.
- A loopback listener: reachable by every local account.

## Consequences

A Python tool, and any language with HTTP, JSON and a Unix socket, can be
decided by the same policy, approvals and trail as an MCP call before B11
writes a client. The operator classifies each tool of an enforcement-API plane
by name, as they classify MCP tools. The plane gains a listener kind, a tool
table, an execution lifetime, a sweep, a run-scoped halt, one reason code and
a three-valued enforcement capability, and the binary's wiring stops assuming
the MCP adapter. An integration built on this API is cooperative by
construction, so its coverage is never `enforced`. A lost admit answer can
spend an approval, which costs the user a second approval and never a second
effect.

## Validation

- The conformance files run against the adapter and the reference client in
  `make test`, and each case's negative control fails when the behaviour it
  pins is removed.
- An end-to-end test drives one tool fixture with a cooperating and a
  defecting client under the same policy: after a `BLOCK` the cooperating
  client never reaches the tool, the defecting one does, neither trail shows
  `ACTION_STARTED`, and the coverage map reports the path `decided, not
  enforced`; an MCP plane in front of a tool of the same classification
  reports it `enforced`, and a defecting MCP client never reaches it.
- A mode test refuses `ENFORCE` for an adapter whose enforcement is `None`
  and accepts it for `Cooperative`; a coverage golden shows a `Cooperative`
  plane in `ENFORCE` as `decided, not enforced`.
- Adversarial tests: two concurrent resumes of one approval, two concurrent
  admits with one request key, a handle from another run, an expired handle,
  a replayed `complete`, an admit under a closed run, an admit body with any
  field outside the message, an argument over its bound, a client that never
  completes, a mismatch reported by one run while another run keeps
  executing, and a timeout reported after a possible effect.
- `scripts/proto-breaking-probe.sh` fails when the new package is left out of
  its pinned configuration, and `buf breaking` still examines v1.
