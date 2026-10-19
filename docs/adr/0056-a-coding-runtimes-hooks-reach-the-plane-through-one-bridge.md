# ADR-0056: A coding runtime's hooks reach the plane through one bridge, by value

Status: accepted
Date: 2026-10-18

Builds on [ADR-0051](0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md),
whose enforcement API the bridge speaks, and
[ADR-0039](0039-many-channels-into-one-core.md), whose ports it is one of.
Amends ADR-0051 on the client that cannot carry a rewrite.

## Context

A coding runtime runs a tool on the agent's machine and, before and after,
starts a hook command per event: the event as JSON on standard input, the
answer in the exit status or on standard output. No two runtimes agree on the
words, most let the tool run when a hook times out, crashes or prints
something unreadable, and none hands a hook the bytes the tool will receive:
each passes a JSON object it serialises again itself. The admit and the
report of one call happen in two processes. ADR-0051's client runs exactly
the authorized bytes and reports them, which a hook can do only for a JSON
value.

## Decision

**One bridge, many profiles.** `guardana-control hook` answers one event. A
runtime surface is described by a profile, data of kind
`hook-profile/v1alpha1` read strictly: which event is an admit, a completion
or a failed completion; where the event name, tool, input, call id, session id
and interrupt flag sit; how a reply is written; the hook timeout and the bound
on an event. Its claims (the runtime and versions tested, the fail-closed
setting, how pending is answered, the tools seen, the bypasses) each name the
cases that back them. A profile holds no script; behaviour data cannot express
is a reviewed change to the bridge. The bridge and its package
(`internal/hookbridge`) name no runtime; a runtime's name appears only in its
profile's files and page and in the paths of links to that page.

**The admit only restricts.** The bridge admits the call with the input's raw
text as the proposed bytes and the call's own request key. Only a full
`EXECUTE` of exactly those bytes lets it run, and then the reply is silence:
exit 0 and nothing on standard output. Every other answer, every failure and
every refusal before the event is read exits with the profile's block status
and one line on standard error; a refusal before any profile is read, a usage
error or a profile that cannot be read, exits 2. The bridge never replies allow, ask or defer,
and never hands the runtime a changed input: allow would skip the runtime's
own permission prompts, ask hands the decision to the local user, and a
deferred call can run through the runtime's own flow. A decision that wants a
rewrite or carries an obligation is aborted with its cause and denied, since
this client cannot carry it. `PENDING` is a deny that names the approval; the
agent's retry is a new admit that resumes the hold.

**The completion reports what ran, by value.** Between the two processes the
bridge keeps only the handle and its expiry, in an owner-only directory, under
a name hashed from the run token, session and call id, published with an
exclusive create. The completion takes the entry with one atomic rename, so a
duplicate completion sends nothing, and sends one `complete` with the input
the runtime reported as the bytes sent. The receiver compares them with the
authorized bytes by `digest_v1`: two inputs are the same call when their
canonical forms are equal, so key order, whitespace, escapes and one number's
spelling do not distinguish them, and anything else does. A difference is
recorded as `EXECUTED_ARGS_MISMATCH` and halts the run. A completion that
carries no input sends nothing; the receiver's sweep closes the call as
abandoned, its outcome unknown. An absent interrupt flag reads as unknown,
never as a clean failure.

**The run token is the operator's**, read from the hook's environment, never
from a flag or the event. The session and call ids from the event name the
handle and the request key and grant nothing; the plane's evidence does not
carry them.

**What a profile may claim.** Nothing over this API is `enforced`
(ADR-0051): the runtime, not the plane, runs the call. A profile is
"decided, not enforced" only where the runtime's setting that blocks a call
on a failed hook is on in settings a user cannot override, the hook command
is an absolute path to a binary the agent's account cannot replace and names
a built-in profile, and the runtime's shell sandbox denies the agent the
plane's directories (approvals, the bridge's store, the socket's directory),
because the hook runs as the agent's account. Otherwise it is "decided, with failure gaps", and its page names
them. Each claim is backed by a case of the profile's fixtures, which run in
every CI without the runtime, or of a qualification against the real runtime
at a pinned version, run before a release and recorded beside the profile;
the page states a claim no case backs as unverified.

## Security / compatibility impact

A hook is a cooperating client: the agent's account runs it and can disable
it, edit its settings where they are not managed, replace a binary or a
profile file it can write, or reach the plane's socket and the bridge's store
itself. Another hook can replace the input after the bridge let the call run;
only the completion shows it, as a mismatch that halts the run. A runtime
refusing a call after the bridge let it run fires no completion; the
handle holds one of the run's open executions until it expires, and a run
whose open executions are all held that way denies every later call until
they do. Tools that do not pass through hooks, a
process a tool starts, and content a runtime loads without a tool call are
not seen. Each is a gap the profile's page states. The wire contract gains
nothing: `request_key` and the three operations exist in v1alpha1.

ADR-0051's client cases assume a client that can run the authorized bytes;
the bridge cannot, and its own tests hold the abort with `ARGUMENTS_DIFFER`
and the deny in their place.

## Alternatives considered

- **Byte identity, hooks refused.** Only an owned wrapper, such as the Python
  client around a tool in the agent's own process, would be integrated; a
  coding runtime would get nothing.
- **Value identity with rewrites handed back** as the runtime's replacement
  input: another hook can replace the input after ours, which only the
  completion would show.
- **Numbers as written.** A runtime that serialises numbers its own way would
  record false mismatches, each halting the run.
- **The plane keeps the handle**, addressed by the request key: the key would
  become a bearer capability, and a lost admit answer would hold its handle,
  against ADR-0051.
- **A bridge daemon or an HTTP hook** holding handles in memory: a listener
  on loopback, which ADR-0051 refuses, and a crash loses every handle anyway.
- **A script per runtime** in place of data: the profile would become a
  language of its own.

## Consequences

Adding a runtime is a profile, its fixtures, a qualification on a pinned
version and a page, with no core change; behaviour data cannot express is a
reviewed change to the bridge. A runtime's hook protocol that changes needs a
new profile version. The first profile's page states its runtime's gaps,
including what the shared account allows.

## Validation

`internal/hookbridge` runs every phase against the enforcement receiver in
front of a plane: an allow publishes its entry and stays silent; a block, a
pending answer, a wanted rewrite, an obligation, an unreachable receiver and
a store others may enter each deny, with the abort owed; a matching
completion is recorded, a mismatching one recorded as a mismatch; two
concurrent completions send one; an absent flag is unknown. Five mutant
bridges (a dropped deny, a carried rewrite, the authorized bytes reported as
sent, an abort in a completion, lenient decoding) each fail the suite.
`cmd/guardana-control` holds every refusal of the command to the block status
and an empty standard output, an allowed admit and a recorded completion to
exit 0, and a receiver that never answers to a block inside the hook timeout.
Each built-in profile's cases state its statuses and timeout apart from it.
