# ADR-0027: An approval's expiry holds until the call is handed out, and an unreadable lost hold is unknown

Status: accepted
Date: 2026-09-27

Builds on [ADR-0013](0013-mcp-interception-approvals-and-modes.md),
[ADR-0016](0016-approval-providers-and-the-lost-hold.md) and
[ADR-0019](0019-an-operator-can-pause-calls.md).
Amends [ADR-0013](0013-mcp-interception-approvals-and-modes.md) on the moment
an approval's expiry is judged and on the decision id of one block's answer,
and
[ADR-0016](0016-approval-providers-and-the-lost-hold.md) on the code a lost
hold is closed with when the plane cannot read or trust the answer.

Amended by [ADR-0055](0055-a-call-is-handed-out-only-while-its-policy-stands.md): the policy a call was decided under is
judged at hand-out beside its approval's and its run's expiry, before and after
ACTION_STARTED.

## Context

A resume consumes its approval, checks the store's answer field by field, its
expiry included, and only then writes the journal flip, `APPROVAL_DECIDED`
and `ACTION_STARTED` before the call is handed to the adapter. The last step
takes the pause state and the clock again, and never looked at the approval's
expiry. A slow journal or a slow sink could therefore let an approval expire
between its consumption and the hand-out, and the call ran on an approval that
had expired by the plane's own clock at the moment it was sent. Invariant 6
says an approval expires; an expiry that stops counting once the record is
consumed is a weaker promise than the one written there.

The reconciliation of a lost hold closed three different situations with the
same `DENY` and `APPROVAL_EXPIRED`: nobody answered, the store could not be
read, and the store answered with a record that fails the checks a live resume
makes. Only the first is an expiry. The other two mean the plane does not know
what the approver said, and a trail that states an expiry there tells an
operator something nobody established.

## Decision

**The expiry is judged again, twice, before the call is handed out.** The
expiry compared is the one on the approval the store answered, which is never
later than the one the plane minted.

- Right before a resumed call's `ACTION_STARTED` is written, with the pause
  state taken for the last time and the clock read with it: at or past the
  expiry the held trail is closed with `ACTION_BLOCKED` carrying the plane's
  own `DENY` and `APPROVAL_EXPIRED`, after `APPROVAL_DECIDED`. A pause read at
  that moment is named instead, because the plane's own causes are checked
  first (ADR-0019).
- Right after `ACTION_STARTED` is appended, with the clock read once more: at
  or past the expiry, or on a zero reading, the execution is closed the way an
  adapter aborts what it did not send, `ACTION_FAILED` with a `BLOCKED` result
  whose `tool_protocol_status` is `APPROVAL_EXPIRED`, no executed digest and
  that reading as its end, and the call gets the plane's `DENY` with
  `APPROVAL_EXPIRED`, decided at that reading. The chain has no place for a
  decision after `ACTION_STARTED`, so the decision id of this one answer is on
  no record; the trail names the execution it closes. If the sink refuses that
  record, nothing is handed out either: the call is blocked with
  `EVIDENCE_UNAVAILABLE`, and the trail left open at `ACTION_STARTED` keeps its
  request id reserved and its journal entry, and is counted in
  `held_trails_left_open`, as any held trail a refused record leaves open.

In both cases nothing is sent and the approval stays spent; it is never handed
back to be used again. A trail that closes takes its journal entry with it.
Both closings are transitions the chain already allows.

What this covers is the plane's own time up to the hand-out, journal, sink and
lock included. The adapter's time after the hand-out, until its request
reaches the upstream, is not measured by the plane and not covered.

**A lost hold's record is the one the plane minted, by request id and
approval id together**, as `Consume` names it: a sibling filed under the same
request id with another approval id is not read, so it cannot relabel the
answer.

**A lost hold whose answer cannot be read or trusted is `INDETERMINATE`.**
`APPROVAL_STATE_UNKNOWN`, registry number 44, verdict `INDETERMINATE`, is the
code of the close when the store cannot be read, when it answers with a record
the field checks refuse or with an answer no approver gives, and when it has no
record for the hold while the approval the plane minted has not expired. The
window is still closed with `APPROVAL_EXPIRED` carrying the plane's own
approval, because nothing but an answer or an expiry may follow a request for
approval in the chain, and the plane records nothing a store said that it did
not check. `APPROVAL_EXPIRED` stays for nobody answered, for a record whose own
expiry has passed, and for no record once the plane's minted expiry has passed
by its clock, since a store drops what expired. A plane that crashed between
journalling a hold and filing its record, and restarts before the expiry,
closes that hold as unknown, because a record never filed cannot be told from
one deleted. A rejection keeps
`APPROVAL_REJECTED` and a grant `APPROVAL_NOT_RESUMED`. The call never runs
under any of them.

## Security / compatibility impact

The plane no longer hands out a call whose approval has expired by its clock
at the last reading it takes, the one after `ACTION_STARTED` is appended,
whatever the journal or the sink cost before it. A call handed out a moment
before the expiry can still reach the upstream after it: the adapter's time
is outside the plane's check. The price is that an approval consumed just
before its expiry can be spent without running, exactly as a pause read in
the same place already spends one.

`APPROVAL_STATE_UNKNOWN` is a new code, and a consumer reading lost-hold
closings sees `INDETERMINATE` where it used to see `DENY`. No wire message
changes. No rule may name the code: a rule's reasons are an allowlist per
effect that does not hold it.

## Alternatives considered

- **Judge the expiry only at consumption, as before.** Rejected: the time
  between consumption and hand-out is unbounded by anything the approver
  controls, so the expiry the approver saw would not be the one enforced.
- **Put the expiry back into the store's hands, unconsumed.** Rejected: a
  consumed approval that returns to be used again is the replay invariant 6
  forbids, and two retries could both run it.
- **List the expiry beside a pause as one more of the plane's causes.**
  Rejected for now: the causes are a function of the plane's state that every
  call shares, and the expiry is a property of one resumed call's approval.
- **Keep `APPROVAL_EXPIRED` for an unreadable answer.** Rejected: it states
  an expiry nobody observed, and an operator acts on the difference between
  "nobody answered" and "the plane could not tell".
- **Close an unreadable lost hold as `EVIDENCE_UNAVAILABLE`.** Rejected: that
  code says a record could not be written or kept, and the operator's question
  here is what the approver said.

## Consequences

The resume path gains one comparison at hand-out. The reconciliation returns a
verdict beside its code. The reason-code reference gains a row, and the pages
on approvals and failure modes say where expiry is judged and what an unknown
close means.

## Validation

- `internal/gateway/lapse_test.go`: with a controlled clock, a slow journal, a
  slow `APPROVAL_DECIDED` append and a slow `ACTION_STARTED` append each move
  the clock to the expiry, and nothing is sent; one tick earlier the same
  resume runs. The store's shorter expiry is the one judged. A zero reading and
  a refused abort record send nothing. A pause in the same window, and sixteen
  identical retries at once, send nothing past the expiry and at most one call
  before it.
- `internal/gateway/reconcile_test.go`: a store that fails, one that answers
  garbage, one that answers an expired record and one that answers a rejection
  close a lost hold four different ways; a missing record a tick before and at
  the plane's expiry closes as unknown and as expired; a sibling record under
  another approval id changes nothing; every close resolves the record once.
- `internal/policy/reasons/registry_test.go` pins number 44, its verdict and
  its summary.
