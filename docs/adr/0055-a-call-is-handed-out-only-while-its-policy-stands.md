# ADR-0055: A call is handed out only while the policy it was decided under stands

Status: accepted
Date: 2026-10-18

Amends [ADR-0012](0012-policy-kernel-semantics.md) on when freshness is
judged, [ADR-0013](0013-mcp-interception-approvals-and-modes.md) and
[ADR-0027](0027-expiry-at-hand-out-and-an-unreadable-lost-hold.md) on what is
judged again before a call is handed out, and
[ADR-0038](0038-a-signed-freshness-statement-and-a-serial-floor.md) on what a
newer bundle does to a call already decided.

## Context

The kernel judges a bundle's freshness when it decides. The gateway then does
more before it hands the call out: it may ask the decision point, look up and
consume an approval, flip a journal entry, append POLICY_DECIDED and
APPROVAL_DECIDED, and raise a run's state. Each step can wait on a store or a
disk. Until now only a pause, a stop, an approval's expiry and an opened run's
expiry were judged again at hand-out, so a call decided under a fresh bundle
ran even when its bundle had passed its staleness budget, or another bundle had
replaced it, by the time it was sent. A retry of a held call decided after a
replacement was already held anew, because the approval binding carries the
bundle digest; the gap was the window inside one admission.

## Decision

A call is handed out only while the policy its decision stood on still stands
at the hand-out reading. The kernel judges this, so the gateway holds no rule
of its own:

- Every outcome carries a `Basis`: the bundle's digest, none where there was no
  bundle, whether that bundle was fresh then, and whether the fail-closed
  table let a read run under fail-open reads. Only the kernel makes one; the zero value stands on nothing.
- `Kernel.Recheck(basis, installed, now, floor)` answers `Current`, `Stale`,
  `Replaced` or `Unknown`, and only `Current` lets the call go:
  - another digest than the decision's, or a bundle where there was none, is
    `Replaced`;
  - the same digest is `Current` while it is fresh under the kernel's own rule
    and budget, judged on the installed snapshot, so a renewal of the bundle
    keeps the call current;
  - a read the table let run stays `Current` while the bundle is the same one,
    or there is still none, since it is the same row of the table and its
    record already says so; a call decided fresh that is stale at hand-out is
    `Stale` even where the table would open a read, since its record does not
    say the setting let it run;
  - a reading the clock step refuses, one earlier than the time the plane
    verified for the installed bundle, or one earlier than an instant the call
    already relied on is `Unknown`.
- The freshness rule itself lives once, as `Snapshot.FreshAt` in
  `internal/policy`, which the kernel and the policy watcher behind `/healthz`
  and the metrics read; the development signer's renewal schedule reads its
  budget, `policy.Budget`.
- The gateway asks at three points, each after its pause, stop, approval and
  run checks there and before it asks whether the agent left: before a resume
  consumes its approval, so a moment of staleness
  spends nothing and the hold stands; before ACTION_STARTED; and after it, for
  every call, not only a held one or one in an opened run. The installed
  snapshot is taken before the clock, as the pause and stop states are.
- A call that does not stand is blocked `INDETERMINATE` with `POLICY_STALE`
  and freshness `STALE` on the plane's own decision: on its own trail before a
  consume, as ACTION_BLOCKED before ACTION_STARTED, and as ACTION_FAILED with a
  BLOCKED result after it, as an expired approval is (ADR-0027).
- `OBSERVE` enforces no policy (ADR-0013 applies a mode to the action), so
  there the call runs, and `/healthz` and `/metrics` count it
  (`pipeline_stale_handed_out_total`) when its policy let it run when decided,
  which is what `ENFORCE` would have withheld at hand-out: the kernel's action
  was to execute, a read the fail-closed table opened included. A call allowed
  with an obligation counts even when `ENFORCE` could not have applied the
  obligation and would have denied it instead. A pause, a stop and a run's expiry
  still block it in every mode.

An approval granted under a bundle since replaced is never consumed for an
execution under another bundle: a retry decided under the new bundle has
another binding and is held anew, and one that reaches the hand-out under the
old bundle is withheld.

## Security / compatibility impact

The check can only withhold a call the decision let run; it never lets one run
that the decision did not. A basis nobody made, a kernel nobody built and a
missing snapshot all fail closed. No wire field, reason code number or verdict
changes; `POLICY_STALE`'s summary now names a replaced bundle and a reading
behind one the call relied on. A replaced bundle now also withholds calls
already decided but not yet handed out, which ADR-0038 left running.

Only the policy is judged again: a delegation hop that expires between the
decision and the hand-out is not, as before; a resumed hold's retry is decided
afresh, which judges the chain at that time.

Holds under a replaced bundle can no longer be resumed, but they count toward
the bounds on held requests until they expire and the sweep closes them; a
busy run can meet that bound sooner after a replacement. Hand-out blocks and
decision-time ones share the `POLICY_STALE` count in `pipeline_blocks_total`.

## Alternatives considered

- The gateway compares the digest itself and asks the kernel only for
  freshness: it would hold the "replaced" rule outside the core, refuse every
  read the table opened, and add a fourth copy of the freshness rule.
- Deciding the call again at hand-out: it honours the table exactly, but the
  trail has room for one POLICY_DECIDED, and it could ask the decision point a
  second time.
- Comparing snapshot objects or a holder generation instead of digests: the
  holder publishes a new snapshot at every confirmation, so every renewal
  would withhold the calls in flight.
- Closing holds under a replaced bundle at once in the sweep: it frees their
  capacity and tells the approver sooner, but adds a policy read and a new
  close path to the sweep; deferred.
- Rechecking material calls only: a read would then run where a decision at
  that instant would block it.

## Consequences

An operator who replaces a bundle, or whose renewal stops, sees calls
decided just before withheld with `POLICY_STALE` instead of running; the
agent retries and is decided under the bundle installed then. A momentary
staleness before a consume costs nothing; after a consume it costs the
approval, as a late pause already does (ADR-0019, ADR-0027). Each admission
takes the installed snapshot and reads the clock once more, after
ACTION_STARTED.

## Validation

- `internal/core/recheck_test.go` holds `Recheck` to an independent
  computation: over the setting, a read and a write, a decision fresh and
  stale, hand-out readings at, inside and past the budget, and a renewal or
  none, with the same envelope and bundle, a call is `Current` exactly when
  deciding it again at that reading lets it run and either the table opened it
  the first time or the second decision is fresh. It also covers each standing, a zero basis and a kernel nobody
  built.
- `internal/gateway/handout_test.go`: a call stale at hand-out, stale while
  ACTION_STARTED is appended, replaced before or while ACTION_STARTED is
  appended (and a renewal that is not), a reading behind the decision or the verified time, each row of the
  fail-closed table, `OBSERVE`, a hold stale before the consume (nothing
  spent, one run after re-confirmation) and one replaced after it (held anew,
  not refused as used). Removing any of the three checks, the `OBSERVE`
  exemption, the opened-read row or the STALE freshness fails a named test.
