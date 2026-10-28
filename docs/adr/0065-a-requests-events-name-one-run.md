# ADR-0065: A request's events name one run

Status: accepted
Date: 2026-10-28

Builds on [ADR-0034](0034-a-run-the-operator-opens-has-an-identity-of-its-own.md),
which gave a run an identity of its own, and on
[ADR-0045](0045-one-run-is-supervised-against-its-procedure.md), which
supervises one run from the events that name it.

## Context

The chain check holds every event of a request's trail to the `request_id`,
`project_id` and `tenant_id` of its first event. It did not hold the
`run_id`. A trail whose last event named another run passed `trail`, and the
evidence consumer reported the request completed under its first run.
`supervise` caught the case only through a copy of the rule of its own, and
missed it when the read left the other run's events out before the check: the
events it kept chained as a whole trail.

No plane ever wrote such a trail. The event builder is the only writer of
`run_id`; it takes the identifiers once per request, and every resume of a
held request reuses them. A trail with two runs comes from a third-party
producer, a damaged file or an edited one.

## Decision

Every event of a request names the run its first event names, or no run, for
an action taken outside a run. The chain check refuses the first event that
does not, naming its index and both runs, and holds `run_id` to
`MaxStringBytes` as it holds the other identifiers. `run_id` is not a link of
the chain: `prev_event_id` stays the only link.

The readers apply the one rule. `trail` reports such a trail failed.
`supervise` reads the chain check's verdict, and a request with an event its
read leaves out for its run is in doubt as well, so neither path can call a
partial trail whole. The evidence consumer, a module that imports nothing of
this one ([ADR-0037](0037-an-evidence-consumer-in-a-module-of-its-own.md)),
holds the rule in its own code: a request that breaks it is unknown, in the
walk and when it follows a trail, an annotation after the request's end
included. Its follow state keeps each ended request's run, so the state is
schema `1.2`. The walk now reads an export whose query names a filter other
than requests as not whole, since a run filter can leave out the very event
that changes the run; a request filter selects whole requests.

## Security / compatibility impact

No wire byte changes and `buf breaking` is unaffected: the change is to what
the checker accepts and to the comment on `Event`. A third-party stream that
changes run within one request was accepted by the 1.0 checker and is now
refused as a broken chain. That is the stricter reading of what a plane
already wrote, and a reader that cannot say which run did what has no other
answer. Supervision fails closed: a request it cannot place in one run leaves
the rules that read it not checked. The plane mints every request id, both
adapters through `NewID`, so a request id names one trail; a stream that
reuses one in another run puts the earlier request in doubt, which errs toward
doubt and never toward a pass. A follow state of `1.1` still loads; an
annotation after the end of a request it closed is unknown, since that state
does not hold the request's run.

## Alternatives considered

- **Leave it to supervision's doubt alone.** `trail` and the evidence
  consumer would still call such a trail whole, and supervision would hold a
  second copy of the rule, which missed the case where its read filtered the
  events first.
- **Make `run_id` part of the `prev_event_id` chain.** A change to the frozen
  1.0 wire contract and to every producer, for a property a comparison with
  the first event already gives.

## Consequences

A producer has to stamp one run on a whole request, as this plane does. A
request that a filtered export splits can no longer read as complete in the
evidence consumer, which costs a consumer that filters by run, kind, tenant
or project an exit 1.

## Validation

- `internal/trailchain`: `TestValidateHoldsEveryEventToTheFirstEventsRun`,
  `TestValidateBoundsARunIDAtMaxStringBytes`.
- `internal/evidence`: the run rows of
  `TestValidateChainRefusesAnEventFromAnotherScope`.
- `guardana-gateway`: `TestTrailFailsATrailWhoseRunChanges`.
- `internal/supervise`: `TestARequestThatNamesTwoRunsConfirmsNothing`,
  `TestARequestWithAnEventOutsideTheRunsReadIsInDoubt`,
  `TestARequestWhollyInAnotherRunPutsNothingInDoubt`.
- `examples/evidence-report`: `TestARequestWhoseRunChangesIsUnknown`,
  `TestARequestOutsideAnyRunIsCompleted`,
  `TestTheFollowerHoldsAnAnnotationAfterTheEndToTheRun`,
  `TestA11StateHoldsNoClosedRun`, `TestAFilteredExportIsNotWhole`.
