# ADR-0044: Coverage judges each plane and joins only a whole export

Status: accepted
Date: 2026-10-05

Amends [ADR-0041](0041-coverage-per-declared-path.md), whose inputs name no
plane evidence although its call around the plane needs it, and
[ADR-0039](0039-many-channels-into-one-core.md) on where coverage's code lives. Builds on
[ADR-0035](0035-a-versioned-evidence-export-and-a-bounded-query.md) and
[ADR-0040](0040-observations-a-record-a-log-and-one-importer.md).

Amended by [ADR-0069](0069-an-egress-proxys-access-log-is-an-independent-sensor-on-a-kind-neutral-descriptor.md),
which decides that no plane decides an egress path, whatever its configuration
lists, and that an undeclared egress host, or a cut of those rows, makes the
exit 1.

## Context

ADR-0041 shows an observation of an enforced path that no plane event joins
as a call around the plane. To say "no plane event joins it", the command has
to read plane events, and ADR-0041's inputs hold none. A join made on too
little would show a bypass that did not happen, or hide one that did: an
evidence export filtered to one run, cut short or with a gap lacks the event a
call left; a call without trace context has empty ids, and empty ids are equal;
and an agent whose MCP client starts a span of its own sends that child's id,
not the id of the span its runtime reports.

Two smaller questions came up while planning the command. ADR-0041 counts a
path enforced when any plane enforces it, so a second plane in `OBSERVE` in
front of the same tool would be hidden. And `policy.fail_open_read` is only in
force outside `LOCKDOWN`, which forces it off.

## Decision

**Evidence is an export, read whole or not joined.** `guardana-control
coverage` takes `--evidence <file>` after a `--plane`, at most one each: the export of ADR-0035 that
`guardana-gateway trail export` writes, decoded by the command's own reader of
the published format, since the approver's binary links neither the evidence
nor the gateway packages. An export belongs to the plane named before it on
the command line, since nothing in an export names its plane. An export is joined only when it is whole: its
trailer is present, it reached the end, it holds no gap, and its query names
no cursor and no filter. Otherwise every join it would have made is printed
as not checked, with the reason.

**The join.** An observation of a path is joined when it, or an observation
below it in the same source and trace (by `parent_span_id`), has a span id
equal to the `span_id` of an `ACTION_PROPOSED` envelope with the same trace
id, tenant, project, tool name and upstream. For a path shown enforced the
proposal must be recorded in a mode that enforces, so an observing plane
cannot cover a call around an enforcing one; for a path a plane only decides,
an `OBSERVE` proposal is the call passing that plane.
Empty ids never join, and a trace id alone never joins. A proposal of a
resource read or a prompt never joins a tool call. An observation that joins
no proposal, and has no event time or one outside the time span the export's
events cover, is not checked. Only an observation that could have joined and did not is printed as
a call around the plane: every plane that counts for the path has a whole
export holding the observation's time, and none holds the call. Otherwise the
check names the plane whose export is missing.

**Each plane on its own.** A plane's configuration is read without the
environment of the shell that runs the command, which is not the plane's, and
the basis says so. A plane in `ENFORCE`, `APPROVE` or `LOCKDOWN` that classifies
a tool enforces it; one in `OBSERVE` decides it without enforcing; `SHADOW` and
`WARN`, which a plane refuses at start, classify nothing. A plane counts for
a path when it lists the path's upstream; without an override for the tool, a
call to it is unclassified, which a mode that enforces blocks and `OBSERVE`
lets run, so such a plane enforces the path or only decides it. A read under
`policy.fail_open_read` outside `LOCKDOWN` is decided, not enforced: it runs
undecided while the policy is unavailable. A path is enforced only when every
plane that classifies it enforces it; otherwise it takes the weakest of them,
and each plane is named. A classification is the configuration's override; the
basis says the live definition is not checked.

**Where the code lives.** `internal/coverage`, outside the guarded trees,
which ADR-0039 placed coverage among. The map decides nothing, nothing it
prints reaches a plane or a stop, and it reads the export's records; the
guarded trees hold what a decision or a stop rests on. `internal/supervise`
stays where ADR-0039 put it, for what can lead to a stop.

**Exit status.** 0 when every declared path is at least observed and no call
around the plane was found, 1 otherwise, 2 when an input is refused, and then
no map is printed. An inventory with no path is refused.

## Security / compatibility impact

The command still decides nothing and no plane reads it. The rules above only
take claims away: a path is enforced in fewer cases, and a bypass is shown only
where the evidence could have shown the call. A local copy of the mode table is
held to the gateway's by a test.

## Alternatives considered

- **Read the trail file.** The command may not link the evidence codec, and a
  trail a collector is writing ends in a torn line; the export already handles
  both, versioned.
- **A third binary that links both sides.** Clean, but a binary to build, sign
  and document for one command.
- **Ship with every join not checked.** Never wrong, but leaves the call around
  the plane, which an operator most needs, unbuilt.
- **Any enforcing plane makes a path enforced.** Hides a route that only
  observes.

## Consequences

An operator who wants the join exports each plane's trail first, unfiltered,
and keeps the export's window wider than the observations it is checked
against. A path the inventory pairs with no source, or a plane whose export is
missing, never shows a bypass, and says why.

## Validation

- A filtered, cut or gapped export, and none at all, give "not checked".
- Empty ids, a trace id alone, another tenant and another tool never join; an
  `OBSERVE`-mode event joins a decided path and never an enforced one; a child
  span's joined proposal joins its parent observation.
- `LOCKDOWN` with `fail_open_read` shows a read enforced; `ENFORCE` with it
  does not.
- An `ENFORCE` plane and an `OBSERVE` plane on one tool do not show it
  enforced.
- A call around the plane makes the exit status 1.
