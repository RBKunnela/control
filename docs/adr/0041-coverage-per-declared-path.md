# ADR-0041: Coverage per declared path

Status: accepted
Date: 2026-10-05

Builds on [ADR-0039](0039-many-channels-into-one-core.md), which says coverage
is stated per declared path and never as a percentage, and on
[ADR-0040](0040-observations-a-record-a-log-and-one-importer.md), whose source
descriptors and import reports it reads. It amends ADR-0039,
which says the plane reports coverage: a command reports it, and no plane
reads what it prints.

Amended by [ADR-0044](0044-coverage-judges-each-plane-and-joins-only-a-whole-export.md):
the command also reads evidence exports, and joins an observation only to a
whole, unfiltered one; a path is enforced only when every plane that
classifies it enforces it; a read under `policy.fail_open_read` outside
`LOCKDOWN` is decided, not enforced; a call around the plane exits 1.

Amended by [ADR-0051](0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md):
a path a `Cooperative` plane serves, such as a tool behind the enforcement
API, is decided, not enforced, in every mode; only a plane that holds the path
to the effect can make it enforced.

Amended by [ADR-0069](0069-an-egress-proxys-access-log-is-an-independent-sensor-on-a-kind-neutral-descriptor.md),
which decides that a connection observes an egress path, that no plane decides
one, and that an egress host a source observed and no path declares is a row
of its own that makes the exit 1.

## Context

An operator needs to know, for each thing an agent can do, whether a plane
decides it, decides it without enforcing, only sees it afterwards, or nothing
covers it at all; and that the paths nobody declared are not covered by
default. Backlog B18 asks for a command that states this from what already
exists: the planes' configurations, the source descriptors, the observation
logs, and an inventory the operator writes.

## Decision

**An inventory of declared paths.** A strict JSON document the operator writes:
`schema_version` `0.1`, and a list of paths, each a `kind` (`mcp_tool`,
`http_api`, `process`, `egress`) and the names that identify it (an MCP tool
by upstream and tool name, and by the sources that would see it with the
tool name and `server_address` an observation of it carries; an egress
destination by host). It is a statement
of what the operator expects agents to do, read as an operator's document is:
an unknown member is refused.

**Inputs, each read as it is, none trusted beyond its owner.**
`guardana-control coverage --inventory <file> [--plane <config>]...
[--source <descriptor> --log <dir>]... ` reads each plane's configuration
(mode, upstreams and the classified tools its overrides pin), each source's
descriptor and the import reports in its log. It contacts no plane.

**One state per declared path, in this order of strength:**

| State | When |
| --- | --- |
| enforced | a plane in `ENFORCE`, `APPROVE` or `LOCKDOWN` classifies the path, and for a read `policy.fail_open_read` is off |
| decided, not enforced | only a plane in `OBSERVE` classifies it |
| observed, with the trust | a source live within its heartbeat has observations of it; the weakest trust among those sources is printed (`self_reported`, `platform`, `independent`) |
| unknown | a source the inventory names for the path has its descriptor present and is past its heartbeat, or has no import report |
| not covered | nothing above |

A standing last row says that undeclared paths are unknown. A path a plane
enforces and a source also observes shows both, the enforcement first; an
observation of that path with no plane event joined to it is shown beside it
as a call around the plane, since a configuration is not proof every call
passed the plane. A removed descriptor turns its paths not covered, never
observed; a log the command cannot read exits 2. "Inferred" (ADR-0039) has no
source yet and is not printed until one exists.

**Liveness** is ADR-0040's: a source was last heard at its newest event time
not later than an import report's receive time, and a source with no such
report is unknown.

**Output** is one line per path, the state and its basis named, and the exit
status says whether every declared path is at least observed (0), some are not
(1), or the command could not read an input (2).

## Security / compatibility impact

The map reads; it decides nothing and grants nothing, and no plane reads it.
Its claims are only as good as its inputs: a plane's configuration is not proof
the plane runs it, and a self-reported source can omit what it did. The output
says which input each state rests on, so a reader can weigh it.

## Alternatives considered

- A percentage of paths covered: ADR-0039 refused it; it hides which path is
  uncovered.
- Asking running planes over their health endpoints: needs an authenticated
  channel the planes do not have yet (B13).
- Inferring paths from evidence and observations alone, with no inventory:
  cannot show a path nobody took, which is the one an operator most needs.

## Consequences

B18 can be built from code that exists: the configuration loader, the
descriptor reader and the observation log's reader. The inventory is one more
document an operator keeps; the map is as complete as it is.

## Validation

- A plane in `OBSERVE` never shows a path enforced, and one with
  `policy.fail_open_read` on never shows a read enforced.
- An observation of an enforced path with no plane event joined to it shows
  beside the path as a call around the plane.
- A path only a self-reported source saw says `observed, self_reported`.
- A source past its heartbeat turns its paths unknown; a removed descriptor
  turns them not covered.
- The standing row for undeclared paths is always printed.
