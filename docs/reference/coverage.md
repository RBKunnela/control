---
title: Coverage
summary: What guardana-control coverage reads, its inventory, the state of each declared path and each undeclared egress host, the join, and its exit status.
type: reference
covers: [internal/coverage/**, cmd/guardana-control/coverage.go, internal/observelog/readfile.go, internal/ingest/ingest.go, internal/netname/**]
---

# Coverage

`guardana-control coverage` says, for each path an operator declares, whether
a plane enforces it, decides it without enforcing it, a source observed it,
nobody can tell, or nothing covers it. It reads files and contacts no plane;
no plane reads what it prints
([ADR-0041](../adr/0041-coverage-per-declared-path.md),
[ADR-0044](../adr/0044-coverage-judges-each-plane-and-joins-only-a-whole-export.md)).
It is `experimental`.

```
guardana-control coverage --inventory <file> [--plane <config> [--evidence <export>]]...
    [--source <descriptor> --log <dir>]...
```

## Inputs

| Flag | What it reads |
| --- | --- |
| `--inventory` | the operator's inventory below, once; a file another account or a group can write is refused |
| `--plane` | a plane's configuration, refused unless this account or root owns it and its directory and others cannot write them, a sticky directory or root's
on a read-only mount excepted; read without this shell's environment |
| `--source`, `--log` | a source descriptor and its observation log's directory, paired in order ([observations](observations.md)) |
| `--evidence` | the evidence export of the `--plane` before it, as `guardana-gateway trail export` writes it ([contracts](../contracts.md#the-evidence-export)); at most one per plane, refused when another account or a group can write it |

A descriptor that is absent turns its paths not covered, never observed. A
log holding an egress source's records is refused unless its egress
descriptor is given with the same directory, as one absent, of another kind
or renamed is not; its hosts would go unprinted, and the pairing is the
operator's to fix. A log directory without a log is never heard. Any other
input that cannot be read or does not parse is refused.

## The inventory

A strict JSON document: an unknown member, a repeated member or an empty list
of paths is refused.

```json
{"schema_version": "0.1", "paths": [
  {"id": "orders.read-file", "kind": "mcp_tool", "upstream": "orders", "tool": "read_file",
   "sources": [{"source_id": "agent-runtime", "name": "read_file", "server_address": "files.example"}]}
]}
```

| Member | Meaning |
| --- | --- |
| `id` | unique, 1 to 64 bytes of `a-z`, `0-9`, `.`, `_`, `-` |
| `kind` | `mcp_tool` with `upstream` and `tool`, one path per pair; `enforce_tool` with `tool`, a tool an enforcement API plane's `tools` table names, one path per tool; `egress` with `host`; `http_api` or `process` with `name` |
| `sources` | each a `source_id` that would see the path, the `name` its observation carries and, optionally, its `server_address`; on an `egress` path, the host its connections name, and no `server_address` |

An egress path's `host` and its sources' names are hosts in the one spelling
the importer writes ([egress access log](egress-access-log.md#what-a-line-becomes)).
Another spelling is refused with the one to write: `Example.COM` as
`example.com`, `2001:0db8::1` as `2001:db8::1`, `::ffff:203.0.113.7` as
`203.0.113.7`. Anything that is not a host, such as `https://x/` or a
non-ASCII letter, is refused.

An observation matches a path when it comes from that source in the tenant
and project its descriptor names, is of a tool, and carries that name and,
when given, that server address. On an `egress` path it is a connection to
that name, whatever the port: a tool never matches
an egress path, nor a connection any other
([egress access log](egress-access-log.md)).

## States

Each path gets the first state that holds:

| State | When |
| --- | --- |
| enforced | every plane that counts for the tool holds the path to the effect, is in `ENFORCE`, `APPROVE` or `LOCKDOWN`, and none lets the read fail open |
| decided, not enforced | a plane counts for it in `OBSERVE`, or under `policy.fail_open_read` outside `LOCKDOWN`, where a read runs undecided while the policy is unavailable, or serves the enforcement API, in any mode |
| observed | a source live within its heartbeat holds a matching observation; the weakest trust of the descriptor and the observations is printed, `independent` as `independent (unsigned descriptor)`, and `sampled` when no such source's descriptor says `SAMPLING_COMPLETE`, so a call may have gone unseen |
| unknown | a source the path names is past its heartbeat or was never heard |
| not covered | nothing above |

Only an `mcp_tool` can be enforced, and only it and an `enforce_tool` decided.
No plane decides egress: an `egress` path is at most observed, whatever a
plane lists, and its line ends `no plane decides egress`.
A plane serving the enforcement API (`listener.kind: enforce_api`) counts for
an `enforce_tool` its `tools` table names, and decides it in every mode it
runs in, never enforces it: it hands the decision to a cooperating client,
which may ignore it, and the line says so
([ADR-0051](../adr/0051-a-tool-outside-mcp-is-admitted-completed-and-aborted-through-an-enforcement-api.md)).
An MCP plane counts for an `mcp_tool` when it lists the tool's upstream: with an override that classifies the tool, or
without one, when a call to it is unclassified, blocked in a mode that
enforces and let run in `OBSERVE`. A plane in `SHADOW` or `WARN` refuses to
start and counts for nothing. A classification is the configuration's
override; the live definition behind its fingerprint is not checked. A
source is last heard at the newest event time an import report of its
descriptor's tenant and project covers, never later than that report's
receive time; one heard after the command's clock is unknown.

## The join

Beside an enforced or decided path, each matching observation is checked
against the exports of the planes that count for it. It is joined when a
whole export holds, for it or an observation below it in the same trace,
tenant and project, the span id of a tool call's proposal for that tool on that upstream, or for an
`enforce_tool` of that tool through the enforcement API, in the same tenant
and project, recorded in a mode
at least as strong as the path's state. A call every such plane's export could
have shown and none does is printed as a call around the plane. The check is
printed as not checked, with the reason, when:

- the observation has no trace or span id;
- no proposal joins it, and a plane that counts has no export, or its export
  is not whole: cut short, not at its end, with a gap, or filtered by a cursor
  or a query;
- no proposal joins it, and it has no event time, or its time is outside the
  span an export's events cover;
- no proposal joins it, but one at or below its span names the same call
  (tenant, project, tool and upstream, of kind tool) in an envelope the
  contract refuses for more than a missing effect class: the plane saw that
  call, and its record cannot be joined;
- more than 65,536 spans are at or below its own in its trace, each counted
  once however many parents it claims, which cuts its walk;
- counting those spans, where spans claim two parents, passes 4,194,304 steps
  for its source, which cuts its walk too;
- the path names no source.

## Output and exit status

One line per declared path, its state and what it rests on, then indented
lines for each plane, each source and the joins; then a row per undeclared
egress host, a row per egress source whose import refused a line, a row per
egress source that is not live, and last the line `undeclared paths: unknown`.

An undeclared egress host is one an egress source given with `--source`
connected to, in its own records, live or not, when no egress path declares
it: no path has it as `host`, and no path naming that source gives it as
`name`. Its row names each such source with its trust, the weaker of the
descriptor's and its connections', `sampled` as above, when it was last
heard, its connections and their distinct ports, at most 16 and a count of the
rest, a port the log did not give as `unknown`, and ends `no plane decides egress`:

```
undeclared egress registry.example.org: observed by egress-envoy: independent (unsigned descriptor), past its heartbeat: last heard 2026-10-04T10:00:01Z, heartbeat 300 s; 1 connection, port 80; no plane decides egress
```

Rows are sorted by the host's bytes, at most 256 (`MaxUndeclared` in
`internal/coverage/undeclared.go`); one line counts the hosts past that. An
agent chooses the hosts it reaches, so it can push one past the cut by
reaching 256 that sort before it; the cut still makes the exit 1. The line
names no digest of the hosts cut, since a digest names none of them; the log
holds every one, and `observe export` lists them.

A line the importer refused is a connection whose host nobody read. Each
egress source whose own import reports count one gets a row with the total
and the count by reason, from `refused` and `refused_by`, at most 16 reasons
and a count of the rest:

```
refused egress by egress-envoy: 2 lines refused, so their connections are unknown: destination 1, port 1; no plane decides egress
```

Each report counts what its own import refused, so a line two imports of
the same file refused counts twice; the row stays until the observation log
is rotated by hand.

An egress source not live gets an unseen row, named by a path or not; a
path naming it stays unknown:

```
unseen egress by egress-envoy: past its heartbeat: last heard 2026-10-04T10:00:01Z, heartbeat 300 s; connections since its last import are unseen; no plane decides egress
```

The check that an independent input is not writable by others reads mode
bits only, not an access control list or the file's owner
([egress access log](egress-access-log.md#trust)).

| Exit | When |
| --- | --- |
| 0 | every declared path is at least observed, and no call around the plane or cut walk was found; a join not checked for another reason, such as no export, is the operator's to close |
| 1 | a path is unknown or not covered; a call around the plane or a cut walk was found, since an agent chooses its spans and can cut a walk on purpose; an egress source reached a host no path declares, its row printed or cut; an egress import refused a line; or an egress source is not live |
| 2 | an input was refused; nothing is printed on standard output |
