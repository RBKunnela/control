---
title: Egress access log
summary: The descriptor of an egress proxy's access log, how its lines map to connection observations, what is never read, each refusal, and the trust it claims.
type: reference
covers: [internal/ingest/egresslog/**, internal/netname/**, internal/observe/kinds.go, internal/observe/connection.go, internal/ingest/ingest.go]
---

# Egress access log

A source of kind `egress-access-log` is an egress proxy's access log, written
as JSON lines. Each line the importer accepts becomes one connection
observation: the host the proxy recorded, not the one the agent reported. It is
`experimental`; [status.md](../status.md) is the inventory and
[ADR-0069](../adr/0069-an-egress-proxys-access-log-is-an-independent-sensor-on-a-kind-neutral-descriptor.md)
the record. [Watch an egress proxy](../guides/watch-an-egress-proxy.md) sets
one up.

## The descriptor

A descriptor of this kind is schema `0.2` and carries the members every kind
shares ([observations](observations.md#the-source-descriptor)) and one of its
own, `egress_access_log`. It may not carry `convention`, `otlp_version`,
`select` or `run_attribute`.

```json
{"schema_version": "0.2", "source_id": "egress-envoy", "kind": "egress-access-log",
 "trust": "TRUST_INDEPENDENT", "sampling": "SAMPLING_COMPLETE", "heartbeat_seconds": 300,
 "tenant_id": "tenant-a", "project_id": "project-a",
 "egress_access_log": {"format": "json-lines",
   "fields": {"time": "start_time", "time_format": "TIME_FORMAT_RFC3339",
              "destination": "authority", "destination_form": "DESTINATION_FORM_AUTHORITY",
              "port": "upstream_remote_port"}}}
```

| Member | Required | Value |
| --- | --- | --- |
| `format` | yes | `json-lines`, the one format |
| `fields.time`, `fields.destination` | yes | the member of a line that holds the time and the host |
| `fields.time_format` | yes | `TIME_FORMAT_RFC3339`, `TIME_FORMAT_UNIX_SECONDS` or `TIME_FORMAT_UNIX_MILLISECONDS` |
| `fields.destination_form` | yes | `DESTINATION_FORM_HOST`, a host alone, or `DESTINATION_FORM_AUTHORITY`, `host`, `host:port`, `[v6]` or `[v6]:port` as a forward proxy's request names its target |
| `fields.port`, `method`, `status`, `bytes_sent`, `bytes_received`, `caller` | no | the member that holds each value |
| `caller_basis` | when `caller` is mapped, and only then | `CALLER_BASIS_NONE`, `CALLER_BASIS_ADDRESS` (the address the connection came from) or `CALLER_BASIS_AUTHENTICATED` (the proxy authenticated the caller) |

A mapped name is a top-level member of the line, never a path into it. The
names are distinct, at most 128 bytes (`MaxMemberNameBytes` in
`internal/ingest/egresslog/descriptor.go`), and hold the text rules every
descriptor string keeps. The caller's basis comes from the descriptor, never
from the data.

Invariant 9 rests on the mapping: the importer copies the members it names
and no other. A mapping that names a path or a header member as `caller`
copies that member, within the caller's rules below.

## What a line becomes

| Observation field | From the line |
| --- | --- |
| `subject` | kind `SUBJECT_KIND_CONNECTION`, name the destination host |
| `event_time` | the mapped time; a time after the import's clock is kept as read |
| `connection.port` | 1 to 65535: the port member's, or the authority's when that member is unset or not mapped; neither is 0, read as unknown |
| `connection.method` | kept only when it is one of `CONNECT`, `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `TRACE`, exactly as spelled |
| `connection.http_status` | 100 to 599, or 0, which the proxy writes when it has none |
| `connection.bytes_sent`, `bytes_received` | an unsigned 64-bit count |
| `connection.caller`, `caller_basis` | under `CALLER_BASIS_ADDRESS`, an IP address with or without a port, in its one spelling; under another basis, the caller as the proxy wrote it, at most 256 bytes (`observe.MaxTextBytes`); and the descriptor's basis. With no caller the basis is `CALLER_BASIS_NONE` |
| `stage` | `STAGE_INDIRECT` |
| `correlation` | basis `BASIS_NONE`, with no trace, span or run: a connection names no run |

A port, status or count may be written as a JSON number or a decimal string,
never with a sign, a fraction or an exponent. `null`, `""` and `-` say nothing: an unset
optional value is left empty and counts as nothing. An RFC 3339 time needs its
zone. Unix seconds take at most nine fractional digits; Unix milliseconds take
none.

A host has one spelling, `Host` in `internal/netname`, and the coverage
inventory uses the same one. A name is lowercased and held to labels of 1
to 63 letters, digits and hyphens, not starting or ending with a hyphen, at
most 253 bytes in all (`observe.MaxHostBytes`), with no trailing dot. An
A-label (`xn--`) is taken as written; a name in Unicode is refused, since this
build carries no IDNA tables. An IPv4 address is a dotted quad; an IPv6
address is written as `net/netip` writes it, without brackets or a zone, and
one that maps an IPv4 address is that IPv4 address. A caller address is
spelled the same way, `[v6]:port` with a port. Under the authority form the
port is optional, since a forward proxy's plain HTTP request often names the
host alone; an IPv6 address still needs its brackets, and a colon needs a port
after it.

## What is never read

A line is checked to be valid JSON, and only the mapped members are decoded;
every other value is stepped over unread. A path, query, header, user agent or
body the proxy also logged is never copied unless the descriptor maps its
member to one of the fields above (invariant 9). A destination that is a URL,
or holds a path, a query, a fragment, user information or whitespace, is
refused whole and never parsed down to its host: mapping a URL member is the
operator's mistake, and guessing the host from it would hide that. Under the
host form a port is refused too; under the authority form a port is split
off.

## Refusals and drops

A refused line becomes no observation. It is counted in `refused`, and under
its reason in the report's `refused_by`. `observe import` prints `lines_read`
and the total refused, not each reason, and any refusal makes it exit 1.

| `refused_by` key | The line |
| --- | --- |
| `line_too_long` | is over 64 KiB (`MaxLineBytes` in `internal/ingest/egresslog/lines.go`); it is never held in memory, and the next line is read whole |
| `not_an_object` | is not one JSON object, or not UTF-8 |
| `duplicate_member` | names a member twice, mapped or not, however the name is escaped |
| `time` | has no time, or one its format cannot read |
| `destination` | has no destination, or one that is not a host alone or an authority, as the form says |
| `port` | has a port that is not a number from 1 to 65535, or one its authority contradicts |

A malformed optional value, such as a method off the list, a status outside
its range or a caller with a control character, is dropped and counted in
`strings_dropped`, and the line is kept. Under `CALLER_BASIS_ADDRESS` a caller
that is not an IP address, such as a name or a path, is dropped and counted
in `callers_dropped` instead. The log's codec holds the method, status and
caller to these rules when it reads a connection back, and under an address
basis the caller to the characters an address is written with, not to an
address: `cafe` or `[[::` reads back from a log another writer wrote. Only the
importer reads a caller as an address, since the codec's tree may not import
`net/netip`. Bytes after the last newline are not
a line: the proxy may still be writing them, so they are neither read nor
refused, and the next import reads them.

A refused line names no run, so the report sets `every_run_doubted`. That
weighs on nothing: `supervise` refuses a source of this kind
([supervision](supervision.md)). `coverage` prints a row for every source
whose reports count a refusal, and one for every source given that is not
live, and exits 1 on either. It refuses a log holding this kind's records
that no descriptor of this kind given with that log names
([coverage](coverage.md)).

Importing a log again refuses its bad line again and writes another report
counting it, so a log that ever held one exits 1 on every import, and keeps
`coverage` at 1 until the observation log is rotated by hand
([observations](observations.md)). An input is read whole, up to 256 MiB,
before a line is mapped, and the import holds every observation it made in
memory until it writes them.

## Identity and the log

An observation's id is `obs-` and the first 32 hex digits of SHA-256 under
the domain `observation-id:connection:1`, over the tenant, project, source,
event time, host, port, method, status, both byte counts and the caller, each
prefixed by its length (`ConnectionID` in `internal/observe/connection.go`).
Importing a file again, grown or rotated, writes only what is new; two
connections alike in all of these are one duplicate. Trust and the caller's
basis are not in the id, so importing a connection again after the
descriptor changed its trust or its caller basis is a conflict. Every record this kind writes is schema `0.3`
and names the kind in `source.kind` ([versions](versions.md)). A log holds
one kind per source: `observe import` refuses a write whose kind is not that
of the records the log already holds for its source, tenant and project.

## Trust

This kind may declare `TRUST_INDEPENDENT` with an unsigned descriptor. It is
the operator's statement that the agent can write neither the log nor the
descriptor; nothing here checks which account writes either. Under it,
`observe import` refuses an input whose mode bits let the group or others
write it, as it refuses such a descriptor under any trust. The check reads
the mode bits only, not an access control list, which can grant write to
another account behind a mode of `0644`, and not which account owns the
file. `coverage` prints the trust as
`independent (unsigned descriptor)`.

A forged line can make a destination look observed, and deleting its lines can
make it look not observed, never covered. A line is the proxy's account of a
request, not proof that a connection succeeded. `supervise` refuses this kind;
a finding may rest on this trust only once the descriptor is signed.
