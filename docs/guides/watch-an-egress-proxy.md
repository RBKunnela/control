---
title: Watch an egress proxy
summary: Have Envoy or Squid write their access log as JSON lines, import it as observations, and see in the coverage map the destinations the proxy logged.
type: how-to
covers: [internal/ingest/egresslog/**, cmd/guardana-control/observe.go, cmd/guardana-control/coverage.go, internal/coverage/undeclared.go]
---

# Watch an egress proxy

An agent's own traces say what it chose to report. When its outbound traffic
goes through a proxy it cannot reconfigure, the proxy's access log says where
that traffic went. This page has the proxy write that log as JSON lines,
imports it, and runs `guardana-control coverage` over it, so each host agents
reached is either a declared path or a row of its own. The importer is
`experimental`; [status.md](../status.md) is the inventory and
[egress access log](../reference/egress-access-log.md) the reference.

## Prerequisites

- `guardana-control` on your `PATH`, built with `go build ./cmd/guardana-control`,
  and a shell at the repository root, where the fixtures below live.
- For a real proxy: an account the agent does not run under that owns the
  proxy's log and the descriptor. Nothing checks this; declaring the source
  `TRUST_INDEPENDENT` states it.

## Steps

### 1. Have the proxy write JSON lines

The member names are yours to choose; the descriptor in step 2 names them.
These are the formats the fixtures in `internal/ingest/egresslog/testdata/`
were written under.

Envoy as a forward proxy, with a file access logger and `json_format`:

```yaml
access_log:
- name: envoy.access_loggers.file
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
    path: /var/log/envoy/egress.jsonl
    log_format:
      json_format:
        start_time: "%START_TIME%"
        authority: "%REQ(:AUTHORITY)%"
        upstream_remote_port: "%UPSTREAM_REMOTE_PORT%"
        method: "%REQ(:METHOD)%"
        response_code: "%RESPONSE_CODE%"
        bytes_sent: "%BYTES_SENT%"
        bytes_received: "%BYTES_RECEIVED%"
        downstream_remote_address: "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
        path: "%REQ(:PATH)%"
        user_agent: "%REQ(USER-AGENT)%"
```

A CONNECT request names its target as an authority, `host:port` or
`[v6]:port`, and the descriptor in step 2 says so. A plain HTTP request
through the proxy often names its host without a port; the line is kept,
with `upstream_remote_port` as its port, or an unknown port when that is
`null` too. Where Envoy is instead the TLS endpoint and routes by SNI,
`%REQUESTED_SERVER_NAME%` is the host alone; the `envoy-sni` fixtures map it
under `DESTINATION_FORM_HOST`.

Squid has no JSON encoding, so the `logformat` writes the braces and quotes:

```
logformat egress_json {"time":%ts.%03tu,"client":"%>a","user":"%ul","method":"%rm","host":"%>rd","port":"%>rP","status":"%>Hs","reply_bytes":"%<st","request_bytes":"%>st","url":"%ru"}
access_log daemon:/var/log/squid/egress.jsonl logformat=egress_json
```

Every value but the time is quoted, because Squid writes `-` for a value it
does not have, and a bare `-` is not JSON. A value that holds a quote or a
backslash still breaks its line, which the import then refuses. `%>rd` is the
host alone, so the Squid descriptor reads it under `DESTINATION_FORM_HOST`.
Both formats also log a path or a URL, which no mapping names and the import
never reads.

### 2. Describe the source

The descriptor maps each value to its member. The Envoy fixture's:

```json
"egress_access_log": {
  "format": "json-lines",
  "fields": {"time": "start_time", "time_format": "TIME_FORMAT_RFC3339",
             "destination": "authority", "destination_form": "DESTINATION_FORM_AUTHORITY",
             "port": "upstream_remote_port",
             "method": "method", "status": "response_code",
             "bytes_sent": "bytes_sent", "bytes_received": "bytes_received",
             "caller": "downstream_remote_address"},
  "caller_basis": "CALLER_BASIS_ADDRESS"}
```

`envoy.descriptor.json` holds the whole file, with `trust: TRUST_INDEPENDENT`.
The authority's port is the connection's when `upstream_remote_port` is
`null`; when both give one and they differ, the line is refused. Under
`CALLER_BASIS_ADDRESS` the caller must be an IP address; anything else is
dropped and counted in `callers_dropped`.
`squid.descriptor.json` reads `%ts.%03tu` as `TIME_FORMAT_UNIX_SECONDS` and
the authenticated user `%ul` as a caller with `CALLER_BASIS_AUTHENTICATED`.
The descriptor must be a file of the account that runs `observe import`, and
neither its group nor others may write it. Copy the fixtures into a directory of their own:

```sh
mkdir -m 700 egress egress/log
cp internal/ingest/egresslog/testdata/envoy.descriptor.json internal/ingest/egresslog/testdata/envoy.jsonl egress/
chmod 600 egress/envoy.descriptor.json egress/envoy.jsonl
```

### 3. Import the log

```sh
guardana-control observe import --source egress/envoy.descriptor.json --log egress/log egress/envoy.jsonl
```

```text
lines_read: 4
observed: 3
written: 3
duplicate: 0
conflict: 0
refused: 1
strings_dropped: 0
callers_dropped: 0
guardana-control: observe import: 1 span(s) or line(s) refused and 0 observation(s) conflicting with the log; the import report holds the counts
```

The third line is a plain HTTP request: its authority is
`registry.example.org` with no port, so the port is `upstream_remote_port`'s,
80. It exits 1, because the fourth line names port 443 while
`upstream_remote_port` is 8443. The same command again writes nothing new and
counts the three connections as duplicates. It refuses the bad line again,
though, and exits 1 each time, until the log is rotated.
Under `TRUST_INDEPENDENT`, an input the group or others can write is refused.

### 4. Map coverage

Declare the hosts agents may reach as `egress` paths, each naming the source
that sees it:

```sh
cat > egress/inventory.json <<'EOF'
{"schema_version": "0.1", "paths": [
  {"id": "egress.api", "kind": "egress", "host": "api.example.com",
   "sources": [{"source_id": "egress-envoy", "name": "api.example.com"}]}
]}
EOF
guardana-control coverage --inventory egress/inventory.json --source egress/envoy.descriptor.json --log egress/log
```

```text
egress.api unknown: sources egress-envoy; no plane decides egress
  source egress-envoy: unknown: past its heartbeat: last heard 2026-10-04T10:00:02Z, heartbeat 300 s
undeclared egress 2001:db8::1: observed by egress-envoy: independent (unsigned descriptor), past its heartbeat: last heard 2026-10-04T10:00:02Z, heartbeat 300 s; 1 connection, port 8443; no plane decides egress
undeclared egress registry.example.org: observed by egress-envoy: independent (unsigned descriptor), past its heartbeat: last heard 2026-10-04T10:00:02Z, heartbeat 300 s; 1 connection, port 80; no plane decides egress
refused egress by egress-envoy: 1 line refused, so their connections are unknown: port 1; no plane decides egress
undeclared paths: unknown
```

The fixture's lines are from 2026-10-04, past the 300-second heartbeat, so the
declared path is unknown; over a log the proxy is still writing, it reads
observed. `2001:db8::1` and `registry.example.org` are in the log and no path
declares them, so each gets a row; the refused line gets one too, since its
destination could not be imported. An undeclared host or a refused line makes
the command exit 1. No plane decides a connection, so an
egress path is never decided or enforced.

## Verify

```sh
guardana-control observe export egress/log/observations.jsonl
```

It writes the three connection observations and the import report, whose
`refusedBy` holds `"port":"1"`. A line refused for another reason is
counted under its own key ([the reference](../reference/egress-access-log.md#refusals-and-drops)).

## Roll back

Leave `--source` and `--log` off the `coverage` command line and nothing reads
the log again. To start the log afresh, with no import running, move
`egress/log/observations.jsonl` out of its directory
([observations](../reference/observations.md#the-log)). A log that holds a
connection cannot be read by 0.14.
