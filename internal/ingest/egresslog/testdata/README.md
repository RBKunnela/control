# Egress access-log fixtures

Each `*.jsonl` file is what a proxy writes under the format shown here, read
by the descriptor beside it. Member names are the operator's choice; values
come from the proxies' own format codes. Hosts are reserved example names,
and the token in an Envoy path is a placeholder the importer must never copy.

## Envoy: `envoy.*` and `envoy-sni.*`

Sources: the Envoy 1.41.0-dev documentation, "Access logging"
(`configuration/observability/access_log/usage`) and "Substitution formatter"
(`configuration/advanced/substitution_formatter`).

`envoy.jsonl` is a forward proxy's log, its destination `%REQ(:AUTHORITY)%`
read under `DESTINATION_FORM_AUTHORITY`:

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

`envoy-sni.jsonl` maps `server_name: "%REQUESTED_SERVER_NAME%"` instead,
under `DESTINATION_FORM_HOST`: the formatter page gives it as the TLS
connection's SNI by default, so it is a host only on a listener that
terminates TLS. The pages do not say how an IPv6 authority is spelled, nor
how `%BYTES_SENT%` and `%UPSTREAM_REMOTE_PORT%` render in typed JSON, so the
importer reads a number as a JSON number or a decimal string. An unset value
is `null` in typed JSON and `"-"` in text.

## Squid: `squid.jsonl`, `squid.descriptor.json`

Source: the Squid `logformat` reference (`Doc/config/logformat`, versions 6
and 7). Squid has no JSON encoding, so the operator writes the braces and
quotes:

```
logformat egress_json {"time":%ts.%03tu,"client":"%>a","user":"%ul","method":"%rm","host":"%>rd","port":"%>rP","status":"%>Hs","reply_bytes":"%<st","request_bytes":"%>st","url":"%ru"}
access_log daemon:/var/log/squid/egress.jsonl logformat=egress_json
```

The destination is `%>rd`, the request URL's domain, under
`DESTINATION_FORM_HOST`, with `%>rP` its port. The page does not say how
`%ru` spells a CONNECT target, so no fixture reads it as an authority. Every
value but the time is quoted, since Squid writes a bare `-` for a value it
lacks; a value holding a quote or a backslash breaks the line, which the
importer refuses. `%<st` is the reply sent to the client and `%>st` the
request received from it.
