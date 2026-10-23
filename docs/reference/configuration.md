---
title: Configuration
summary: Every key the gateway reads, with its environment variable, kind, default, whether it is required and the spellings it takes.
type: reference
covers: [internal/gatewayconfig/**, internal/classify/**, cmd/guardana-gateway/**]
generated: scripts/gen-config.go
---

# Configuration

The gateway reads one file, named by `--config`, and then the environment: a variable
named `GUARDANA_CONTROL_` followed by a key's path in upper case, with each dot an
underscore, sets that key and wins over the file. A key the table does not declare is
refused rather than ignored, and a required key with no default has to be set by the
file or by a variable. A key with a default is never without a value, so `yes` under
Required matters only where the default is empty. Some requirements depend on another
key and are not in the table: an MCP HTTP listener needs `listener.address`, and only a
`stateful_http` listener takes `listener.session_idle`, from one minute to a day, and
`listener.max_sessions`, from 1 to 16384; an upstream
needs exactly one of `endpoint` and `command`; `evidence.fsync_interval` is needed
under the `interval` policy and refused under `every_record`; the `file` approval
provider needs `approvals.dir` and `approvals.hold_journal_dir`, and that journal
directory may be neither the spool's nor the approvals directory, nor inside either;
and `APPROVE` needs the `file` provider, since nothing outside the process answers a
request held in memory. An entry of `overrides` or `tools` is refused when no call to its tool could carry
an envelope the contract takes: `resource_type` is an identifier of at most 1024 bytes,
`resource_from` an RFC 6901 pointer of at most 8 tokens of 64 bytes, an effect whose
envelope needs a resource id (`WRITE`, `DELETE`, `TRANSACT`, `IDENTITY_OR_ACCESS` and `CONFIGURE`) needs `resource_from`, and
`COMMUNICATE` needs `trust_zone`; a tool's `name` and `provider`, and an upstream's
`name`, which is every call's `action.provider`, are identifiers of at most 1024 bytes too. An identifier is held to the contract's rule
([contracts](../contracts.md#decoding-and-validation)): invalid UTF-8 is refused, and so
are White_Space at either end and, anywhere, a space other than U+0020, a code point in
Cc, Cf, Zl or Zp, or a Default_Ignorable_Code_Point. An `enforce_api` listener serves the enforcement API on the Unix
socket `listener.socket` names, at most 103 bytes as it resolves; the plane checks that
the socket's directory is its own with no permission for group or others, and checks
neither a macOS access control list on it nor a parent directory another account may
write. It needs `runs.dir`, `listener.execution_lifetime`, from one
second to an hour with no default, and at least one entry of `tools`, each name once;
`listener.max_body_bytes` takes 1KiB to 256KiB, `listener.max_open_per_run` is
positive and below `approvals.max_open`, and a tool's resource has the plane's
`tenant_id` and `environment`. It refuses `listener.address`, `listener.origins`,
`upstreams`, `overrides` and the `upstream.` and `list.` keys, and every other kind refuses
`listener.socket`, `listener.execution_lifetime`, `listener.max_body_bytes`,
`listener.max_open_per_run` and `tools`.
`upstream.call_timeout`, `pdp.timeout` and `export.timeout` have
to be positive, so nothing waits on an upstream's call, the decision point or the
collector without a bound; `upstream.list_timeout` may be zero, which is the adapter's
own bound of `30s`, longer than the key's `10s` default, and no duration
may be negative. `runs.dir` may not be, hold or sit inside the spool, the
approvals directory, the hold journal or the pause file's directory, needs a
`listener.principal.type`, and refuses `flow.max_runs`, which bounds only the runs a
plane keeps in memory. `reaction.route`, `reaction.public_key`, `reaction.floor_dir` and
`reaction.stops` are set together or not at all; a route needs `runs.dir`,
`reaction.poll_interval` takes 100ms to a minute, and the stops directory may not be,
hold or sit inside the runs directory, the spool, the approvals directory, the hold
journal, either floor directory or the pause file's directory, compared through
symbolic links too. Every `pdp.` key is refused while `pdp.identifier` is empty,
since it would apply to no decision point, and the identifier is written into every
decision that consulted the decision point, so a credential goes in `pdp.headers`,
never in it. Other directories are compared as paths and not as what they
reach: two paths that are one directory through a symbolic link are not refused, and
a pair this build cannot compare, such as one across volumes, is refused rather than
allowed.

Rendered from the field table in `internal/gatewayconfig`. Rebuild it with
`make docs-gen`; an edit made here does not survive the next run.

| Key | Variable | Kind | Default | Required | Values |
| --- | --- | --- | --- | --- | --- |
| `mode` | `GUARDANA_CONTROL_MODE` | one of |  | yes | `OBSERVE`, `SHADOW`, `WARN`, `APPROVE`, `ENFORCE`, `LOCKDOWN` |
| `project_id` | `GUARDANA_CONTROL_PROJECT_ID` | string |  | yes |  |
| `tenant_id` | `GUARDANA_CONTROL_TENANT_ID` | string |  | yes |  |
| `environment` | `GUARDANA_CONTROL_ENVIRONMENT` | string |  | no |  |
| `log.level` | `GUARDANA_CONTROL_LOG_LEVEL` | one of | `info` | no | `debug`, `info`, `warn`, `error` |
| `listener.kind` | `GUARDANA_CONTROL_LISTENER_KIND` | one of | `stateless_http` | yes | `stateless_http`, `stateful_http`, `stdio`, `enforce_api` |
| `listener.address` | `GUARDANA_CONTROL_LISTENER_ADDRESS` | string | `127.0.0.1:8080` | no |  |
| `listener.socket` | `GUARDANA_CONTROL_LISTENER_SOCKET` | string |  | no |  |
| `listener.execution_lifetime` | `GUARDANA_CONTROL_LISTENER_EXECUTION_LIFETIME` | duration |  | no |  |
| `listener.max_body_bytes` | `GUARDANA_CONTROL_LISTENER_MAX_BODY_BYTES` | bytes, plain or with KiB, MiB, GiB | `128KiB` | no |  |
| `listener.max_open_per_run` | `GUARDANA_CONTROL_LISTENER_MAX_OPEN_PER_RUN` | integer | `16` | no |  |
| `listener.session_idle` | `GUARDANA_CONTROL_LISTENER_SESSION_IDLE` | duration | `30m` | no |  |
| `listener.max_sessions` | `GUARDANA_CONTROL_LISTENER_MAX_SESSIONS` | integer | `1024` | no |  |
| `listener.principal.id` | `GUARDANA_CONTROL_LISTENER_PRINCIPAL_ID` | string |  | yes |  |
| `listener.principal.type` | `GUARDANA_CONTROL_LISTENER_PRINCIPAL_TYPE` | string | `service` | no |  |
| `listener.principal.tenant_id` | `GUARDANA_CONTROL_LISTENER_PRINCIPAL_TENANT_ID` | string |  | no |  |
| `listener.agent.id` | `GUARDANA_CONTROL_LISTENER_AGENT_ID` | string |  | yes |  |
| `listener.agent.framework` | `GUARDANA_CONTROL_LISTENER_AGENT_FRAMEWORK` | string |  | no |  |
| `listener.agent.version` | `GUARDANA_CONTROL_LISTENER_AGENT_VERSION` | string |  | no |  |
| `health.address` | `GUARDANA_CONTROL_HEALTH_ADDRESS` | string | `127.0.0.1:8081` | no |  |
| `policy.bundle_id` | `GUARDANA_CONTROL_POLICY_BUNDLE_ID` | string |  | yes |  |
| `policy.bundle_file` | `GUARDANA_CONTROL_POLICY_BUNDLE_FILE` | string |  | yes |  |
| `policy.key_id` | `GUARDANA_CONTROL_POLICY_KEY_ID` | string |  | yes |  |
| `policy.public_key` | `GUARDANA_CONTROL_POLICY_PUBLIC_KEY` | string |  | yes |  |
| `policy.statement_file` | `GUARDANA_CONTROL_POLICY_STATEMENT_FILE` | string |  | yes |  |
| `policy.state_dir` | `GUARDANA_CONTROL_POLICY_STATE_DIR` | string |  | yes |  |
| `policy.freshness_key_id` | `GUARDANA_CONTROL_POLICY_FRESHNESS_KEY_ID` | string |  | yes |  |
| `policy.freshness_public_key` | `GUARDANA_CONTROL_POLICY_FRESHNESS_PUBLIC_KEY` | string |  | yes |  |
| `policy.max_stale` | `GUARDANA_CONTROL_POLICY_MAX_STALE` | duration | `10m` | no |  |
| `policy.poll_interval` | `GUARDANA_CONTROL_POLICY_POLL_INTERVAL` | duration |  | yes |  |
| `policy.fail_open_read` | `GUARDANA_CONTROL_POLICY_FAIL_OPEN_READ` | true or false | `false` | no |  |
| `pdp.identifier` | `GUARDANA_CONTROL_PDP_IDENTIFIER` | string |  | no |  |
| `pdp.evaluation_endpoint` | `GUARDANA_CONTROL_PDP_EVALUATION_ENDPOINT` | string |  | no |  |
| `pdp.timeout` | `GUARDANA_CONTROL_PDP_TIMEOUT` | duration | `100ms` | no |  |
| `pdp.max_in_flight` | `GUARDANA_CONTROL_PDP_MAX_IN_FLIGHT` | integer | `16` | no |  |
| `pdp.allow_plaintext` | `GUARDANA_CONTROL_PDP_ALLOW_PLAINTEXT` | true or false | `false` | no |  |
| `pdp.proxy` | `GUARDANA_CONTROL_PDP_PROXY` | string |  | no |  |
| `approvals.provider` | `GUARDANA_CONTROL_APPROVALS_PROVIDER` | one of | `memory` | yes | `memory`, `file` |
| `approvals.dir` | `GUARDANA_CONTROL_APPROVALS_DIR` | string |  | no |  |
| `approvals.hold_journal_dir` | `GUARDANA_CONTROL_APPROVALS_HOLD_JOURNAL_DIR` | string |  | no |  |
| `approvals.ttl` | `GUARDANA_CONTROL_APPROVALS_TTL` | duration | `15m` | no |  |
| `approvals.retry_after` | `GUARDANA_CONTROL_APPROVALS_RETRY_AFTER` | duration | `30s` | no |  |
| `approvals.max_held` | `GUARDANA_CONTROL_APPROVALS_MAX_HELD` | integer | `128` | no |  |
| `approvals.max_held_per_run` | `GUARDANA_CONTROL_APPROVALS_MAX_HELD_PER_RUN` | integer | `16` | no |  |
| `approvals.max_open` | `GUARDANA_CONTROL_APPROVALS_MAX_OPEN` | integer | `256` | no |  |
| `approvals.max_records` | `GUARDANA_CONTROL_APPROVALS_MAX_RECORDS` | integer | `1024` | no |  |
| `approvals.max_record_bytes` | `GUARDANA_CONTROL_APPROVALS_MAX_RECORD_BYTES` | integer | `16384` | no |  |
| `approvals.reconcile_max` | `GUARDANA_CONTROL_APPROVALS_RECONCILE_MAX` | integer | `256` | no |  |
| `pause.file` | `GUARDANA_CONTROL_PAUSE_FILE` | string |  | no |  |
| `pause.poll_interval` | `GUARDANA_CONTROL_PAUSE_POLL_INTERVAL` | duration | `1s` | no |  |
| `runs.dir` | `GUARDANA_CONTROL_RUNS_DIR` | string |  | no |  |
| `flow.max_runs` | `GUARDANA_CONTROL_FLOW_MAX_RUNS` | integer | `64` | no |  |
| `reaction.route` | `GUARDANA_CONTROL_REACTION_ROUTE` | string |  | no |  |
| `reaction.public_key` | `GUARDANA_CONTROL_REACTION_PUBLIC_KEY` | string |  | no |  |
| `reaction.floor_dir` | `GUARDANA_CONTROL_REACTION_FLOOR_DIR` | string |  | no |  |
| `reaction.stops` | `GUARDANA_CONTROL_REACTION_STOPS` | string |  | no |  |
| `reaction.poll_interval` | `GUARDANA_CONTROL_REACTION_POLL_INTERVAL` | duration | `1s` | no |  |
| `evidence.dir` | `GUARDANA_CONTROL_EVIDENCE_DIR` | string |  | yes |  |
| `evidence.max_bytes` | `GUARDANA_CONTROL_EVIDENCE_MAX_BYTES` | bytes, plain or with KiB, MiB, GiB | `1GiB` | no |  |
| `evidence.segment_bytes` | `GUARDANA_CONTROL_EVIDENCE_SEGMENT_BYTES` | bytes, plain or with KiB, MiB, GiB | `64MiB` | no |  |
| `evidence.closing_reserve` | `GUARDANA_CONTROL_EVIDENCE_CLOSING_RESERVE` | bytes, plain or with KiB, MiB, GiB | `64KiB` | no |  |
| `evidence.fsync` | `GUARDANA_CONTROL_EVIDENCE_FSYNC` | one of | `every_record` | yes | `every_record`, `interval` |
| `evidence.fsync_interval` | `GUARDANA_CONTROL_EVIDENCE_FSYNC_INTERVAL` | duration | `0s` | no |  |
| `evidence.on_unwritable` | `GUARDANA_CONTROL_EVIDENCE_ON_UNWRITABLE` | one of | `block` | yes | `block`, `allow_reads` |
| `export.endpoint` | `GUARDANA_CONTROL_EXPORT_ENDPOINT` | string |  | yes |  |
| `export.allow_plaintext` | `GUARDANA_CONTROL_EXPORT_ALLOW_PLAINTEXT` | true or false | `false` | no |  |
| `export.timeout` | `GUARDANA_CONTROL_EXPORT_TIMEOUT` | duration | `10s` | no |  |
| `export.in_flight` | `GUARDANA_CONTROL_EXPORT_IN_FLIGHT` | integer | `4` | no |  |
| `export.max_batch` | `GUARDANA_CONTROL_EXPORT_MAX_BATCH` | integer | `128` | no |  |
| `export.linger` | `GUARDANA_CONTROL_EXPORT_LINGER` | duration | `100ms` | no |  |
| `export.backoff` | `GUARDANA_CONTROL_EXPORT_BACKOFF` | duration | `500ms` | no |  |
| `export.max_backoff` | `GUARDANA_CONTROL_EXPORT_MAX_BACKOFF` | duration | `30s` | no |  |
| `list.shaping` | `GUARDANA_CONTROL_LIST_SHAPING` | one of | `none` | yes | `none`, `annotate`, `hide` |
| `list.ttl` | `GUARDANA_CONTROL_LIST_TTL` | duration | `1m` | no |  |
| `upstream.call_timeout` | `GUARDANA_CONTROL_UPSTREAM_CALL_TIMEOUT` | duration | `30s` | no |  |
| `upstream.list_timeout` | `GUARDANA_CONTROL_UPSTREAM_LIST_TIMEOUT` | duration | `10s` | no | bounds reading one upstream's list, and connecting to each upstream at start; `0` is the adapter's own `30s` |
| `upstreams.N.name` | `GUARDANA_CONTROL_UPSTREAMS_N_NAME` | string |  | yes |  |
| `upstreams.N.endpoint` | `GUARDANA_CONTROL_UPSTREAMS_N_ENDPOINT` | string |  | no |  |
| `upstreams.N.command` | `GUARDANA_CONTROL_UPSTREAMS_N_COMMAND` | string |  | no |  |
| `upstreams.N.tenant_id` | `GUARDANA_CONTROL_UPSTREAMS_N_TENANT_ID` | string |  | no |  |
| `upstreams.N.environment` | `GUARDANA_CONTROL_UPSTREAMS_N_ENVIRONMENT` | string |  | no |  |
| `overrides.N.upstream` | `GUARDANA_CONTROL_OVERRIDES_N_UPSTREAM` | string |  | yes |  |
| `overrides.N.tool` | `GUARDANA_CONTROL_OVERRIDES_N_TOOL` | string |  | yes |  |
| `overrides.N.fingerprint` | `GUARDANA_CONTROL_OVERRIDES_N_FINGERPRINT` | string |  | yes |  |
| `overrides.N.effect` | `GUARDANA_CONTROL_OVERRIDES_N_EFFECT` | one of |  | yes | `READ`, `WRITE`, `DELETE`, `EXECUTE`, `COMMUNICATE`, `TRANSACT`, `IDENTITY_OR_ACCESS`, `CONFIGURE`, `SPAWN_OR_DELEGATE` |
| `overrides.N.resource_type` | `GUARDANA_CONTROL_OVERRIDES_N_RESOURCE_TYPE` | string |  | yes |  |
| `overrides.N.resource_from` | `GUARDANA_CONTROL_OVERRIDES_N_RESOURCE_FROM` | string |  | no |  |
| `overrides.N.trust_zone` | `GUARDANA_CONTROL_OVERRIDES_N_TRUST_ZONE` | one of |  | no | an empty value, `TRUSTED_INTERNAL`, `PARTNER`, `UNTRUSTED_EXTERNAL`, `USER_CONTROLLED`, `MODEL_GENERATED` |
| `overrides.N.returns.trust` | `GUARDANA_CONTROL_OVERRIDES_N_RETURNS_TRUST` | one of |  | no | an empty value, `TRUSTED_INTERNAL`, `PARTNER`, `UNTRUSTED_EXTERNAL`, `USER_CONTROLLED`, `MODEL_GENERATED` |
| `overrides.N.returns.sensitivity` | `GUARDANA_CONTROL_OVERRIDES_N_RETURNS_SENSITIVITY` | one of |  | no | an empty value, `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`, `SECRET` |
| `tools.N.name` | `GUARDANA_CONTROL_TOOLS_N_NAME` | string |  | yes |  |
| `tools.N.effect` | `GUARDANA_CONTROL_TOOLS_N_EFFECT` | one of |  | yes | `READ`, `WRITE`, `DELETE`, `EXECUTE`, `COMMUNICATE`, `TRANSACT`, `IDENTITY_OR_ACCESS`, `CONFIGURE` |
| `tools.N.provider` | `GUARDANA_CONTROL_TOOLS_N_PROVIDER` | string |  | yes |  |
| `tools.N.resource_type` | `GUARDANA_CONTROL_TOOLS_N_RESOURCE_TYPE` | string |  | yes |  |
| `tools.N.resource_from` | `GUARDANA_CONTROL_TOOLS_N_RESOURCE_FROM` | string |  | no |  |
| `tools.N.trust_zone` | `GUARDANA_CONTROL_TOOLS_N_TRUST_ZONE` | one of |  | no | an empty value, `TRUSTED_INTERNAL`, `PARTNER`, `UNTRUSTED_EXTERNAL`, `USER_CONTROLLED`, `MODEL_GENERATED` |
| `tools.N.returns.trust` | `GUARDANA_CONTROL_TOOLS_N_RETURNS_TRUST` | one of |  | no | an empty value, `TRUSTED_INTERNAL`, `PARTNER`, `UNTRUSTED_EXTERNAL`, `USER_CONTROLLED`, `MODEL_GENERATED` |
| `tools.N.returns.sensitivity` | `GUARDANA_CONTROL_TOOLS_N_RETURNS_SENSITIVITY` | one of |  | no | an empty value, `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`, `SECRET` |

These keys hold a list or a map, one element per key:

| Key | Variable | One element |
| --- | --- | --- |
| `listener.origins.N` | `GUARDANA_CONTROL_LISTENER_ORIGINS_N` | one origin a browser may call the listener from |
| `pdp.informational_context.N` | `GUARDANA_CONTROL_PDP_INFORMATIONAL_CONTEXT_N` | one context member an allowing answer of the decision point may carry |
| `upstreams.N.args.N` | `GUARDANA_CONTROL_UPSTREAMS_N_ARGS_N` | one argument of an upstream's command |
| `upstreams.N.env.N` | `GUARDANA_CONTROL_UPSTREAMS_N_ENV_N` | the name of one variable of the plane's environment an upstream's command receives, beside PATH, HOME, LANG, LC_ALL, TMPDIR, USER; no other variable reaches it, and its value is never printed |
| `export.headers.<name>` | `GUARDANA_CONTROL_EXPORT_HEADERS_<NAME>` | one header the exporter sends; its value is a credential and is never printed |
| `pdp.headers.<name>` | `GUARDANA_CONTROL_PDP_HEADERS_<NAME>` | one header every question to the decision point carries; its value is a credential and is never printed |

`N` in a key is an entry's index, from 0, and `<name>` a name the operator
chooses. A variable for a key under `N` sets an entry the file declares; it never adds
one. In the variable of a header each `_` stands for a `-` in the header's name.
Header names are compared without case, so a variable wins over the file however
either spells the name. A name the file or the environment spells twice is refused,
and so is a `_` in a header's name in the file, since no variable could replace it.
A relative path resolves against the directory of the file.
