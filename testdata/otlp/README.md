# OTLP logs golden

`export_logs_request.json` is the OTLP/HTTP logs request the exporter in
`adapters/otel` has to produce for the four events in `events.jsonl`. It pins
the protobuf JSON mapping of `ExportLogsServiceRequest`, so the exporter can
be written on the standard library and still be checked against the
protocol's own types (ADR-0014).

Provenance: produced once with `go.opentelemetry.io/proto/otlp v1.11.0`
(`collector/logs/v1`, `logs/v1`, `common/v1`, `resource/v1`) and
`google.golang.org/protobuf v1.36.12` `protojson`, in a throwaway module
outside this repository, by `go run . testdata/otlp`; both files are that
run's output and neither is edited by hand.

What the generator encodes, and the exporter has to match:

- one `resourceLogs` entry whose resource carries `service.name` set to the
  product slug, one `scopeLogs` entry whose scope is named after the product's
  OpenTelemetry namespace;
- one `logRecords` entry per event: `timeUnixNano` from `occurred_at`, absent
  when the event has none, or its time precedes 1970 or passes 2554; `severityNumber` `SEVERITY_NUMBER_INFO` and
  `severityText` `INFO`; `body.stringValue` the event's JSONL line without its
  newline, exactly as `internal/evidence` writes it; attributes, in this
  order and each under the namespace prefix, for `event_id`, `request_id`,
  `run_id`, `project_id`, `tenant_id`, `kind` and `enforcement_mode`, an empty
  identifier left out and an enum given by its name.

The test compares the two documents parsed, so member order is free and
every value is exact. `scripts/rename-product.sh` rewrites the brand literals
in both files as it does everywhere under `testdata/`.
