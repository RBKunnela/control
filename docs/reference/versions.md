---
title: Format versions
summary: Every versioned file and message a user writes or reads, the version this tree writes, the versions it reads, and how stable each is.
type: reference
covers: [internal/evidence/event.go, internal/evidence/version.go, internal/core/codes.go, adapters/mcp/translate.go, adapters/enforce/**, internal/gateway/decisions.go, internal/gateway/journal.go, internal/trailfile/export.go, internal/coverage/export.go, internal/coverage/inventory.go, internal/policy/rules/rules.go, internal/policy/statement.go, internal/scenario/scenario.go, internal/supervise/ruletable.go, internal/supervise/evaluate.go, internal/supervise/record.go, internal/supervise/report.go, cmd/guardana-control/procedure_cases.go, internal/findinglog/**, internal/observe/version.go, internal/ingest/*/descriptor.go, internal/observelog/export.go, internal/runs/s*.go, internal/reaction/**, internal/pause/*.go, internal/approvals/record.go, internal/holdjournal/**, internal/policystate/format.go, internal/hookbridge/**, internal/enforceclient/client.go, internal/policy/bundle/bundle.go, internal/spool/frame.go]
generated: go test ./internal/docscheck -run TestVersionsPageIsTheCode
---

# Format versions

The product is `0.x`, with no compatibility promise between minor releases
([CHANGELOG.md](../../CHANGELOG.md), [ADR-0008](../adr/0008-branching-and-release-policy.md)),
and each format below carries a version of its own. A reader refuses any
version it does not read, a new major included, rather than read it as the
newest it knows (invariant 3 in [AGENTS.md](../../AGENTS.md)).

## The formats

Written is what this tree writes, `—` where only the operator writes the
file. Read is what this tree accepts: `1.x` is any minor of major 1, and `—`
means nothing here reads the format back. `stable` is the frozen v1 wire
contract alone; an `experimental` or alpha format may change without a major
version. [status.md](../status.md) is the inventory.

| Format | Written | Read | Stability | Defined in |
| --- | --- | --- | --- | --- |
| Wire messages (`guardana.control.v1`, `schema_version`) | `1.0` | `1.x` | `stable` | [contracts.md](../contracts.md#schema-versioning) |
| Evidence export (`guardana.control.evidence-export`) | `1.1` | `1.x` | `experimental` | [contracts.md](../contracts.md#the-evidence-export) |
| Trail segment manifest (`guardana.control.segments`) | `0.1` | `0.1` | `experimental` | [ADR-0072](../adr/0072-the-collector-keeps-bounded-segments-of-one-project-behind-a-credential.md) |
| Policy document (`apiVersion`) | — | `agent-policy/v1alpha1` | alpha | [policy-format.md](policy-format.md#the-document) |
| Freshness statement (`kind`) | `agent-policy-freshness/v1alpha1` | `agent-policy-freshness/v1alpha1` | `experimental` | [ADR-0038](../adr/0038-a-signed-freshness-statement-and-a-serial-floor.md) |
| Trust roster (`kind`) | `trust-roster/v1alpha1` | `trust-roster/v1alpha1` | `experimental` | [ADR-0071](../adr/0071-operators-are-named-by-a-signed-roster.md) |
| Approval answer (`kind`) | `approval-answer/v1alpha1` | `approval-answer/v1alpha1` | `experimental` | [ADR-0073](../adr/0073-an-approval-counts-only-as-the-plane-judges-it.md) |
| Floor directories (`schema_version`) | `1.0` | `1.x` | `experimental` | [cli.md](cli.md#guardana-control) |
| Scenario (`kind`) | — | `agent-scenario/v1alpha1` | `experimental` | [scenario-format.md](scenario-format.md#the-document) |
| Pause file (`schema_version`) | `2`, `3` | `1`, `2`, `3` | `experimental` | [pausing calls](../concepts/enforcement-modes.md#pausing-calls) |
| Approvals directory (`schema_version`) | `2.1` | `2.x` | `experimental` | [approvals](../concepts/approvals-and-the-held-call.md#what-is-held-and-by-whom) |
| Hold journal (`schema_version`) | `1.0` | `1.x` | `experimental` | [approvals](../concepts/approvals-and-the-held-call.md#a-hold-the-plane-loses) |
| Spent ledger (`schema_version`) | `1.0` | `1.x` | `experimental` | [approvals](../concepts/approvals-and-the-held-call.md#an-approval-is-spent-once) |
| Hook profile (`kind`) | — | `hook-profile/v1alpha1` | `experimental` | [runtime-profiles](../extending/runtime-profiles.md#the-profile) |
| Hook bridge handles (`version`) | `1.0` | `1.x` | `experimental` | [runtime-profiles](../extending/runtime-profiles.md#what-the-bridge-does) |
| Runs directory marker and root state (`schema_version`) | `1.0` | `1.x` | `experimental` | [contracts.md](../contracts.md#the-runs-directory) |
| Run record (`schema_version`) | `2.0` | `2.x` | `experimental` | [contracts.md](../contracts.md#the-runs-directory) |
| Signed run record (`schema_version`) | `3.0` | `3.x` | `experimental` | [runs.md](runs.md#a-signed-runs-directory) |
| Observation records and log (`guardana.control.observe.v1alpha1`) | `0.1`, `0.2`, `0.3` | `0.1`, `0.2`, `0.3` | `experimental` | [observations.md](observations.md#the-log) |
| Source descriptor (`schema_version`) | — | `0.1`, `0.2` | `experimental` | [observations.md](observations.md#the-source-descriptor) |
| OpenTelemetry GenAI spans, imported | — | conventions `1.41.0`, OTLP `1.11.1` | `experimental` | [observations.md](observations.md#what-an-import-keeps) |
| Egress access log, imported | — | `json-lines` under the descriptor's mapping, no version of its own | `experimental` | [egress-access-log.md](egress-access-log.md#the-descriptor) |
| Observation export (`guardana.control.observation-export`) | `0.1` | — | `experimental` | [observations.md](observations.md#commands) |
| Coverage inventory (`schema_version`) | — | `0.1` | `experimental` | [coverage.md](coverage.md#the-inventory) |
| Procedure (`schema_version`) | — | `0.1`, `0.2` | `experimental` | [supervision.md](supervision.md#the-procedure) |
| Procedure test cases (`schema_version`) | — | `0.1` | `experimental` | [test a procedure](../guides/test-a-procedure.md#2-write-a-case) |
| Finding records and log (`guardana.control.finding.v1alpha1`) | `0.1`, `0.2` | `0.1`, `0.2` | `experimental` | [supervision.md](supervision.md#the-finding-record-and-its-log) |
| Findings export (`guardana.control.findings-export`) | `0.1` | — | `experimental` | [supervision.md](supervision.md#findings-export) |
| Enforcement API (`guardana.control.enforce.v1alpha1`) | `v1alpha1` | `v1alpha1` | `experimental` | [contracts.md](../contracts.md#the-enforcement-api) |
| Reaction route (`kind`) | — | `reaction-route/v1alpha1`, `reaction-route/v1alpha2` | `experimental` | [contracts.md](../contracts.md#the-route) |
| Stop list (`version`) | `1.0`, `2.0` | `1.0`, `2.0` | `experimental` | [contracts.md](../contracts.md#the-stop-list) |
| Lift (`kind`, `version`) | `reaction-lift/v1alpha1`, `1.0`, `reaction-lift/v1alpha2` | `reaction-lift/v1alpha1`, `1.0`, `reaction-lift/v1alpha2` | `experimental` | [contracts.md](../contracts.md#the-lift) |
| Health answer (`schema`) | `2` | — | `experimental` | [run the gateway](../guides/run-the-gateway.md#6-read-the-health) |

The gateway's configuration file and a `policy test` case carry no version.
Each refuses a key it does not know, so a file that names a key a later
release added is refused, not read in part. The signed envelopes around a
policy bundle, a freshness statement, a route and a lift carry no version of
their own, only the payload type each is signed under, and the evidence
spool frames its segments with no version at all, so a spool another release
wrote is not promised readable. `notify`'s `--state` list of delivered alerts,
one quoted key per line, carries none either. A plane under
`approvals.authority: signed` reads pause file `3` alone, and any other `1`
and `2` alone. It reads a `reaction-route/v1alpha2` route alone, with stop
list `2.0`, whose signed header is `reaction-list-header/2.0`, and lift
`reaction-lift/v1alpha2`; any other plane reads a `v1alpha1` route alone,
with stop list `1.0` and lift `reaction-lift/v1alpha1`. A `1.0` list is not
carried into `2.0`: start a new list, and `react` stops again the findings
that still may stop a run.

## Reading files an older release wrote

- **Wire messages, the evidence export, the runs directory's marker and
  root states, the hold journal, the spent ledger and the floor
  directories.** Any minor of major 1 is read. A member the reader does not
  know is refused, so a file a later minor extended is refused when that
  member arrives, never read with it dropped.
- **Approvals directory.** Any minor of major 2 is read. A 2.1 record names
  the authority holding it and the call's tenant and project; a 2.0 record
  names none of them and is read as held under `directory`. A 1.0 directory
  kept the plane's spent mark beside the answers, so it is refused: empty
  it; its holds expire within `approvals.ttl`.
- **Run record.** Any minor of major 2 is read, except in a signed layout's
  `records/`, which reads major 3 alone. A record of major 1 names no
  project, so it is refused, never read as any project's run: open the run
  again ([runs.md](runs.md#runs-an-earlier-release-opened)).
- **Policy document, scenario, reaction route, freshness statement and
  lift.** One exact `kind` is read; another is refused, never read as this
  one.
- **Procedure.** A `0.1` document reads as before, with the same digest,
  rules and findings, and the records it gives keep schema `0.1`, unless the
  report names a source in doubt.
- **Finding log.** A log with no header is read as it is; an empty one gains
  a header when it is opened. A release that does not know a member of a
  line, such as one reading schema `0.1` alone, or one without
  `sources_in_doubt` reading a report that names a source, refuses the whole
  log as damaged at that line; nothing is misread.
- **Findings export.** A cursor holds only in its own log, known by the
  header's `log_id`, or by its first line in a log that has no header; the
  trailer's `identity` says which.
- **Observation records and the source descriptor.** Only the minors in the
  reader's table are read; another `0.x` is refused rather than read as the
  nearest one. A record is `0.3` exactly when it carries a connection,
  refusals by reason, callers dropped or its source's kind, and an import
  report `0.2` exactly when it names runs
  in doubt or sets `every_run_doubted` and carries neither. A descriptor is
  `0.2` exactly when it maps an egress access log, and every `0.1` descriptor
  keeps its digest. A release whose table lacks a version refuses its lines:
  0.14's `observe import` and `coverage` refuse a log holding a `0.3` line as
  damaged. The observation export carries each record's line as the log
  holds it, so its reader meets `0.2` and `0.3` lines inside an export whose
  own version stays `0.1`; an earlier release's export counts such a line as
  an `unsupported_version` gap.

`internal/docscheck/versions_test.go` holds the table to the constants and
readers in the code. It fails when a version changes there, when a format is
missing from this page, and, for each reader it can call, when that reader
accepts a version the page does not name.
