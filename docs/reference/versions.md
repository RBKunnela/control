---
title: Format versions
summary: Every versioned file and message a user writes or reads, the version this tree writes, the versions it reads, and how stable each is.
type: reference
covers: [internal/evidence/event.go, internal/evidence/version.go, internal/core/codes.go, adapters/mcp/translate.go, adapters/enforce/**, internal/gateway/decisions.go, internal/gateway/journal.go, internal/trailfile/export.go, internal/coverage/export.go, internal/coverage/inventory.go, internal/policy/rules/rules.go, internal/policy/statement.go, internal/scenario/scenario.go, internal/supervise/ruletable.go, internal/supervise/evaluate.go, internal/supervise/record.go, internal/supervise/report.go, cmd/guardana-control/procedure_cases.go, internal/findinglog/**, internal/observe/version.go, internal/observe/descriptor.go, internal/observelog/export.go, internal/runs/strict.go, internal/reaction/**, internal/pause/document.go, internal/approvals/record.go, internal/holdjournal/**, internal/policystate/format.go, internal/hookbridge/**, internal/enforceclient/client.go, internal/policy/bundle/bundle.go, internal/spool/frame.go]
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
| Evidence export (`guardana.control.evidence-export`) | `1.0` | `1.x` | `experimental` | [contracts.md](../contracts.md#the-evidence-export) |
| Policy document (`apiVersion`) | — | `agent-policy/v1alpha1` | alpha | [policy-format.md](policy-format.md#the-document) |
| Freshness statement (`kind`) | `agent-policy-freshness/v1alpha1` | `agent-policy-freshness/v1alpha1` | `experimental` | [ADR-0038](../adr/0038-a-signed-freshness-statement-and-a-serial-floor.md) |
| Floor directories (`schema_version`) | `1.0` | `1.x` | `experimental` | [cli.md](cli.md#guardana-control) |
| Scenario (`kind`) | — | `agent-scenario/v1alpha1` | `experimental` | [scenario-format.md](scenario-format.md#the-document) |
| Pause file (`schema_version`) | `1` | `1` | `experimental` | [cli.md](cli.md#guardana-control) |
| Approvals directory (`schema_version`) | `1.0` | `1.x` | `experimental` | [approvals](../concepts/approvals-and-the-held-call.md#what-is-held-and-by-whom) |
| Hold journal (`schema_version`) | `1.0` | `1.x` | `experimental` | [approvals](../concepts/approvals-and-the-held-call.md#a-hold-the-plane-loses) |
| Hook profile (`kind`) | — | `hook-profile/v1alpha1` | `experimental` | [runtime-profiles](../extending/runtime-profiles.md#the-profile) |
| Hook bridge handles (`version`) | `1.0` | `1.x` | `experimental` | [runtime-profiles](../extending/runtime-profiles.md#what-the-bridge-does) |
| Runs directory marker and root state (`schema_version`) | `1.0` | `1.x` | `experimental` | [contracts.md](../contracts.md#the-runs-directory) |
| Run record (`schema_version`) | `2.0` | `2.x` | `experimental` | [contracts.md](../contracts.md#the-runs-directory) |
| Observation records and log (`guardana.control.observe.v1alpha1`) | `0.1`, `0.2` | `0.1`, `0.2` | `experimental` | [observations.md](observations.md#the-log) |
| Source descriptor (`schema_version`) | — | `0.1` | `experimental` | [observations.md](observations.md#the-source-descriptor) |
| OpenTelemetry GenAI spans, imported | — | conventions `1.41.0`, OTLP `1.11.1` | `experimental` | [observations.md](observations.md#what-an-import-keeps) |
| Observation export (`guardana.control.observation-export`) | `0.1` | — | `experimental` | [observations.md](observations.md#commands) |
| Coverage inventory (`schema_version`) | — | `0.1` | `experimental` | [coverage.md](coverage.md#the-inventory) |
| Procedure (`schema_version`) | — | `0.1`, `0.2` | `experimental` | [supervision.md](supervision.md#the-procedure) |
| Procedure test cases (`schema_version`) | — | `0.1` | `experimental` | [test a procedure](../guides/test-a-procedure.md#2-write-a-case) |
| Finding records and log (`guardana.control.finding.v1alpha1`) | `0.1`, `0.2` | `0.1`, `0.2` | `experimental` | [supervision.md](supervision.md#the-finding-record-and-its-log) |
| Findings export (`guardana.control.findings-export`) | `0.1` | — | `experimental` | [supervision.md](supervision.md#findings-export) |
| Enforcement API (`guardana.control.enforce.v1alpha1`) | `v1alpha1` | `v1alpha1` | `experimental` | [contracts.md](../contracts.md#the-enforcement-api) |
| Reaction route (`kind`) | — | `reaction-route/v1alpha1` | `experimental` | [contracts.md](../contracts.md#the-route) |
| Stop list (`version`) | `1.0` | `1.0` | `experimental` | [contracts.md](../contracts.md#the-stop-list) |
| Lift (`kind`, `version`) | `reaction-lift/v1alpha1`, `1.0` | `reaction-lift/v1alpha1`, `1.0` | `experimental` | [contracts.md](../contracts.md#the-lift) |

The gateway's configuration file and a `policy test` case carry no version.
Each refuses a key it does not know, so a file that names a key a later
release added is refused, not read in part. The signed envelopes around a
policy bundle, a freshness statement, a route and a lift carry no version of
their own, only the payload type each is signed under, and the evidence
spool frames its segments with no version at all, so a spool another release
wrote is not promised readable. `notify`'s `--state` list of delivered alerts,
one quoted key per line, carries none either.

## Reading files an older release wrote

- **Wire messages, the evidence export, the runs directory's marker and
  root states, the approvals directory, the hold journal and the floor
  directories.** Any minor of major 1 is read. A member the reader does not
  know is refused, so a file a later minor extended is refused when that
  member arrives, never read with it dropped.
- **Run record.** Any minor of major 2 is read. A record of major 1 names no
  project, so it is refused, never read as any project's run: open the run
  again ([runs.md](runs.md#runs-an-earlier-release-opened)).
- **Policy document, scenario, reaction route, freshness statement and
  lift.** One exact `kind` is read; another is refused, never read as this
  one.
- **Procedure.** A `0.1` document reads as before, with the same digest,
  rules and findings, and the records it gives keep schema `0.1`.
- **Finding log.** A log with no header is read as it is; an empty one gains
  a header when it is opened. A reader of schema `0.1` alone, such as an
  earlier release's, refuses every `0.2` line by name.
- **Findings export.** A cursor holds only in its own log, known by the
  header's `log_id`, or by its first line in a log that has no header; the
  trailer's `identity` says which.
- **Observation records and the source descriptor.** Only the minors in the
  reader's table are read; another `0.x` is refused rather than read as the
  nearest one. An import report is `0.2` exactly when it names runs in doubt
  or sets `every_run_doubted`, and a reader of `0.1` alone, such as an
  earlier release's, refuses that line. The observation export carries each
  report's line as the log holds it, so its reader meets `0.2` import
  reports inside an export whose own version stays `0.1`; an earlier
  release's export counts such a line as an `unsupported_version` gap.

`internal/docscheck/versions_test.go` holds the table to the constants and
readers in the code. It fails when a version changes there, when a format is
missing from this page, and, for each reader it can call, when that reader
accepts a version the page does not name.
