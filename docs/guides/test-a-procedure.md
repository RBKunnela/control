---
title: Test a procedure
summary: Lint a procedure document, then prove what supervise finds with cases that state a run, its evidence and every expected finding.
type: how-to
covers: [cmd/guardana-control/procedure*.go, testdata/procedure/**]
---

# Test a procedure

## When to use this

You wrote or changed a procedure, and you want to know what `supervise` will
find in a run before a real run depends on it. `procedure lint` says whether a
document is one this build reads and what it configures; `procedure test`
supervises runs you describe and compares what was found with what you
expect, exactly. Both are `experimental`; [status.md](../status.md) is the
inventory. Neither reads a runs directory, a findings log or the clock, and
neither writes anything.

What a procedure may say is in [reference/supervision.md](../reference/supervision.md).

## Prerequisites

- This repository at the Go toolchain `go.mod` pins. Run the commands with
  `go run ./cmd/guardana-control ...` from its root.
- A procedure document of schema `0.1` or `0.2`. The worked example is
  [testdata/procedure/](../../testdata/procedure/): `refund-0.1.json` and
  `refund-0.2.json` with a cases document each.

## Steps

### 1. Lint the procedure

```
$ go run ./cmd/guardana-control procedure lint testdata/procedure/refund-0.2.json
schema_version: 0.2
procedure_id: refund
version: 2
digest: 3bdccd18fb0503f6168a59a8bae712b9b37be7e4435f796b111be409f7d59dd6
children: inherit
rule: REPEATED_DENIAL version 2, may stop
rule: STEP_OUTSIDE_PROCEDURE version 1, may stop
rule: DEADLINE_EXCEEDED version 1, may stop
rule: REQUIRED_STEP_SKIPPED version 1, never stops
rule: STEP_OUT_OF_ORDER version 2, never stops
rule: CONTINUED_AFTER_FAILURE version 2, never stops
rule: RESOURCE_OUTSIDE_RUN version 1, may stop
rule: DENIED_ACTION_RETRIED_ARGUMENTS version 1, may stop
rule: DENIED_ACTION_RETRIED_RESOURCE version 1, may stop
rule: DENIED_ACTION_RETRIED_AROUND version 1, never stops
rule: EXCEPTION_TAKEN version 1, never stops
```

The digest is the one `supervise` records, so an edit shows as a new digest.
Each rule of the schema is listed with its version and whether a confirmed
finding of it may stop a run; a route may name only those that may, at the
version listed. A
document the reader refuses exits 2 with its reason on one line and nothing
on stdout:

```
$ go run ./cmd/guardana-control procedure lint step-failed.json
guardana-control: procedure lint: step-failed.json: supervise: procedure refused: an exception on a rule that may stop a run is taken only on an approval
```

### 2. Write a case

A cases document names the procedure and holds one or more cases. Paths in it
are read from the document's own directory.

```json
{
  "schema_version": "0.1",
  "procedure": "refund-0.2.json",
  "cases": [
    {
      "name": "a resource outside the run",
      "run": {"id": "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "tenant": "t1", "parent": "", "closed": true},
      "tree": [],
      "evidence": [{"whole": true, "events": [ ... ]}],
      "expect": {
        "rules": {"REPEATED_DENIAL": "CHECKED", "...": "...", "DENIED_ACTION_RETRIED_AROUND": "NOT_CHECKED"},
        "findings": [
          {"rule": "RESOURCE_OUTSIDE_RUN", "verdict": "CONFIRMED",
           "run": "run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "requests": ["r1", "r2"]}
        ]
      }
    }
  ]
}
```

Every member is required except `sources` and `sources_not_read`, and a member
the format does not have is refused:

- `run` is the supervised run as its record would say: its id, tenant,
  parent (empty for a root) and whether it is closed. Rules that rest on what
  was not seen are checked only on a closed run.
- `tree` lists the other runs of its tree, each after its parent, for a `0.2`
  procedure; `[]` is the run alone.
- `evidence` holds exports, each either `{"path": "<export file>"}`, a file
  the gateway's trail export wrote, or `{"whole": <bool>, "events": [...]}`
  with the events as that export writes them.
- `sources`, if given, are sources of an agent runtime's spans: `source_id`,
  `heartbeat_seconds`, `last_heard` (left out for a source never heard) and
  `observations`. `sources_not_read` names sources given and not found.
- Every time comes from the events and the sources, written in UTC with `Z`.

`expect` states the state of every rule the report lists (`CHECKED`,
`NOT_CHECKED` or `OFF`) and every finding: its rule, its verdict
(`CONFIRMED`, `SUSPECTED` or `INDETERMINATE`), the run it names, the requests
it cites and, if any, the observations it cites. `"findings": []` says no
finding is made. `never_heard`, `silent` and `not_read`, each optional and
`[]` when left out, list the sources the run was not judged against for that
reason, so a source that went unheard fails a case that does not list it.

### 3. Run the cases

```
$ go run ./cmd/guardana-control procedure test testdata/procedure/cases-0.2.json
ok   a waiver taken: EXCEPTION_TAKEN CONFIRMED
ok   a resource outside the run: RESOURCE_OUTSIDE_RUN CONFIRMED
ok   a denied refund retried with other arguments: DENIED_ACTION_RETRIED_ARGUMENTS CONFIRMED
procedure refund version 2: 3 cases, 3 passed, 0 failed
```

A case passes only when every rule's state, the whole set of findings and
the sources not judged against match. A failing case names each difference on
its line: a field of a finding that differs, a finding missing or unexpected,
a rule whose state differs or that the expectation leaves out, a list of
sources that differs, or `refused:` and the reason when `supervise` refuses
the case's input:

```
FAIL a resource outside the run: finding RESOURCE_OUTSIDE_RUN SUSPECTED run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa [r1 r2]: verdict CONFIRMED, want SUSPECTED
```

## Verify

`procedure test` exits 0 when every case passed and 1 when any failed. A
cases document it cannot read, a version other than `0.1`, a procedure the
reader refuses, an export it cannot read, no case, or two cases of one name
exit 2 with one line on stderr and nothing run.

## Roll back

Both commands only read. To undo a procedure change, restore the document you
had and run its cases again; `supervise` records the digest of whichever you
give it.
