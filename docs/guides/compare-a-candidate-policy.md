---
title: Compare a candidate policy
summary: Before signing a changed policy, decide your cases and a plane's evidence under both versions, and read what changes and what cannot be judged.
type: how-to
covers: [cmd/guardana-control/policy_compare.go, internal/policycompare/**, testdata/policy/compare/**]
---

# Compare a candidate policy

## When to use this

You have changed a policy document and want to know, before you sign it,
which calls the new version decides differently from the one your planes run.
`policy compare` decides the same cases under both through the kernel's own
evaluation and writes a report; [policy-compare.md](../reference/policy-compare.md)
describes every member of it. Nothing it does reaches a plane: it is a
simulation, and the report says so on every case.

## Prerequisites

- `guardana-control`, built as [cli.md](../reference/cli.md) says.
- The document in force (`--current`) and the candidate (`--candidate`).
- Cases, evidence or both: a directory of `policy test` cases written against
  the current document, as [write and test a policy](write-and-test-a-policy.md)
  shows, and an evidence export a plane's collector wrote
  ([read the evidence from a program](read-the-evidence-from-a-program.md)).

`testdata/policy/compare/` in this repository holds a worked set: two
documents, nine cases, an export with a gap and a labels file.

## Steps

### 1. Point your cases at the current document

Each case file carries the whole document it is decided under, and
`policy compare` refuses one whose document is not `--current`. Copy the
current document into every case's `document`; `expect` may stay: its format
is checked; it is not compared with any decision. Keep each case's
`decided_at` within its staleness budget of its `loaded_at` under both
policies, the smaller of the policy's `maxStaleSeconds` and the case's
`options.max_stale_seconds`, or the case is unknown as `freshness_not_held`.
A case the kernel denies on its own, for a refused delegation or two
tenants, is unknown as `not_evaluated`: it says nothing about either policy.

### 2. Export the evidence

Export the trail of the planes that run the current policy. A request whose
decision names another policy digest is counted unknown as
`historic_policy_missing`, so export the window the current policy was in
force. An export with a gap still compares: a request that lost its proposal
or its decision is unknown, and the report's scope says that a request that
looks whole may still have lost later events.

### 3. Label cases, if someone reviewed them

A labels file names who labelled and calls each case `attack` or
`legitimate`:

```json
{"kind": "policy-case-labels/v1alpha1", "labeller": "Orders security review",
 "labels": [{"case": "case:changed-definition.json", "label": "attack"},
            {"case": "request:r-read", "label": "legitimate"}]}
```

A case is `case:` and its file name, or `request:` and the request id. The
labeller should not be the policy's author; nothing can check that, and the
report says independence is declared, not verified.

### 4. Run the comparison

```
$ guardana-control policy compare \
    --current testdata/policy/compare/current.json \
    --candidate testdata/policy/compare/candidate.json \
    --cases testdata/policy/compare/cases \
    --evidence testdata/policy/compare/evidence.jsonl \
    --labels testdata/policy/compare/labels.json \
    --report /tmp/compare.json
report: /tmp/compare.json
read: 19 (9 case, 10 evidence)
evaluated on both sides: 15 of 19
unknown: 11 of 19 (export_not_whole 1, several_decisions 1, historic_policy_missing 1, recorded_stale 1, external_answer_needed 1, missing_facts 3, freshness_not_held 1, obligation_applicability_unknown 1, disagrees_with_record 1)
changes of 8 compared: 2 unchanged, 2 stricter, 3 looser, 1 other
attack: 3: 0 unchanged, 1 stricter, 0 looser, 1 other, 1 unknown
legitimate: 3: 1 unchanged, 0 stricter, 2 looser, 0 other, 0 unknown
unlabelled: 13: 1 unchanged, 1 stricter, 1 looser, 0 other, 10 unknown
labeller independence: declared, not verified
```

It exits 1 here: some cases are unknown. It exits 0 only when every case was
decided on both sides and none is unknown, and 2 when it refused an input and
wrote nothing.

### 5. Read the report

Start with the counts, then the rows. `looser` rows are the calls the
candidate lets through further: a broadened effect class or resource shows
here, and so does a binding obligation dropped. `stricter` rows are calls it
blocks or holds where the current policy let them run, or binds to more.
`other` says nothing about direction, so read each such row: it is a change
that moves both ways, such as a call held for approval that no longer emits
its alert, a changed obligation parameter, or the same action with other
codes. A rule conflict shows here: when an allow and a deny both match, the
deny stays and the allow's code joins the decision's codes.

An `unknown` row names its reason. `missing_facts` and
`external_answer_needed` mean a rule reads what the case does not hold:
evidence holds no flow and no decision point answer, so a policy that reads
them compares little against evidence alone. Write a case that states them.
`disagrees_with_record` means today's kernel on the current policy does not
decide the request as the plane recorded: read that before trusting any
other row.

## Verify

Every case appears once in `cases`; `counts.read` is their number; and
`unchanged`, `stricter`, `looser` and `other` add up to `counts.compared`,
which with `counts.unknown` makes `counts.read`. The report's `current.digest`
is the digest `policy sign` prints for the current document's bundle.

## Roll back

The command changed nothing but the report it wrote. Delete the report to
undo it.
