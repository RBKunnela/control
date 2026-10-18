# ADR-0052: A change is gated on its pull request, and releases keep a rhythm

Status: accepted
Date: 2026-10-13

Amends [ADR-0008](0008-branching-and-release-policy.md) and
[ADR-0025](0025-public-repository-merges-and-releases.md) on how the admin's
changes reach `main`, where the gate runs, and when a release is cut.

Amended by [ADR-0057](0057-an-external-mcp-client-runs-the-guide-on-every-pull-request.md):
a pull request is also to be gated on the external MCP client job, outside
`make quality`, once it is a required check.

## Context

ADR-0025 let the admin push to `main` directly. Each such commit was first
gated on the maintainer's machine by `scripts/gate-commit.sh`: the whole
`make quality`, cold, about half an hour, with a stamp tied to the commit that
`scripts/pre-push.sh` required. CI then ran the same gate again. A release of
several commits spent hours in gates that ran one at a time, a rebase voided
every stamp, and a second writer pushing to `main` meanwhile voided a whole
stack. Tests that depend on the clock failed only under the load of those
gates, on the release path, where a failure costs the most.

## Decision

- **One change is one commit on `main`.** Work happens on a branch, in as many
  commits as it needs, and reaches `main` as one squash-merged pull request.
  That holds for the admin too. The admin's bypass covers the approving reviews
  a sole maintainer cannot give themselves; it is not used to merge past a red
  or missing check. Nothing enforces that difference today: the review rule and
  the required checks sit in one ruleset, and its bypass waives both. It is a
  rule the admin keeps.
- **The gate of record for a change is `make quality` on its pull request.**
  While working, `make quality-quick` and the linters.
- **A release commit is also gated cold on a maintainer's machine**, then
  pushed to `main` by the admin, as [RELEASING.md](../../RELEASING.md) says.
  It is the commit a release's tag names, and the one commit that still
  arrives without a pull request. `scripts/pre-push.sh` requires a stamp for
  commits sent to `main` and for the commit a `v*` tag names, and for nothing
  else.
- **One writer at a time merges into `main` and releases.** Parallel work, a
  maintainer's own included, arrives as a pull request and waits for that
  writer.
- **Releases keep a rhythm.** Until 1.0 a release follows every one to three
  changes and does not wait for a milestone. From 1.0 a release is cut every
  Monday from what landed that week, and an urgent fix gets a release of its
  own.
- **A scheduled run finds clock-dependent tests.** Every night the race tests
  run under processor load on Linux and macOS. A red night opens an issue.
  `test-race` stays in `make quality`.
- **The whole tree is audited before every release**, by a reviewer who did
  not write the changes,
  against the invariants, the roadmap and what the pages claim. A finding is
  verified at its source before it is acted on, and its fix is an ordinary
  change.

## Security / compatibility impact

No product code changes. A commit on `main` no longer carries proof that the
gate passed on a maintainer's machine before it left; it carries CI's run on
the pull request's head and CI's run on `main` after the merge. CI runs on
Linux. A defect that shows only on macOS is found by the nightly run or by the
release commit's cold gate, later than before. The checks of a pull request
still run from its own tree, so a change to a workflow or to the gate is held
by its review. With one maintainer the admin's own change there has no second
reviewer and is held by the admin alone, as ADR-0025 already says.

## Alternatives considered

- A cold local gate for every commit, as before: the strongest evidence for
  each commit on the platform the maintainer uses, at half an hour of one
  machine per commit.
- A local gate for changes to authorization paths as well: most changes of the
  next milestone touch the gate or the workflows, so little would change.
- A lock file the hook reads to name the writer: more code in a gate script
  for a rule one writer keeps by merging one pull request at a time.
- A nightly run on Linux only: cheaper, and blind to the platform the gate
  no longer runs on.
- A release for every user-visible change: the release procedure's fixed cost
  on each of them.

## Consequences

Bisecting ends at a change, not at a step of it. The machine is free while CI
runs. A release is smaller and its reconciliation of status, README and site
is shorter. The nightly workflow is one more thing that can be red, and a red
night is fixed like any defect, never rerun until it passes.

## Validation

`make pre-push-probe`, part of `make quality`, runs the hook in a throwaway
repository, on lines written by hand and on real pushes. The hook must pass a
branch push of commits nobody gated, and refuse them sent to `main` under any
source spelling, sent to a remote that has no `main`, hidden behind a merge or
a replace ref, or tagged as a release, and refuse a stamp that is missing or
is not the one line the gate writes.
`ci.yml` runs `make quality` on every pull request, and the ruleset requires
that check.

Planned: the nightly workflow, added in a change of its own, whose runs show
whether it finds anything.
