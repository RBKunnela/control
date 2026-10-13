# ADR-0008: Protected main, DCO, semver, releases built by CI

Status: accepted
Date: 2026-09-09

Amended by [ADR-0025](0025-public-repository-merges-and-releases.md): the
repository admin pushes to `main` directly, only the maintain role merges, and
a release is an immutable tag that CI builds, signs and attests. The sentences
below about a repository that does not exist describe the state before it was
published.

Amended by [ADR-0052](0052-a-change-is-gated-on-its-pull-request.md): a change
is gated by CI on its pull request, and releases keep a rhythm.

## Context

This repository carries authorization logic. What lands on `main` and what ships
in a release both have to be provable later by someone who was not in the room.
Licensing and contribution terms have to be settled before the first outside
pull request, not after.

## Decision

- `main` is protected, from the moment the repository exists: pull request
  required, linear history, required status checks, conversations resolved,
  stale approvals dismissed, code-owner review on the paths that carry
  authorization meaning, and no force pushes.
- Merges are squash merges with a conventional-commit title.
- Contributions carry a DCO `Signed-off-by` line. Review confirms it: no
  automated DCO check exists yet, and `scripts/github-bootstrap.sh` does not
  enable one. There is no CLA.
- Versioning is semver, with an explicit `0.x` compatibility statement.
- Releases are built and signed by CI, never from a maintainer's machine. The
  release pipeline is planned.

The GitHub repository does not exist. The ruleset above is prepared in
`scripts/github-bootstrap.sh` and applied by the maintainer rather than by CI.

## Security / compatibility impact

A release artifact traces back to a commit and a workflow run, and no signing
key needs to live on a laptop. Every change needs one approving review. A change
to the paths that decide, or to the gate those paths are held to, also needs a
code-owner review from the security maintainers: `internal/core`,
`internal/policy`, `internal/canon`, `internal/evidence`, `pkg/contract`,
`pkg/policyprovider`, `api/proto`, `testdata/`, `scripts/`, `.github/`, and the
files the gate is built from, `Makefile`, `.golangci.yml`, `buf.yaml`,
`buf.gen.yaml`, `go.mod` and `go.sum`. `.github/CODEOWNERS` is the list. Both
requirements are enforced by the ruleset.

Those paths additionally take a second independent approval, and nothing
enforces it. A GitHub ruleset carries one approval count for the whole
repository and cannot require a different one for a subset of paths, so the
second approval is a rule the maintainers apply in review and record in the pull
request. That is permanent, not a gap waiting on a setting.

Linear history keeps a regression in the decision path bisectable.

## Alternatives considered

- A CLA. Apache-2.0 already grants what the project needs; the extra right a CLA
  buys is relicensing, which this project does not want, and it costs
  contributor trust, see [ADR-0009](0009-open-core-boundary.md).
- Merge commits. A non-linear history makes bisecting harder for no gain here.
- Releasing from a maintainer's machine. No attestation, and the build depends
  on one unreproducible environment.

## Consequences

The branch protection is only real once the maintainer runs the bootstrap
script; until then this record states the intent and the script carries it. A
contributor who forgets `Signed-off-by` has to amend the commit.

## Validation

Runnable today: `scripts/check-actions-pinned.sh`, through
`make check-actions`, fails when a workflow refers to an action by anything
other than a full commit SHA.

Written but never run: the four workflows in `.github/workflows/` that carry the
required status checks. `scripts/github-bootstrap.sh` is on disk and applies the
ruleset; the maintainer runs it once, and it has not been run, because the
repository does not exist.

Planned: the release pipeline, which is the first thing that would check the
release path.
