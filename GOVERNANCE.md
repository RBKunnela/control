# Governance

This project is maintainer-led and run in the open. The rules below exist so
that a decision can be explained later by someone who was not in the room.

## Who decides

Maintainers decide. A maintainer can merge, release, and say no. Today there is
one, Konrad Karauda, which is worth stating plainly rather than hiding behind a
plural.

Disagreement between maintainers is settled in the issue or pull request where
it arose. If it cannot be settled there, it becomes an architecture decision
record carrying the outcome and the rejected alternatives.

## How decisions are recorded

- In public: issues, pull requests and architecture decision records in
  `docs/adr/`. A decision that outlives the change that caused it becomes a
  record.
- In private: only what cannot be discussed safely in public, which in practice
  means an unfixed vulnerability. See [SECURITY.md](SECURITY.md). Once a fix
  ships, the reasoning moves into the open.

## Review requirements

A pull request needs one approving review from a maintainer other than its
last pusher.

Two independent approvals are required for a change that touches any of:

- authorization semantics: verdicts, precedence, the fail-closed table;
- identity, delegation and authority propagation;
- what an approval binds to and when it expires;
- cryptography, including the canonical action digest;
- a public wire schema with security meaning;
- redaction and evidence content defaults;
- release signing, provenance, workflow security, or the gate's checks.

"Independent" means the two approvers did not write the change or pair on it.

The rulesets on `main` enforce what GitHub can: the review, code-owner review,
resolved conversations, the required checks, and two approvals from
`@guardana/security-maintainers` on the paths `scripts/lib/github-settings.sh`
lists. Whether two approvers paired stays a rule the maintainers apply and
record in the pull request.

With one maintainer, another author's change to those paths waits for a second
maintainer or a reviewer invited to the security maintainers for it. Which of
the two happened is written in the pull request, and a change that has not met
it does not merge. A dependency update to the workflows is the exception: the
admin merges it once its checks pass, and says so in the pull request.

The admin's own change arrives by pull request too and, while there is one
maintainer, has no second reviewer on any path: the admin merges it once its
checks are green
([ADR-0025](docs/adr/0025-public-repository-merges-and-releases.md)). The
bypass that allows this would waive a red check as well; not merging past one
is a rule the admin keeps. Only a release commit is pushed to `main` directly
([ADR-0052](docs/adr/0052-a-change-is-gated-on-its-pull-request.md)).

## Roles on GitHub

| Role | Held by | Can |
| --- | --- | --- |
| Admin | Konrad Karauda | push to `main`, change settings and rulesets |
| Maintain | `@guardana/maintainers` | merge reviewed pull requests, create release tags |
| Write | `@guardana/security-maintainers` | review as code owners of the authorization paths |
| Everyone | anyone with a GitHub account | open issues, and pull requests from a fork |

Nobody can force-push or delete `main`, or move or delete a release tag.
Settings, teams and rulesets live in `scripts/lib/github-settings.sh` and what
it sources; `scripts/github-bootstrap.sh` applies them, and
`scripts/github-settings-check.sh` compares them with GitHub without writing:
exit 1 on drift, 2 when unsure. How a release is cut is in
[RELEASING.md](RELEASING.md).

## Becoming a maintainer

A maintainer nominates you; the maintainers decide. What counts is sustained
quality of contribution and of review: whether your reviews find real problems,
whether your changes hold up, and whether you say "I do not know" when you do
not. Commit count is not a criterion, and neither is employer.

An invitation is made privately and announced in a public issue.

A maintainer who has been away for a long time moves to emeritus, without
prejudice, and comes back by asking. No threshold in days is set here, because
a project this size would not apply one honestly.

## Licensing posture

Everything in this repository is Apache-2.0, including every security
capability, except the website's fonts, which keep their own licence. Two parts of that are meant to be permanent, because the project
has no point without them: code already released under Apache-2.0 cannot be
withdrawn from the people who have it, and a security capability is not moved
behind a paid tier. What may become commercial is hosting and curated content.

The boundary is recorded in [ADR-0009](docs/adr/0009-open-core-boundary.md). A
future maintainer group can supersede that record, as with any other; what they
cannot do is retract the licence on code already published.
