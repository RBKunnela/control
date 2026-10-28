# ADR-0009: Everything in this repository is Apache-2.0 and stays open

Status: accepted
Date: 2026-09-09

Amended by [ADR-0030](0030-a-static-website-drawn-from-the-repository.md): the
website's IBM Plex fonts under `site/assets/brand/v1/fonts/` are third-party
files under the SIL Open Font License 1.1, which ships beside them.

Amended by [ADR-0066](0066-each-decision-about-authority-is-a-port.md),
which decides that each pluggable part this record names is a port with a
default, a closed kind and at most one remote kind.

## Context

The project has to be complete and safe as a self-hosted open-source
deployment, and it also has to leave room for a commercial offering later.
Stating where that line runs before any code exists is what stops the second
from eating the first one feature at a time.

## Decision

The kernel, the matcher, PDP adapters, protocol adapters, approvals, evidence,
detectors, ingest, graph and the control API are all Apache-2.0 and all stay in
this repository. A security capability is never withheld from the open build.

What may become commercial later is hosting, meaning a managed control plane,
and curated content, meaning policy and detector packs. Both speak the same
versioned control API. That shared API is what makes a first-class self-hosted
deployment possible; what makes it the rule is the line above, that a security
capability is never withheld from the open build.

To keep that possible, the open build has to carry, from the first version that
has these parts at all:

- a project and tenant identifier on every persisted record,
- a versioned control API with a compatibility policy,
- pluggable control API authentication,
- pluggable policy sources, event sinks, approval providers and alert sinks,
- usage counters exposed only as metrics, with no phone-home and no licence
  check.

None of these exist yet. They are requirements on the work that builds those
parts, the earliest being the control API and tenant isolation, both planned.

Those seams will be internal Go interfaces, not part of the public Go surface
that [ADR-0007](0007-repository-layout-and-dependency-rule.md) fixes at four
packages. Promoting one to `pkg/` is a separate compatibility decision.

## Security / compatibility impact

No security capability sits behind a paid tier, so a self-hosted deployment is
not the less safe one. No phone-home and no licence check means the enforcement
path has no outbound dependency that could fail for a commercial reason, and an
air-gapped deployment behaves like any other.

## Alternatives considered

- An open-core split that holds back an enforcement or audit capability. It
  would make the open build the unsafe build, which contradicts the point of the
  project.
- A source-available licence. It excludes both the users and the vendors this
  project needs in order to be a neutral control point.
- Leaving the boundary unstated. Every later feature then becomes an argument
  about where the line is.

## Consequences

The multi-tenant and pluggable seams are carried from the first version even
though a single-tenant deployment does not need them. Revenue has to come from
running the system and from content, not from withholding a feature.

## Validation

No gate can prove this decision, so it is held by review. The earliest thing
that would falsify it is a security capability reachable only behind a build
flag or a licence check, appearing anywhere in the tree. `TRADEMARKS.md` states
the trademark boundary and `docs/status.md` carries the open-versus-hosted
table, but both are prose, and prose does not fail a build.
